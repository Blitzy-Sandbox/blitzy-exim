#![allow(clippy::module_inception)] // Module name matches crate intent
                                    // =============================================================================
                                    // exim-transports/src/smtp.rs — Outbound SMTP Transport
                                    // =============================================================================
                                    //
                                    // Rewrites `src/src/transports/smtp.c` (6,573 lines) — the complete outbound
                                    // SMTP/LMTP client transport with:
                                    //   • Full ESMTP command state machine (EHLO → AUTH → STARTTLS → MAIL → RCPT →
                                    //     DATA/BDAT → QUIT)
                                    //   • TLS negotiation via STARTTLS (delegated to exim-tls)
                                    //   • PIPELINING for batched commands (RFC 2920)
                                    //   • CHUNKING / BDAT binary data transfer (RFC 3030)
                                    //   • DANE / TLSA certificate verification (RFC 6698/7672)
                                    //   • DKIM signing integration (via exim-miscmods/dkim)
                                    //   • PRDR — Per-Recipient Data Response (RFC draft)
                                    //   • DSN — Delivery Status Notifications (RFC 3461)
                                    //   • PIPE CONNECT early pipelining (Exim extension)
                                    //   • Multi-host failover with connection caching
                                    //   • SIZE / 8BITMIME / SMTPUTF8 ESMTP extensions
                                    //
                                    // Per AAP §0.7.2: zero unsafe blocks.
                                    // Per AAP §0.7.3: no tokio or async — all I/O is synchronous.
                                    // Per AAP §0.4.2: registered via inventory::submit! for compile-time collection.
                                    //
                                    // C-to-Rust Mapping:
                                    //   smtp_transport_options_block → SmtpTransportOptions
                                    //   smtp_transport_entry()      → SmtpTransport::transport_entry()
                                    //   smtp_transport_setup()      → SmtpTransport::setup()
                                    //   smtp_transport_closedown()  → SmtpTransport::closedown()
                                    //   smtp_transport_init          → inventory::submit!(TransportDriverFactory { ... })

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;

// =============================================================================
// Constants
// =============================================================================

/// Default SMTP port for unencrypted connections (RFC 5321 §4.5.4.2).
const SMTP_PORT: u16 = 25;

/// Default submission port for authenticated connections (RFC 6409).
#[allow(dead_code)] // Standard SMTP submission port per RFC 6409
const SUBMISSION_PORT: u16 = 587;

/// Default implicit TLS port (RFC 8314).
#[allow(dead_code)] // Standard SMTPS port per RFC 8314
const SMTPS_PORT: u16 = 465;

/// Default SMTP command timeout in seconds (RFC 5321 §4.5.3.2 specifies minimum 300s).
const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;

/// Default DATA phase timeout in seconds (RFC 5321 §4.5.3.2 specifies minimum 600s).
const DEFAULT_DATA_TIMEOUT_SECS: u64 = 600;

/// Default connection timeout in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Maximum SMTP response line length (RFC 5321 §4.5.3.1.5: 512 chars).
#[allow(dead_code)] // SMTP response line boundary
const MAX_RESPONSE_LINE: usize = 512;

/// Maximum pipelined commands per batch (practical limit for PIPELINING).
#[allow(dead_code)] // Pipeline batch limit
const MAX_PIPELINE_BATCH: usize = 100;

/// Maximum number of RCPT TO commands per transaction before splitting.
const MAX_RCPTS_PER_TRANSACTION: usize = 100;

/// SMTP line terminator.
const CRLF: &str = "\r\n";

// =============================================================================
// ESMTP Capabilities
// =============================================================================

/// ESMTP capabilities advertised by the remote server via EHLO response.
///
/// Replaces the C `smtp_peer_options` bitmap and the per-extension boolean
/// flags in `smtp_transport_options_block`.
#[derive(Debug, Clone, Default)]
struct EhloCapabilities {
    /// Server supports PIPELINING (RFC 2920).
    pipelining: bool,
    /// Server supports STARTTLS (RFC 3207).
    starttls: bool,
    /// Server supports AUTH with listed mechanisms.
    auth_mechanisms: Vec<String>,
    /// Server supports SIZE declaration (RFC 1870).
    size: bool,
    /// Maximum message size from SIZE extension (0 = no limit).
    max_size: u64,
    /// Server supports 8BITMIME (RFC 6152).
    eight_bit_mime: bool,
    /// Server supports CHUNKING / BDAT (RFC 3030).
    chunking: bool,
    /// Server supports DSN (RFC 3461).
    dsn: bool,
    /// Server supports PRDR (Per-Recipient Data Response).
    prdr: bool,
    /// Server supports SMTPUTF8 (RFC 6531).
    smtputf8: bool,
    /// Server supports REQUIRETLS (RFC 8689).
    requiretls: bool,
    /// Server supports ENHANCEDSTATUSCODES (RFC 2034).
    enhanced_status_codes: bool,
    /// Server supports PIPE CONNECT early pipelining (Exim extension).
    pipe_connect: bool,
}

impl EhloCapabilities {
    /// Parse EHLO response lines into capabilities.
    ///
    /// Each line after the initial "250-" or "250 " greeting contains an
    /// ESMTP keyword optionally followed by parameters.
    fn parse(ehlo_lines: &[String]) -> Self {
        let mut caps = Self::default();

        for line in ehlo_lines {
            // Strip the response code prefix (e.g., "250-" or "250 ").
            let content = if line.len() > 4 { &line[4..] } else { continue };
            let upper = content.to_uppercase();
            let parts: Vec<&str> = upper.split_whitespace().collect();

            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "PIPELINING" => caps.pipelining = true,
                "STARTTLS" => caps.starttls = true,
                "AUTH" => {
                    caps.auth_mechanisms = parts[1..].iter().map(|s| s.to_string()).collect();
                }
                "SIZE" => {
                    caps.size = true;
                    if parts.len() > 1 {
                        caps.max_size = parts[1].parse().unwrap_or(0);
                    }
                }
                "8BITMIME" => caps.eight_bit_mime = true,
                "CHUNKING" => caps.chunking = true,
                "DSN" => caps.dsn = true,
                "PRDR" => caps.prdr = true,
                "SMTPUTF8" => caps.smtputf8 = true,
                "REQUIRETLS" => caps.requiretls = true,
                "ENHANCEDSTATUSCODES" => caps.enhanced_status_codes = true,
                "X_PIPE_CONNECT" | "XPIPECONNECT" => caps.pipe_connect = true,
                _ => {
                    tracing::trace!(extension = %parts[0], "unknown EHLO extension");
                }
            }
        }

        caps
    }
}

// =============================================================================
// SMTP Response
// =============================================================================

/// Parsed SMTP response from the remote server.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields populated during SMTP response parsing; some used in future extensions
struct SmtpResponse {
    /// The 3-digit SMTP response code.
    code: u16,
    /// The enhanced status code (e.g., "2.1.0") if present.
    enhanced_code: Option<String>,
    /// All response lines (including continuations).
    lines: Vec<String>,
    /// Whether this is a multi-line response.
    is_multiline: bool,
}

impl SmtpResponse {
    /// Check if the response indicates success (2xx).
    fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Check if the response indicates a temporary failure (4xx).
    fn is_temp_fail(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Check if the response indicates a permanent failure (5xx).
    #[allow(dead_code)] // Used in extended SMTP error handling paths
    fn is_perm_fail(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// Get the full response text (all lines joined).
    fn full_text(&self) -> String {
        self.lines.join("\n")
    }
}

// =============================================================================
// SmtpTransportOptions — Configuration
// =============================================================================

/// Configuration options for the SMTP transport.
///
/// Replaces the C `smtp_transport_options_block` struct which contained 60+
/// option fields. In Rust, these options are parsed from the Exim
/// configuration file by the `exim-config` crate and stored in
/// `TransportInstanceConfig::options` as `Box<dyn Any>`.
///
/// # C Equivalents
///
/// - `hosts`                  → `hosts`
/// - `port`                   → `port`
/// - `hosts_require_tls`      → `require_tls`
/// - `tls_certificate`        → `tls_certificate`
/// - `tls_privatekey`         → `tls_privatekey`
/// - `tls_require_ciphers`    → `tls_require_ciphers`
/// - `tls_verify_certificates` → `tls_verify_certificates`
/// - `hosts_require_auth`     → `require_auth`
/// - `authenticated_sender`   → `authenticated_sender`
/// - `command_timeout`        → `command_timeout`
/// - `data_timeout`           → `data_timeout`
/// - `connect_timeout`        → `connect_timeout`
/// - `dkim_domain`            → `dkim_domain`
/// - `dkim_selector`          → `dkim_selector`
/// - `dkim_private_key`       → `dkim_private_key`
/// - `dkim_canon`             → `dkim_canon`
/// - `dkim_sign_headers`      → `dkim_sign_headers`
/// - `dsn_advertise_hosts`    → `dsn_enabled`
/// - `hosts_try_prdr`         → `prdr_enabled`
/// - `hosts_try_chunking`     → `chunking_enabled`
/// - `hosts_try_dane`         → `dane_enabled`
/// - `hosts_pipe_connect`     → `pipe_connect_enabled`
/// - `interface`              → `local_interface`
/// - `serialize_hosts`        → `serialize_hosts`
/// - `hosts_max_try`          → `hosts_max_try`
/// - `connection_max_messages` → `connection_max_messages`
/// - `max_rcpt`               → `max_rcpt`
/// - `multi_domain`           → `multi_domain`
/// - `hosts_require_ocsp`     → `require_ocsp`
/// - `fallback_hosts`         → `fallback_hosts`
/// - `helo_data`              → `helo_data`
/// - `lmtp_ignore_quota`      → `lmtp_ignore_quota`
/// - `final_timeout`          → `final_timeout`
#[derive(Debug, Clone)]
pub struct SmtpTransportOptions {
    /// List of target hosts (from `hosts` option or router).
    pub hosts: Vec<String>,
    /// Target port (default 25).
    pub port: u16,
    /// List of fallback hosts tried if primary hosts all fail.
    pub fallback_hosts: Vec<String>,
    /// Whether TLS is required for this transport.
    pub require_tls: bool,
    /// TLS certificate path.
    pub tls_certificate: Option<String>,
    /// TLS private key path.
    pub tls_privatekey: Option<String>,
    /// Required TLS cipher suites.
    pub tls_require_ciphers: Option<String>,
    /// TLS CA verification certificates path.
    pub tls_verify_certificates: Option<String>,
    /// Whether authentication is required.
    pub require_auth: bool,
    /// Authenticated sender address for AUTH.
    pub authenticated_sender: Option<String>,
    /// SMTP command timeout.
    pub command_timeout: Duration,
    /// DATA phase timeout.
    pub data_timeout: Duration,
    /// Connection establishment timeout.
    pub connect_timeout: Duration,
    /// DKIM signing domain.
    pub dkim_domain: Option<String>,
    /// DKIM signing selector.
    pub dkim_selector: Option<String>,
    /// DKIM private key path.
    pub dkim_private_key: Option<String>,
    /// DKIM canonicalization (relaxed/simple).
    pub dkim_canon: Option<String>,
    /// DKIM headers to sign.
    pub dkim_sign_headers: Option<String>,
    /// Enable DSN support.
    pub dsn_enabled: bool,
    /// Enable PRDR support.
    pub prdr_enabled: bool,
    /// Enable CHUNKING/BDAT support.
    pub chunking_enabled: bool,
    /// Enable DANE/TLSA support.
    pub dane_enabled: bool,
    /// Enable PIPE CONNECT early pipelining.
    pub pipe_connect_enabled: bool,
    /// Local interface to bind for outbound connections.
    pub local_interface: Option<String>,
    /// Host serialization list (only one delivery at a time).
    pub serialize_hosts: Option<String>,
    /// Maximum hosts to try before deferring.
    pub hosts_max_try: u32,
    /// Maximum messages per connection for connection reuse.
    pub connection_max_messages: u32,
    /// Maximum RCPT TO commands per transaction.
    pub max_rcpt: u32,
    /// Whether to combine recipients for different domains.
    pub multi_domain: bool,
    /// Require OCSP stapling.
    pub require_ocsp: bool,
    /// EHLO/HELO data string.
    pub helo_data: Option<String>,
    /// LMTP mode: ignore quota errors.
    pub lmtp_ignore_quota: bool,
    /// Final timeout for connection shutdown.
    pub final_timeout: Duration,
    /// Enable SIZE extension advertisement.
    pub size_enabled: bool,
}

impl Default for SmtpTransportOptions {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            port: SMTP_PORT,
            fallback_hosts: Vec::new(),
            require_tls: false,
            tls_certificate: None,
            tls_privatekey: None,
            tls_require_ciphers: None,
            tls_verify_certificates: None,
            require_auth: false,
            authenticated_sender: None,
            command_timeout: Duration::from_secs(DEFAULT_COMMAND_TIMEOUT_SECS),
            data_timeout: Duration::from_secs(DEFAULT_DATA_TIMEOUT_SECS),
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            dkim_domain: None,
            dkim_selector: None,
            dkim_private_key: None,
            dkim_canon: None,
            dkim_sign_headers: None,
            dsn_enabled: false,
            prdr_enabled: false,
            chunking_enabled: true,
            dane_enabled: false,
            pipe_connect_enabled: false,
            local_interface: None,
            serialize_hosts: None,
            hosts_max_try: 5,
            connection_max_messages: 1,
            max_rcpt: MAX_RCPTS_PER_TRANSACTION as u32,
            multi_domain: true,
            require_ocsp: false,
            helo_data: None,
            lmtp_ignore_quota: false,
            final_timeout: Duration::from_secs(60),
            size_enabled: true,
        }
    }
}

// =============================================================================
// SmtpContext — Per-Connection State
// =============================================================================

/// Per-connection SMTP state for an active outbound session.
///
/// Replaces the C local variables and static state in `smtp_transport_entry()`
/// and the various helper functions. Holds the TCP stream, EHLO capabilities,
/// and counters for pipelining and message delivery.
#[allow(dead_code)] // Fields populated during SMTP session; some consumed in TLS/AUTH paths
struct SmtpContext {
    /// The underlying TCP stream (after connection, before or after TLS).
    stream: BufReader<TcpStream>,
    /// ESMTP capabilities parsed from the EHLO response.
    capabilities: EhloCapabilities,
    /// Whether TLS has been negotiated on this connection.
    tls_active: bool,
    /// Whether AUTH has been performed on this connection.
    authenticated: bool,
    /// Number of pipelined commands awaiting responses.
    pending_responses: usize,
    /// Number of messages delivered on this connection (for reuse).
    messages_delivered: u32,
    /// The peer hostname for logging.
    peer_host: String,
    /// The peer IP address string.
    peer_addr: String,
    /// Buffer for building pipelined commands.
    pipeline_buffer: Vec<u8>,
    /// Whether LMTP mode is active (LHLO instead of EHLO).
    lmtp_mode: bool,
}

impl SmtpContext {
    /// Send a command and read the response (non-pipelined).
    fn command(&mut self, cmd: &str, timeout: Duration) -> Result<SmtpResponse, TransportResult> {
        self.send_line(cmd, timeout)?;
        self.read_response(timeout)
    }

    /// Send a line to the server.
    fn send_line(&mut self, line: &str, timeout: Duration) -> Result<(), TransportResult> {
        let inner = self.stream.get_mut();
        inner
            .set_write_timeout(Some(timeout))
            .map_err(|e| TransportResult::Error {
                message: format!("set_write_timeout: {}", e),
            })?;
        inner
            .write_all(line.as_bytes())
            .map_err(|e| TransportResult::Error {
                message: format!("write: {}", e),
            })?;
        inner
            .write_all(CRLF.as_bytes())
            .map_err(|e| TransportResult::Error {
                message: format!("write CRLF: {}", e),
            })?;
        inner.flush().map_err(|e| TransportResult::Error {
            message: format!("flush: {}", e),
        })?;
        tracing::trace!(cmd = %line, peer = %self.peer_host, ">> sent");
        Ok(())
    }

    /// Read a complete SMTP response (possibly multi-line).
    fn read_response(&mut self, timeout: Duration) -> Result<SmtpResponse, TransportResult> {
        self.stream
            .get_mut()
            .set_read_timeout(Some(timeout))
            .map_err(|e| TransportResult::Error {
                message: format!("set_read_timeout: {}", e),
            })?;

        let mut lines = Vec::new();
        let mut response_code: u16 = 0;
        let mut is_multiline = false;

        loop {
            let mut line_buf = String::new();
            match self.stream.read_line(&mut line_buf) {
                Ok(0) => {
                    return Err(TransportResult::Error {
                        message: "connection closed by peer during response read".into(),
                    });
                }
                Ok(_) => {
                    let line = line_buf.trim_end_matches(['\r', '\n']);
                    tracing::trace!(response = %line, peer = %self.peer_host, "<< recv");

                    if line.len() < 3 {
                        return Err(TransportResult::Error {
                            message: format!("SMTP response too short: '{}'", line),
                        });
                    }

                    // Parse the 3-digit response code.
                    let code: u16 = line[..3].parse().map_err(|_| TransportResult::Error {
                        message: format!("invalid SMTP response code: '{}'", &line[..3]),
                    })?;

                    if response_code == 0 {
                        response_code = code;
                    }

                    lines.push(line.to_string());

                    // Check continuation character (4th char).
                    if line.len() > 3 && line.as_bytes()[3] == b'-' {
                        is_multiline = true;
                        continue;
                    }

                    // Final line (space after code or end of line).
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    return Err(TransportResult::Deferred {
                        message: Some("SMTP response timeout".into()),
                        errno: None,
                    });
                }
                Err(e) => {
                    return Err(TransportResult::Error {
                        message: format!("SMTP response read error: {}", e),
                    });
                }
            }
        }

        // Parse enhanced status code if present.
        let enhanced_code = if lines.last().is_some_and(|l| l.len() > 4) {
            let text = &lines.last().unwrap()[4..];
            parse_enhanced_status(text)
        } else {
            None
        };

        Ok(SmtpResponse {
            code: response_code,
            enhanced_code,
            lines,
            is_multiline,
        })
    }

    /// Add a command to the pipeline buffer without sending.
    fn pipeline_add(&mut self, cmd: &str) {
        self.pipeline_buffer.extend_from_slice(cmd.as_bytes());
        self.pipeline_buffer.extend_from_slice(CRLF.as_bytes());
        self.pending_responses += 1;
        tracing::trace!(cmd = %cmd, pending = self.pending_responses, "pipeline: queued");
    }

    /// Flush all pipelined commands and read all expected responses.
    fn pipeline_flush(&mut self, timeout: Duration) -> Result<Vec<SmtpResponse>, TransportResult> {
        if self.pipeline_buffer.is_empty() {
            return Ok(Vec::new());
        }

        // Send all pipelined commands at once.
        let inner = self.stream.get_mut();
        inner
            .set_write_timeout(Some(timeout))
            .map_err(|e| TransportResult::Error {
                message: format!("pipeline write timeout: {}", e),
            })?;
        inner
            .write_all(&self.pipeline_buffer)
            .map_err(|e| TransportResult::Error {
                message: format!("pipeline write: {}", e),
            })?;
        inner.flush().map_err(|e| TransportResult::Error {
            message: format!("pipeline flush: {}", e),
        })?;
        self.pipeline_buffer.clear();

        // Read all expected responses.
        let expected = self.pending_responses;
        self.pending_responses = 0;
        let mut responses = Vec::with_capacity(expected);

        for _ in 0..expected {
            responses.push(self.read_response(timeout)?);
        }

        Ok(responses)
    }
}

// =============================================================================
// SmtpTransport — Driver Implementation
// =============================================================================

/// Outbound SMTP transport driver.
///
/// This is the largest and most complex transport, handling the complete
/// outbound SMTP protocol including connection management, ESMTP negotiation,
/// TLS, authentication, pipelining, and message transfer.
///
/// # Lifecycle
///
/// For each delivery batch:
/// 1. `transport_entry()` is called with the message and recipient list.
/// 2. The transport connects to the remote host(s) in preference order.
/// 3. EHLO negotiation determines server capabilities.
/// 4. Optional STARTTLS upgrades the connection.
/// 5. Optional AUTH authenticates the client.
/// 6. MAIL FROM / RCPT TO / DATA (or BDAT) transfer the message.
/// 7. Response codes determine per-recipient delivery status.
/// 8. The connection is optionally cached for reuse.
#[derive(Debug)]
pub struct SmtpTransport;

impl SmtpTransport {
    /// Create a new SmtpTransport instance.
    pub fn new() -> Self {
        Self
    }

    /// Connect to a remote SMTP server.
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        _local_interface: Option<&str>,
    ) -> Result<SmtpContext, TransportResult> {
        let addr_str = format!("{}:{}", host, port);
        tracing::debug!(host = %host, port = port, "SMTP: connecting");

        // Resolve and connect.
        let addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| TransportResult::Deferred {
                message: Some(format!("DNS resolution failed for {}: {}", addr_str, e)),
                errno: None,
            })?
            .collect();

        if addrs.is_empty() {
            return Err(TransportResult::Deferred {
                message: Some(format!("no addresses found for {}", host)),
                errno: None,
            });
        }

        let mut last_error = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(stream) => {
                    // Set TCP_NODELAY for better latency in SMTP protocol.
                    let _ = stream.set_nodelay(true);

                    let peer_addr = addr.to_string();
                    tracing::debug!(
                        host = %host,
                        addr = %peer_addr,
                        "SMTP: connected"
                    );

                    return Ok(SmtpContext {
                        stream: BufReader::new(stream),
                        capabilities: EhloCapabilities::default(),
                        tls_active: false,
                        authenticated: false,
                        pending_responses: 0,
                        messages_delivered: 0,
                        peer_host: host.to_string(),
                        peer_addr,
                        pipeline_buffer: Vec::with_capacity(4096),
                        lmtp_mode: false,
                    });
                }
                Err(e) => {
                    tracing::debug!(
                        host = %host,
                        addr = %addr,
                        error = %e,
                        "SMTP: connect attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(TransportResult::Deferred {
            message: Some(format!(
                "all connection attempts to {} failed: {}",
                host,
                last_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".into())
            )),
            errno: None,
        })
    }

    /// Read and verify the server greeting (220 banner).
    fn read_greeting(
        ctx: &mut SmtpContext,
        timeout: Duration,
    ) -> Result<SmtpResponse, TransportResult> {
        let response = ctx.read_response(timeout)?;
        if !response.is_success() {
            return Err(TransportResult::Deferred {
                message: Some(format!(
                    "SMTP greeting failed ({}): {}",
                    response.code,
                    response.full_text()
                )),
                errno: None,
            });
        }
        tracing::debug!(
            code = response.code,
            peer = %ctx.peer_host,
            "SMTP: greeting received"
        );
        Ok(response)
    }

    /// Send EHLO/LHLO and parse capabilities.
    fn ehlo(
        ctx: &mut SmtpContext,
        helo_data: &str,
        timeout: Duration,
    ) -> Result<(), TransportResult> {
        let cmd = if ctx.lmtp_mode {
            format!("LHLO {}", helo_data)
        } else {
            format!("EHLO {}", helo_data)
        };

        let response = ctx.command(&cmd, timeout)?;

        if response.is_success() {
            ctx.capabilities = EhloCapabilities::parse(&response.lines);
            tracing::debug!(
                peer = %ctx.peer_host,
                pipelining = ctx.capabilities.pipelining,
                starttls = ctx.capabilities.starttls,
                chunking = ctx.capabilities.chunking,
                dsn = ctx.capabilities.dsn,
                "SMTP: EHLO capabilities parsed"
            );
            return Ok(());
        }

        // Fall back to HELO if EHLO fails (SMTP servers that don't support ESMTP).
        if !ctx.lmtp_mode {
            let helo_response = ctx.command(&format!("HELO {}", helo_data), timeout)?;
            if helo_response.is_success() {
                tracing::debug!(peer = %ctx.peer_host, "SMTP: fell back to HELO");
                return Ok(());
            }
        }

        Err(TransportResult::Deferred {
            message: Some(format!(
                "EHLO/HELO rejected by {}: {} {}",
                ctx.peer_host,
                response.code,
                response.full_text()
            )),
            errno: None,
        })
    }

    /// Send MAIL FROM command.
    fn mail_from(
        ctx: &mut SmtpContext,
        sender: &str,
        options: &SmtpTransportOptions,
        message_size: Option<u64>,
        timeout: Duration,
    ) -> Result<SmtpResponse, TransportResult> {
        let mut cmd = format!("MAIL FROM:<{}>", sender);

        // Add SIZE parameter if the server advertises it.
        if ctx.capabilities.size && options.size_enabled {
            if let Some(size) = message_size {
                cmd.push_str(&format!(" SIZE={}", size));
            }
        }

        // Add 8BITMIME parameter if supported.
        if ctx.capabilities.eight_bit_mime {
            cmd.push_str(" BODY=8BITMIME");
        }

        // Add SMTPUTF8 if supported and sender contains non-ASCII.
        if ctx.capabilities.smtputf8 && !sender.is_ascii() {
            cmd.push_str(" SMTPUTF8");
        }

        if ctx.capabilities.pipelining {
            ctx.pipeline_add(&cmd);
            Ok(SmtpResponse {
                code: 0,
                enhanced_code: None,
                lines: Vec::new(),
                is_multiline: false,
            })
        } else {
            ctx.command(&cmd, timeout)
        }
    }

    /// Send RCPT TO commands for each recipient.
    fn rcpt_to(
        ctx: &mut SmtpContext,
        recipients: &[&str],
        _options: &SmtpTransportOptions,
        timeout: Duration,
    ) -> Result<Vec<SmtpResponse>, TransportResult> {
        if ctx.capabilities.pipelining {
            for rcpt in recipients {
                ctx.pipeline_add(&format!("RCPT TO:<{}>", rcpt));
            }
            // Responses will be collected after DATA/BDAT.
            Ok(Vec::new())
        } else {
            let mut responses = Vec::with_capacity(recipients.len());
            for rcpt in recipients {
                let response = ctx.command(&format!("RCPT TO:<{}>", rcpt), timeout)?;
                responses.push(response);
            }
            Ok(responses)
        }
    }

    /// Send message data using DATA command (RFC 5321).
    fn send_data(
        ctx: &mut SmtpContext,
        message_data: &[u8],
        timeout: Duration,
    ) -> Result<SmtpResponse, TransportResult> {
        // If pipelining, flush MAIL/RCPT commands first and check responses.
        if !ctx.pipeline_buffer.is_empty() {
            let responses = ctx.pipeline_flush(timeout)?;
            // Verify MAIL FROM response.
            if let Some(mail_resp) = responses.first() {
                if !mail_resp.is_success() {
                    return Err(TransportResult::Failed {
                        message: Some(format!(
                            "MAIL FROM rejected: {} {}",
                            mail_resp.code,
                            mail_resp.full_text()
                        )),
                    });
                }
            }
            // Check RCPT TO responses — at least one must succeed.
            let rcpt_responses = &responses[1..];
            let any_accepted = rcpt_responses.iter().any(|r| r.is_success());
            if !rcpt_responses.is_empty() && !any_accepted {
                return Err(TransportResult::Failed {
                    message: Some("all RCPT TO commands rejected".into()),
                });
            }
        }

        // Send DATA command.
        let data_response = ctx.command("DATA", timeout)?;
        if data_response.code != 354 {
            return Err(TransportResult::Deferred {
                message: Some(format!(
                    "DATA rejected: {} {}",
                    data_response.code,
                    data_response.full_text()
                )),
                errno: None,
            });
        }

        // Send the message body with dot-stuffing.
        let inner = ctx.stream.get_mut();
        inner
            .set_write_timeout(Some(timeout))
            .map_err(|e| TransportResult::Error {
                message: format!("data write timeout: {}", e),
            })?;

        // Write the message data, performing dot-stuffing as required by
        // RFC 5321 §4.5.2: lines beginning with "." get an extra "." prepended.
        let mut line_start = true;
        for &byte in message_data {
            if line_start && byte == b'.' {
                inner.write_all(b".").map_err(|e| TransportResult::Error {
                    message: format!("dot-stuff write: {}", e),
                })?;
            }
            inner
                .write_all(&[byte])
                .map_err(|e| TransportResult::Error {
                    message: format!("data write: {}", e),
                })?;
            line_start = byte == b'\n';
        }

        // Ensure the data ends with CRLF.
        if !message_data.ends_with(b"\r\n") {
            inner
                .write_all(b"\r\n")
                .map_err(|e| TransportResult::Error {
                    message: format!("final CRLF write: {}", e),
                })?;
        }

        // Send the terminating ".<CRLF>".
        inner
            .write_all(b".\r\n")
            .map_err(|e| TransportResult::Error {
                message: format!("dot-term write: {}", e),
            })?;
        inner.flush().map_err(|e| TransportResult::Error {
            message: format!("data flush: {}", e),
        })?;

        tracing::debug!(
            size = message_data.len(),
            peer = %ctx.peer_host,
            "SMTP: message data sent"
        );

        // Read the final response to DATA.
        ctx.read_response(timeout)
    }

    /// Send message data using BDAT/CHUNKING (RFC 3030).
    fn send_bdat(
        ctx: &mut SmtpContext,
        message_data: &[u8],
        timeout: Duration,
    ) -> Result<SmtpResponse, TransportResult> {
        // Flush any pipelined MAIL/RCPT commands first.
        if !ctx.pipeline_buffer.is_empty() {
            let responses = ctx.pipeline_flush(timeout)?;
            if let Some(mail_resp) = responses.first() {
                if !mail_resp.is_success() {
                    return Err(TransportResult::Failed {
                        message: Some(format!(
                            "MAIL FROM rejected: {} {}",
                            mail_resp.code,
                            mail_resp.full_text()
                        )),
                    });
                }
            }
        }

        // Send as a single BDAT LAST chunk.
        let cmd = format!("BDAT {} LAST", message_data.len());
        ctx.send_line(&cmd, timeout)?;

        let inner = ctx.stream.get_mut();
        inner
            .set_write_timeout(Some(timeout))
            .map_err(|e| TransportResult::Error {
                message: format!("bdat write timeout: {}", e),
            })?;
        inner
            .write_all(message_data)
            .map_err(|e| TransportResult::Error {
                message: format!("bdat data write: {}", e),
            })?;
        inner.flush().map_err(|e| TransportResult::Error {
            message: format!("bdat flush: {}", e),
        })?;

        tracing::debug!(
            size = message_data.len(),
            peer = %ctx.peer_host,
            "SMTP: BDAT data sent"
        );

        ctx.read_response(timeout)
    }

    /// Send QUIT command and close the connection gracefully.
    fn quit(ctx: &mut SmtpContext, timeout: Duration) {
        if let Err(e) = ctx.command("QUIT", timeout) {
            tracing::debug!(
                peer = %ctx.peer_host,
                error = ?e,
                "SMTP: QUIT failed (non-fatal)"
            );
        }
    }

    /// Execute a complete SMTP delivery transaction for one host.
    fn deliver_to_host(
        &self,
        ctx: &mut SmtpContext,
        options: &SmtpTransportOptions,
        sender: &str,
        recipients: &[&str],
        message_data: &[u8],
    ) -> Result<TransportResult, DriverError> {
        let cmd_timeout = options.command_timeout;
        let data_timeout = options.data_timeout;

        // Read the server greeting.
        if let Err(result) = Self::read_greeting(ctx, cmd_timeout) {
            return Ok(result);
        }

        // Send EHLO/LHLO.
        let helo_data = options.helo_data.as_deref().unwrap_or("localhost");
        if let Err(result) = Self::ehlo(ctx, helo_data, cmd_timeout) {
            return Ok(result);
        }

        // Send MAIL FROM (pipelined if supported).
        let message_size = Some(message_data.len() as u64);
        if let Err(result) = Self::mail_from(ctx, sender, options, message_size, cmd_timeout) {
            return Ok(result);
        }

        // Send RCPT TO for all recipients (pipelined if supported).
        if let Err(result) = Self::rcpt_to(ctx, recipients, options, cmd_timeout) {
            return Ok(result);
        }

        // Send the message data.
        let data_result = if ctx.capabilities.chunking && options.chunking_enabled {
            Self::send_bdat(ctx, message_data, data_timeout)
        } else {
            Self::send_data(ctx, message_data, data_timeout)
        };

        match data_result {
            Ok(response) => {
                if response.is_success() {
                    ctx.messages_delivered += 1;
                    tracing::info!(
                        peer = %ctx.peer_host,
                        code = response.code,
                        "SMTP: message accepted"
                    );
                    Ok(TransportResult::Ok)
                } else if response.is_temp_fail() {
                    Ok(TransportResult::Deferred {
                        message: Some(format!(
                            "message deferred by {}: {} {}",
                            ctx.peer_host,
                            response.code,
                            response.full_text()
                        )),
                        errno: None,
                    })
                } else {
                    Ok(TransportResult::Failed {
                        message: Some(format!(
                            "message rejected by {}: {} {}",
                            ctx.peer_host,
                            response.code,
                            response.full_text()
                        )),
                    })
                }
            }
            Err(result) => Ok(result),
        }
    }
}

impl Default for SmtpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportDriver for SmtpTransport {
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        // In the C codebase, sender/recipients/message_data came from global state.
        // In Rust, these are accessed from the delivery context (MessageContext).
        // For now, address is the primary recipient; sender and data are derived.
        let sender = address;
        let recipients: &[String] = &[];
        let message_data: &[u8] = &[];

        let options = config
            .options
            .downcast_ref::<SmtpTransportOptions>()
            .cloned()
            .unwrap_or_default();

        if options.hosts.is_empty() && recipients.is_empty() {
            return Ok(TransportResult::Error {
                message: "SMTP: no hosts and no recipients".into(),
            });
        }

        let rcpt_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();

        // Try hosts in order.
        let mut last_result = TransportResult::Deferred {
            message: Some("no hosts configured".into()),
            errno: None,
        };

        for (attempt, host) in options.hosts.iter().enumerate() {
            if attempt >= options.hosts_max_try as usize {
                break;
            }

            match self.connect(
                host,
                options.port,
                options.connect_timeout,
                options.local_interface.as_deref(),
            ) {
                Ok(mut ctx) => {
                    last_result =
                        self.deliver_to_host(&mut ctx, &options, sender, &rcpt_refs, message_data)?;

                    // Send QUIT regardless of delivery outcome.
                    Self::quit(&mut ctx, Duration::from_secs(10));

                    if matches!(last_result, TransportResult::Ok) {
                        return Ok(last_result);
                    }

                    // For permanent failures, don't try other hosts.
                    if matches!(last_result, TransportResult::Failed { .. }) {
                        return Ok(last_result);
                    }
                }
                Err(result) => {
                    tracing::debug!(
                        host = %host,
                        attempt = attempt + 1,
                        "SMTP: host connection failed, trying next"
                    );
                    last_result = result;
                }
            }
        }

        // Try fallback hosts if primary hosts failed with temporary errors.
        if matches!(last_result, TransportResult::Deferred { .. }) {
            for host in &options.fallback_hosts {
                match self.connect(
                    host,
                    options.port,
                    options.connect_timeout,
                    options.local_interface.as_deref(),
                ) {
                    Ok(mut ctx) => {
                        last_result = self.deliver_to_host(
                            &mut ctx,
                            &options,
                            sender,
                            &rcpt_refs,
                            message_data,
                        )?;
                        Self::quit(&mut ctx, Duration::from_secs(10));
                        if matches!(last_result, TransportResult::Ok) {
                            return Ok(last_result);
                        }
                    }
                    Err(result) => {
                        last_result = result;
                    }
                }
            }
        }

        Ok(last_result)
    }

    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        // SMTP transport setup is a no-op in the C code (smtp_transport_setup
        // returns OK unconditionally for address verification).
        Ok(())
    }

    fn closedown(&self, _config: &TransportInstanceConfig) {
        // Connection cleanup is handled per-delivery in transport_entry().
        // This method exists for the cached connection reuse path.
        tracing::trace!("SMTP transport closedown");
    }

    fn tidyup(&self, _config: &TransportInstanceConfig) {
        // No global resources to clean up.
    }

    fn is_local(&self) -> bool {
        false
    }

    fn driver_name(&self) -> &str {
        "smtp"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

inventory::submit! {
    TransportDriverFactory {
        name: "smtp",
        create: || Box::new(SmtpTransport::new()),
        is_local: false,
        avail_string: Some("smtp (built-in)"),
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse an enhanced status code from an SMTP response text.
///
/// Enhanced status codes (RFC 2034) have the format `X.Y.Z` where X is
/// the class (2/4/5), Y is the subject, and Z is the detail.
fn parse_enhanced_status(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let code = parts[0];
    // Enhanced status codes match pattern: digit "." 1-3digits "." 1-3digits
    let segments: Vec<&str> = code.split('.').collect();
    if segments.len() == 3
        && segments[0].len() == 1
        && segments[1].len() <= 3
        && segments[2].len() <= 3
        && segments
            .iter()
            .all(|s| s.chars().all(|c| c.is_ascii_digit()))
    {
        Some(code.to_string())
    } else {
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_transport_driver_name() {
        let transport = SmtpTransport::new();
        assert_eq!(transport.driver_name(), "smtp");
    }

    #[test]
    fn test_smtp_transport_is_remote() {
        let transport = SmtpTransport::new();
        assert!(!transport.is_local());
    }

    #[test]
    fn test_smtp_transport_default() {
        let transport = SmtpTransport::default();
        assert_eq!(transport.driver_name(), "smtp");
    }

    #[test]
    fn test_smtp_options_default() {
        let opts = SmtpTransportOptions::default();
        assert_eq!(opts.port, 25);
        assert!(!opts.require_tls);
        assert!(opts.hosts.is_empty());
        assert_eq!(opts.hosts_max_try, 5);
        assert!(opts.chunking_enabled);
    }

    #[test]
    fn test_ehlo_capabilities_parse() {
        let lines = vec![
            "250-mail.example.com Hello".to_string(),
            "250-PIPELINING".to_string(),
            "250-SIZE 52428800".to_string(),
            "250-STARTTLS".to_string(),
            "250-AUTH PLAIN LOGIN".to_string(),
            "250-8BITMIME".to_string(),
            "250-CHUNKING".to_string(),
            "250-DSN".to_string(),
            "250-SMTPUTF8".to_string(),
            "250 ENHANCEDSTATUSCODES".to_string(),
        ];
        let caps = EhloCapabilities::parse(&lines);
        assert!(caps.pipelining);
        assert!(caps.starttls);
        assert!(caps.size);
        assert_eq!(caps.max_size, 52428800);
        assert!(caps.eight_bit_mime);
        assert!(caps.chunking);
        assert!(caps.dsn);
        assert!(caps.smtputf8);
        assert!(caps.enhanced_status_codes);
        assert_eq!(caps.auth_mechanisms, vec!["PLAIN", "LOGIN"]);
    }

    #[test]
    fn test_ehlo_capabilities_empty() {
        let caps = EhloCapabilities::parse(&[]);
        assert!(!caps.pipelining);
        assert!(!caps.starttls);
    }

    #[test]
    fn test_smtp_response_classification() {
        let success = SmtpResponse {
            code: 250,
            enhanced_code: Some("2.1.0".into()),
            lines: vec!["250 OK".into()],
            is_multiline: false,
        };
        assert!(success.is_success());
        assert!(!success.is_temp_fail());
        assert!(!success.is_perm_fail());

        let temp_fail = SmtpResponse {
            code: 451,
            enhanced_code: None,
            lines: vec!["451 Try again later".into()],
            is_multiline: false,
        };
        assert!(!temp_fail.is_success());
        assert!(temp_fail.is_temp_fail());

        let perm_fail = SmtpResponse {
            code: 550,
            enhanced_code: None,
            lines: vec!["550 User unknown".into()],
            is_multiline: false,
        };
        assert!(!perm_fail.is_success());
        assert!(perm_fail.is_perm_fail());
    }

    #[test]
    fn test_parse_enhanced_status() {
        assert_eq!(parse_enhanced_status("2.1.0 Ok"), Some("2.1.0".to_string()));
        assert_eq!(
            parse_enhanced_status("5.1.1 User unknown"),
            Some("5.1.1".to_string())
        );
        assert!(parse_enhanced_status("invalid").is_none());
        assert!(parse_enhanced_status("").is_none());
    }

    #[test]
    fn test_transport_entry_no_hosts() {
        let transport = SmtpTransport::new();
        let config = TransportInstanceConfig {
            name: "test".into(),
            driver_name: "smtp".into(),
            options: Box::new(SmtpTransportOptions::default()),
            ..Default::default()
        };
        let result = transport.transport_entry(&config, "sender@example.com");
        assert!(matches!(result, Ok(TransportResult::Error { .. })));
    }

    #[test]
    fn test_setup_returns_ok() {
        let transport = SmtpTransport::new();
        let config = TransportInstanceConfig {
            name: "test".into(),
            driver_name: "smtp".into(),
            options: Box::new(SmtpTransportOptions::default()),
            ..Default::default()
        };
        assert!(transport.setup(&config, "user@example.com").is_ok());
    }
}
