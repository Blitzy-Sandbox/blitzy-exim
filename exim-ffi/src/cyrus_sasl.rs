//! Safe wrappers around the Cyrus SASL library (libsasl2).
//!
//! Provides managed SASL context and connection handles for server-side
//! SASL authentication, supporting all mechanisms installed as libsasl2 plugins
//! (PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, SCRAM, GSSAPI, etc.).
//!
//! This module wraps `<sasl/sasl.h>` — the Cyrus SASL C library.
//! NOT to be confused with libgsasl (GNU SASL) which is wrapped in `gsasl.rs`.
//!
//! # Safety Policy
//!
//! All `unsafe` blocks in this module are documented with inline justification
//! comments. The raw C pointers (`*mut ffi::sasl_conn_t`) are wrapped in RAII
//! structs whose `Drop` implementations call the appropriate C cleanup functions
//! (`sasl_dispose`, `sasl_done`).
//!
//! # Example
//!
//! ```no_run
//! use exim_ffi::cyrus_sasl::{SaslContext, SaslConnection, SaslStepResult};
//!
//! let _ctx = SaslContext::new("exim").expect("failed to init SASL");
//! let mut conn = SaslConnection::new("smtp", "mail.example.com", None)
//!     .expect("failed to create SASL connection");
//! let mechs = conn.list_mechanisms().expect("failed to list mechanisms");
//! println!("Available mechanisms: {mechs}");
//! ```

use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;

// ---------------------------------------------------------------------------
// Raw FFI bindings — manual extern "C" declarations for <sasl/sasl.h>.
// ---------------------------------------------------------------------------
//
// These are hand-written rather than bindgen-generated because the Cyrus SASL
// API surface used by Exim is small (≈15 functions) and stable. Manual
// declarations give precise control over types and avoid pulling in the
// entire sasl.h header graph.

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code
)]
// Justification: FFI bindings preserve C naming conventions from <sasl/sasl.h>.
// Suppressing these lints is standard practice for FFI interop code and does
// not hide any logic errors.
mod ffi {
    use libc::{c_char, c_int, c_uint, c_ulong, c_void};

    // -----------------------------------------------------------------------
    // Result codes from <sasl/sasl.h> — used for control flow after each
    // SASL API call.  Values verified against /usr/include/sasl/sasl.h.
    // -----------------------------------------------------------------------
    pub const SASL_CONTINUE: c_int = 1;
    pub const SASL_OK: c_int = 0;
    pub const SASL_FAIL: c_int = -1;
    pub const SASL_NOMEM: c_int = -2;
    pub const SASL_BUFOVER: c_int = -3;
    pub const SASL_NOMECH: c_int = -4;
    pub const SASL_BADPROT: c_int = -5;
    pub const SASL_NOTDONE: c_int = -6;
    pub const SASL_BADPARAM: c_int = -7;
    pub const SASL_TRYAGAIN: c_int = -8;
    pub const SASL_BADMAC: c_int = -9;
    pub const SASL_NOTINIT: c_int = -12;
    pub const SASL_BADAUTH: c_int = -13;
    pub const SASL_NOAUTHZ: c_int = -14;
    pub const SASL_ENCRYPT: c_int = -16;
    pub const SASL_EXPIRED: c_int = -18;
    pub const SASL_DISABLED: c_int = -19;
    pub const SASL_NOUSER: c_int = -20;

    // -----------------------------------------------------------------------
    // Flag constants — passed to sasl_server_new() `flags` parameter.
    // -----------------------------------------------------------------------
    pub const SASL_SUCCESS_DATA: c_uint = 0x0004;

    // -----------------------------------------------------------------------
    // Property constants — used with sasl_getprop() / sasl_setprop().
    // Values verified against /usr/include/sasl/sasl.h.
    // -----------------------------------------------------------------------
    pub const SASL_USERNAME: c_int = 0;
    pub const SASL_SSF: c_int = 1;
    pub const SASL_MAXOUTBUF: c_int = 2;
    pub const SASL_IPLOCALPORT: c_int = 8;
    pub const SASL_IPREMOTEPORT: c_int = 9;
    pub const SASL_SSF_EXTERNAL: c_int = 100;

    // -----------------------------------------------------------------------
    // Callback ID constants — the `id` field of sasl_callback_t.
    // Type is c_ulong because the C struct uses `unsigned long id`.
    // -----------------------------------------------------------------------
    pub const SASL_CB_LIST_END: c_ulong = 0;
    pub const SASL_CB_LOG: c_ulong = 2;

    // -----------------------------------------------------------------------
    // SASL log level constants — passed to the log callback `level` param.
    // -----------------------------------------------------------------------
    pub const SASL_LOG_NONE: c_int = 0;
    pub const SASL_LOG_ERR: c_int = 1;
    pub const SASL_LOG_FAIL: c_int = 2;
    pub const SASL_LOG_WARN: c_int = 3;
    pub const SASL_LOG_NOTE: c_int = 4;
    pub const SASL_LOG_DEBUG: c_int = 5;
    pub const SASL_LOG_TRACE: c_int = 6;
    pub const SASL_LOG_PASS: c_int = 7;

    // -----------------------------------------------------------------------
    // Opaque type — represents a SASL connection handle (sasl_conn_t *).
    // -----------------------------------------------------------------------
    pub enum sasl_conn_t {}

    // -----------------------------------------------------------------------
    // Callback struct — matches the C `sasl_callback_t` layout exactly.
    //
    //   typedef struct sasl_callback {
    //       unsigned long id;
    //       int (*proc)(void);
    //       void *context;
    //   } sasl_callback_t;
    //
    // The `id` field is `unsigned long` (c_ulong on 64-bit Linux = 8 bytes).
    // Using c_uint here would cause struct layout misalignment.
    // -----------------------------------------------------------------------
    #[repr(C)]
    pub struct sasl_callback_t {
        pub id: c_ulong,
        pub proc_: Option<unsafe extern "C" fn() -> c_int>,
        pub context: *mut c_void,
    }

    // -----------------------------------------------------------------------
    // Function declarations — the core Cyrus SASL server API.
    // -----------------------------------------------------------------------
    extern "C" {
        /// Initialize the SASL library for server use.
        /// Must be called once before any other SASL function.
        pub fn sasl_server_init(callbacks: *const sasl_callback_t, appname: *const c_char)
            -> c_int;

        /// Create a new SASL server connection.
        pub fn sasl_server_new(
            service: *const c_char,
            server_fqdn: *const c_char,
            user_realm: *const c_char,
            iplocalport: *const c_char,
            ipremoteport: *const c_char,
            callbacks: *const sasl_callback_t,
            flags: c_uint,
            pconn: *mut *mut sasl_conn_t,
        ) -> c_int;

        /// List available SASL mechanisms for a connection.
        pub fn sasl_listmech(
            conn: *mut sasl_conn_t,
            user: *const c_char,
            prefix: *const c_char,
            sep: *const c_char,
            suffix: *const c_char,
            result: *mut *const c_char,
            plen: *mut c_uint,
            pcount: *mut c_int,
        ) -> c_int;

        /// Begin a SASL authentication exchange.
        pub fn sasl_server_start(
            conn: *mut sasl_conn_t,
            mech: *const c_char,
            clientin: *const c_char,
            clientinlen: c_uint,
            serverout: *mut *const c_char,
            serveroutlen: *mut c_uint,
        ) -> c_int;

        /// Continue a SASL authentication exchange with the next client token.
        pub fn sasl_server_step(
            conn: *mut sasl_conn_t,
            clientin: *const c_char,
            clientinlen: c_uint,
            serverout: *mut *const c_char,
            serveroutlen: *mut c_uint,
        ) -> c_int;

        /// Get a property of a SASL connection (e.g., authenticated username).
        pub fn sasl_getprop(
            conn: *mut sasl_conn_t,
            propnum: c_int,
            pvalue: *mut *const c_void,
        ) -> c_int;

        /// Set a property on a SASL connection (e.g., IP addresses).
        pub fn sasl_setprop(conn: *mut sasl_conn_t, propnum: c_int, value: *const c_void) -> c_int;

        /// Dispose of a SASL connection, releasing all associated resources.
        pub fn sasl_dispose(pconn: *mut *mut sasl_conn_t);

        /// Shut down the SASL library and release global resources.
        /// Must be called after all connections are disposed.
        pub fn sasl_done();

        /// Convert a SASL error code to a human-readable string.
        /// The returned string is statically allocated and must not be freed.
        pub fn sasl_errstring(
            saslerr: c_int,
            langlist: *const c_char,
            outlang: *mut *const c_char,
        ) -> *const c_char;

        /// Get detailed error information for a specific SASL connection.
        /// The returned string is valid until the next SASL call on this conn.
        pub fn sasl_errdetail(conn: *mut sasl_conn_t) -> *const c_char;

        /// Get the SASL library version information.
        /// All parameters are optional (NULL to skip).
        pub fn sasl_version_info(
            implementation: *mut *const c_char,
            version_string: *mut *const c_char,
            version_major: *mut c_int,
            version_minor: *mut c_int,
            version_step: *mut c_int,
            version_patch: *mut c_int,
        );
    }
}

// ---------------------------------------------------------------------------
// SaslError — Typed error wrapping a SASL numeric error code.
// ---------------------------------------------------------------------------

/// Error type representing a Cyrus SASL library error.
///
/// Wraps both a numeric SASL result code and a human-readable error message
/// obtained from `sasl_errstring()` (generic errors) or `sasl_errdetail()`
/// (connection-specific errors).
#[derive(Debug, Clone)]
pub struct SaslError {
    /// Raw SASL error code (negative values indicate errors).
    code: i32,
    /// Human-readable error description from the SASL library.
    message: String,
}

impl SaslError {
    /// Create an error from a SASL result code using `sasl_errstring()`.
    ///
    /// This is used for errors that are not associated with a specific
    /// connection (e.g., initialization failures).
    pub fn from_code(code: i32) -> Self {
        // unsafe justification: calling sasl_errstring() to convert a numeric
        // SASL error code to a human-readable static string. This is a pure
        // lookup function with no side effects. The returned pointer refers to
        // a statically allocated string within libsasl2 that remains valid for
        // the lifetime of the process.
        let message = unsafe {
            let ptr = ffi::sasl_errstring(code, ptr::null(), ptr::null_mut());
            if ptr.is_null() {
                format!("unknown SASL error (code {code})")
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Self { code, message }
    }

    /// Create an error from a connection-specific SASL failure.
    ///
    /// Uses `sasl_errdetail()` which provides more context than the generic
    /// `sasl_errstring()`, including mechanism-specific information.
    pub fn from_connection(conn: &SaslConnection, code: i32) -> Self {
        // unsafe justification: calling sasl_errdetail() to retrieve
        // connection-specific error details. The returned pointer is valid
        // only until the next SASL call on this connection, so we immediately
        // copy it to an owned String.
        let message = unsafe {
            let ptr = ffi::sasl_errdetail(conn.conn);
            if ptr.is_null() {
                // Fall back to the generic error string if errdetail returns null.
                let generic = ffi::sasl_errstring(code, ptr::null(), ptr::null_mut());
                if generic.is_null() {
                    format!("unknown SASL error (code {code})")
                } else {
                    CStr::from_ptr(generic).to_string_lossy().into_owned()
                }
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Self { code, message }
    }

    /// Get the raw SASL error code.
    ///
    /// Negative values indicate errors; 0 is `SASL_OK`, 1 is `SASL_CONTINUE`.
    #[inline]
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Get the human-readable error message from the SASL library.
    #[inline]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SaslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SASL error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for SaslError {}

// ---------------------------------------------------------------------------
// SaslStepResult — Outcome of a SASL authentication step.
// ---------------------------------------------------------------------------

/// Result of a SASL authentication step (`server_start` or `server_step`).
///
/// SASL authentication is a multi-step process. Each step returns either
/// `Complete` (authentication finished, SASL_OK) or `Continue` (more client
/// data needed, SASL_CONTINUE), along with optional server data to send
/// to the client.
#[derive(Debug)]
pub enum SaslStepResult {
    /// Authentication is complete (`SASL_OK`).
    ///
    /// Contains optional final server data that may need to be sent to the
    /// client (e.g., for mechanisms with mutual authentication).
    Complete(Vec<u8>),

    /// More steps are needed (`SASL_CONTINUE`).
    ///
    /// Contains the server challenge data to send to the client. The client
    /// must respond with the next token to continue the exchange.
    Continue(Vec<u8>),
}

// ---------------------------------------------------------------------------
// SaslProperty — Named property identifiers for sasl_getprop/sasl_setprop.
// ---------------------------------------------------------------------------

/// SASL connection property identifiers.
///
/// These map to the `SASL_*` property constants in `<sasl/sasl.h>` and are
/// used with [`SaslConnection::set_prop`] and [`SaslConnection::get_username`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslProperty {
    /// Authenticated username (read-only after successful authentication).
    /// Maps to `SASL_USERNAME` (0).
    Username,

    /// Security Strength Factor — the number of bits of encryption
    /// protecting the connection. Maps to `SASL_SSF` (1).
    Ssf,

    /// Maximum output buffer size for the security layer.
    /// Maps to `SASL_MAXOUTBUF` (2).
    MaxOutBuf,

    /// Local IP address and port in "addr;port" format.
    /// Maps to `SASL_IPLOCALPORT` (8).
    IpLocalPort,

    /// Remote IP address and port in "addr;port" format.
    /// Maps to `SASL_IPREMOTEPORT` (9).
    IpRemotePort,
}

impl SaslProperty {
    /// Convert the Rust enum variant to the C SASL property constant.
    fn to_c_propnum(self) -> libc::c_int {
        match self {
            SaslProperty::Username => ffi::SASL_USERNAME,
            SaslProperty::Ssf => ffi::SASL_SSF,
            SaslProperty::MaxOutBuf => ffi::SASL_MAXOUTBUF,
            SaslProperty::IpLocalPort => ffi::SASL_IPLOCALPORT,
            SaslProperty::IpRemotePort => ffi::SASL_IPREMOTEPORT,
        }
    }
}

// ---------------------------------------------------------------------------
// SaslVersionInfo — Library version metadata.
// ---------------------------------------------------------------------------

/// Cyrus SASL library version information.
///
/// Populated by calling [`version_info()`], which wraps the C
/// `sasl_version_info()` function.
#[derive(Debug, Clone)]
pub struct SaslVersionInfo {
    /// Implementation name (e.g., "Cyrus SASL").
    pub implementation: String,
    /// Full version string (e.g., "2.1.28").
    pub version_string: String,
    /// Major version number.
    pub version_major: i32,
    /// Minor version number.
    pub version_minor: i32,
    /// Step (patch) version number.
    pub version_step: i32,
    /// Additional patch level (typically 0).
    pub version_patch: i32,
}

// ---------------------------------------------------------------------------
// Logging callback — routes libsasl2 log messages to the tracing framework.
// ---------------------------------------------------------------------------

/// Extern "C" trampoline for the SASL logging callback.
///
/// This function is registered with libsasl2 via a `sasl_callback_t` entry
/// with id `SASL_CB_LOG`. When libsasl2 generates a log message, it invokes
/// this callback which converts the C string and routes it to Rust's `tracing`
/// framework at an appropriate severity level.
///
/// # Safety
///
/// This function is called from C code within libsasl2. The `message` pointer
/// must be a valid null-terminated C string (or null, which we handle). The
/// `context` pointer is unused (null) in our registration.
unsafe extern "C" fn sasl_log_callback(
    _context: *mut libc::c_void,
    level: libc::c_int,
    message: *const libc::c_char,
) -> libc::c_int {
    // unsafe justification: this is a C callback invoked by libsasl2 for logging.
    // We read the C string message pointer and forward its content to the Rust
    // tracing framework. The message pointer is guaranteed valid by the SASL
    // library contract for the duration of this callback invocation.
    let msg = if message.is_null() {
        "(null)"
    } else {
        // CStr::from_ptr requires a valid null-terminated string.
        // If the SASL library passes a valid pointer (contractual guarantee),
        // this is safe.
        CStr::from_ptr(message)
            .to_str()
            .unwrap_or("(invalid UTF-8 in SASL log message)")
    };

    match level {
        ffi::SASL_LOG_ERR => tracing::error!(target: "exim::sasl", "{}", msg),
        ffi::SASL_LOG_FAIL => tracing::warn!(target: "exim::sasl", "auth failure: {}", msg),
        ffi::SASL_LOG_WARN => tracing::warn!(target: "exim::sasl", "{}", msg),
        ffi::SASL_LOG_NOTE => tracing::info!(target: "exim::sasl", "{}", msg),
        ffi::SASL_LOG_DEBUG => tracing::debug!(target: "exim::sasl", "{}", msg),
        ffi::SASL_LOG_TRACE | ffi::SASL_LOG_PASS => {
            tracing::trace!(target: "exim::sasl", "{}", msg);
        }
        _ => tracing::debug!(target: "exim::sasl", "level={}: {}", level, msg),
    }

    ffi::SASL_OK
}

/// Build the standard SASL callback array used for library initialization.
///
/// Registers the log callback trampoline so that all SASL log messages
/// are routed through the Rust tracing framework. The returned array is
/// terminated with `SASL_CB_LIST_END` as required by the SASL API.
fn make_log_callbacks() -> [ffi::sasl_callback_t; 2] {
    // unsafe justification: transmuting the typed log callback function pointer
    // to the generic `int (*)(void)` signature stored in sasl_callback_t.proc_.
    // This matches the C convention where sasl_callback_t uses a generic function
    // pointer type and the library casts it back to the specific callback
    // signature (sasl_log_t: int(*)(void*, int, const char*)) based on the
    // callback id (SASL_CB_LOG). The two function pointer types have the same
    // ABI calling convention (extern "C") and the library guarantees correct
    // argument passing at the call site.
    let log_proc: Option<unsafe extern "C" fn() -> libc::c_int> = Some(unsafe {
        std::mem::transmute::<
            unsafe extern "C" fn(
                *mut libc::c_void,
                libc::c_int,
                *const libc::c_char,
            ) -> libc::c_int,
            unsafe extern "C" fn() -> libc::c_int,
        >(sasl_log_callback)
    });

    [
        ffi::sasl_callback_t {
            id: ffi::SASL_CB_LOG,
            proc_: log_proc,
            context: ptr::null_mut(),
        },
        ffi::sasl_callback_t {
            id: ffi::SASL_CB_LIST_END,
            proc_: None,
            context: ptr::null_mut(),
        },
    ]
}

// ---------------------------------------------------------------------------
// SaslContext — Global SASL library lifecycle management.
// ---------------------------------------------------------------------------

/// Safe wrapper around the global Cyrus SASL library context.
///
/// Creating a `SaslContext` initializes the SASL library via `sasl_server_init()`.
/// Dropping it calls `sasl_done()` to clean up global resources. Only one
/// `SaslContext` should exist per process at a time, matching the libsasl2
/// library contract.
///
/// # Lifecycle
///
/// 1. Create with [`SaslContext::new("exim")`](SaslContext::new)
/// 2. Create [`SaslConnection`]s for individual authentication exchanges
/// 3. Drop all connections before dropping the context
pub struct SaslContext {
    /// Tracks whether the library was successfully initialized.
    /// Used by Drop to avoid calling sasl_done() if init failed.
    initialized: bool,
}

impl SaslContext {
    /// Initialize the Cyrus SASL library for server use.
    ///
    /// `appname` is the application name registered with the SASL library
    /// (typically `"exim"`). This name is used by SASL plugins to locate
    /// application-specific configuration files.
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] if the library fails to initialize (e.g.,
    /// missing plugin directory, out of memory).
    pub fn new(appname: &str) -> Result<Self, SaslError> {
        let c_appname = CString::new(appname).map_err(|_| SaslError {
            code: ffi::SASL_BADPARAM,
            message: "application name contains interior NUL byte".to_string(),
        })?;

        let callbacks = make_log_callbacks();

        // unsafe justification: calling sasl_server_init() to initialize the
        // global SASL library state. This must be called before any other SASL
        // function. The callbacks array is stack-allocated and remains valid
        // for the duration of the call. The appname CString is valid and
        // null-terminated. sasl_server_init copies what it needs internally.
        let rc = unsafe { ffi::sasl_server_init(callbacks.as_ptr(), c_appname.as_ptr()) };

        if rc != ffi::SASL_OK {
            return Err(SaslError::from_code(rc));
        }

        Ok(SaslContext { initialized: true })
    }
}

impl Drop for SaslContext {
    fn drop(&mut self) {
        if self.initialized {
            // unsafe justification: calling sasl_done() to clean up all global
            // SASL resources. This is the documented cleanup function that must
            // be called after all SASL connections have been disposed. The
            // initialized flag ensures we only call this if init succeeded.
            unsafe {
                ffi::sasl_done();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SaslConnection — Per-authentication-exchange wrapper.
// ---------------------------------------------------------------------------

/// Safe wrapper around a SASL server connection (`sasl_conn_t`).
///
/// Manages the lifecycle of one SASL authentication exchange. Each SMTP
/// AUTH attempt creates a new `SaslConnection`, performs the multi-step
/// SASL exchange, retrieves the authenticated username, and then drops
/// the connection.
///
/// # Lifecycle
///
/// 1. Create with [`SaslConnection::new("smtp", hostname, realm)`](SaslConnection::new)
/// 2. Optionally set properties (IP addresses) via [`set_prop`](SaslConnection::set_prop)
/// 3. Start the exchange with [`server_start`](SaslConnection::server_start)
/// 4. Continue with [`server_step`](SaslConnection::server_step) until complete
/// 5. Retrieve the username with [`get_username`](SaslConnection::get_username)
/// 6. Drop the connection (calls `sasl_dispose`)
pub struct SaslConnection {
    /// Raw pointer to the C `sasl_conn_t` structure.
    /// Owned by this struct; disposed in Drop.
    conn: *mut ffi::sasl_conn_t,
}

impl SaslConnection {
    /// Create a new SASL server connection.
    ///
    /// Parameters match the C `sasl_server_new()` function:
    /// - `service`: SASL service name (typically `"smtp"` for mail)
    /// - `hostname`: Server's fully qualified domain name
    /// - `realm`: SASL realm (or `None` for the default realm)
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] if the connection cannot be created (e.g.,
    /// library not initialized, invalid parameters).
    pub fn new(service: &str, hostname: &str, realm: Option<&str>) -> Result<Self, SaslError> {
        let c_service = CString::new(service).map_err(|_| SaslError {
            code: ffi::SASL_BADPARAM,
            message: "service name contains interior NUL byte".to_string(),
        })?;
        let c_hostname = CString::new(hostname).map_err(|_| SaslError {
            code: ffi::SASL_BADPARAM,
            message: "hostname contains interior NUL byte".to_string(),
        })?;
        let c_realm = realm
            .map(|r| {
                CString::new(r).map_err(|_| SaslError {
                    code: ffi::SASL_BADPARAM,
                    message: "realm contains interior NUL byte".to_string(),
                })
            })
            .transpose()?;

        let realm_ptr = c_realm.as_ref().map_or(ptr::null(), |r| r.as_ptr());

        let mut conn: *mut ffi::sasl_conn_t = ptr::null_mut();

        // unsafe justification: calling sasl_server_new() to create a SASL
        // server connection handle. All string parameters are valid CStrings
        // (null-terminated, no interior NUL). The NULL pointers for
        // iplocalport, ipremoteport, and callbacks are permitted by the API
        // (those can be set later via sasl_setprop). The flags=0 means no
        // special options. The conn pointer is written by the library.
        let rc = unsafe {
            ffi::sasl_server_new(
                c_service.as_ptr(),
                c_hostname.as_ptr(),
                realm_ptr,
                ptr::null(), // iplocalport — set later via set_prop
                ptr::null(), // ipremoteport — set later via set_prop
                ptr::null(), // per-connection callbacks — use global ones
                0,           // flags — no special options
                &mut conn,
            )
        };

        if rc != ffi::SASL_OK {
            return Err(SaslError::from_code(rc));
        }

        if conn.is_null() {
            return Err(SaslError {
                code: ffi::SASL_FAIL,
                message: "sasl_server_new returned OK but conn pointer is null".to_string(),
            });
        }

        Ok(SaslConnection { conn })
    }

    /// List available SASL mechanisms for this connection.
    ///
    /// Returns a space-separated string of mechanism names
    /// (e.g., `"PLAIN LOGIN CRAM-MD5 DIGEST-MD5"`).
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] if no mechanisms are available or the
    /// library encounters an error.
    pub fn list_mechanisms(&self) -> Result<String, SaslError> {
        let mut result: *const libc::c_char = ptr::null();
        let mut len: libc::c_uint = 0;
        let mut count: libc::c_int = 0;

        // Use empty strings for prefix/suffix and space for separator,
        // producing a clean space-separated mechanism list.
        let empty = CString::new("").expect("empty string cannot fail");
        let sep = CString::new(" ").expect("single space cannot fail");

        // unsafe justification: calling sasl_listmech() to query the available
        // SASL mechanisms from the library's plugin registry. The result pointer
        // is written by the library and points to memory owned by the connection
        // (valid until the connection is disposed). We copy it immediately to
        // an owned String.
        let rc = unsafe {
            ffi::sasl_listmech(
                self.conn,
                ptr::null(),    // user — NULL for all mechanisms
                empty.as_ptr(), // prefix
                sep.as_ptr(),   // separator
                empty.as_ptr(), // suffix
                &mut result,
                &mut len,
                &mut count,
            )
        };

        if rc != ffi::SASL_OK {
            return Err(SaslError::from_connection(self, rc));
        }

        if result.is_null() {
            return Ok(String::new());
        }

        // unsafe justification: reading the mechanism list string returned by
        // sasl_listmech(). The pointer is valid as long as the connection exists
        // (which it does — we hold &self). We copy to an owned String immediately.
        let mech_str = unsafe { CStr::from_ptr(result).to_string_lossy().into_owned() };

        Ok(mech_str)
    }

    /// Start SASL authentication with the given mechanism and optional initial data.
    ///
    /// This is the first step of the SASL exchange. The client typically sends
    /// the mechanism name and optional initial response in the SMTP AUTH command.
    ///
    /// Returns [`SaslStepResult::Complete`] if authentication succeeds in one
    /// step (rare), or [`SaslStepResult::Continue`] with challenge data to
    /// send to the client.
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] for authentication failures, invalid mechanisms,
    /// or protocol errors.
    pub fn server_start(
        &mut self,
        mechanism: &str,
        initial_data: Option<&[u8]>,
    ) -> Result<SaslStepResult, SaslError> {
        let c_mech = CString::new(mechanism).map_err(|_| SaslError {
            code: ffi::SASL_BADPARAM,
            message: "mechanism name contains interior NUL byte".to_string(),
        })?;

        let (client_ptr, client_len) = match initial_data {
            Some(data) => (
                data.as_ptr().cast::<libc::c_char>(),
                data.len() as libc::c_uint,
            ),
            None => (ptr::null(), 0),
        };

        let mut serverout: *const libc::c_char = ptr::null();
        let mut serveroutlen: libc::c_uint = 0;

        // unsafe justification: calling sasl_server_start() to begin the SASL
        // authentication exchange. The mechanism name is a valid CString. The
        // initial client data (if any) points to valid memory for its stated
        // length. The serverout pointer is written by the library and points
        // to library-managed memory valid until the next SASL call.
        let rc = unsafe {
            ffi::sasl_server_start(
                self.conn,
                c_mech.as_ptr(),
                client_ptr,
                client_len,
                &mut serverout,
                &mut serveroutlen,
            )
        };

        self.process_step_result(rc, serverout, serveroutlen)
    }

    /// Continue SASL authentication with the next client response.
    ///
    /// Called after receiving the client's response to the server challenge
    /// from the previous `server_start` or `server_step` call.
    ///
    /// Returns [`SaslStepResult::Complete`] when authentication is finished,
    /// or [`SaslStepResult::Continue`] with the next challenge.
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] for authentication failures or protocol errors.
    pub fn server_step(&mut self, client_data: &[u8]) -> Result<SaslStepResult, SaslError> {
        let mut serverout: *const libc::c_char = ptr::null();
        let mut serveroutlen: libc::c_uint = 0;

        // unsafe justification: calling sasl_server_step() to process the next
        // client token in the SASL exchange. The client_data slice is valid
        // for its stated length. The serverout pointer is written by the
        // library to library-managed memory valid until the next SASL call.
        let rc = unsafe {
            ffi::sasl_server_step(
                self.conn,
                client_data.as_ptr().cast::<libc::c_char>(),
                client_data.len() as libc::c_uint,
                &mut serverout,
                &mut serveroutlen,
            )
        };

        self.process_step_result(rc, serverout, serveroutlen)
    }

    /// Internal helper to interpret the result of sasl_server_start/step.
    fn process_step_result(
        &self,
        rc: libc::c_int,
        serverout: *const libc::c_char,
        serveroutlen: libc::c_uint,
    ) -> Result<SaslStepResult, SaslError> {
        // Extract server output data into an owned Vec<u8>.
        let server_data = if serverout.is_null() || serveroutlen == 0 {
            Vec::new()
        } else {
            // unsafe justification: creating a byte slice from the server output
            // pointer returned by sasl_server_start/sasl_server_step. The pointer
            // and length are as returned by the library and are valid for the
            // duration of this function call.
            unsafe {
                std::slice::from_raw_parts(serverout.cast::<u8>(), serveroutlen as usize).to_vec()
            }
        };

        match rc {
            ffi::SASL_OK => Ok(SaslStepResult::Complete(server_data)),
            ffi::SASL_CONTINUE => Ok(SaslStepResult::Continue(server_data)),
            _ => Err(SaslError::from_connection(self, rc)),
        }
    }

    /// Get the authenticated username after successful authentication.
    ///
    /// Calls `sasl_getprop(SASL_USERNAME)` to retrieve the identity
    /// established during the SASL exchange. This should only be called
    /// after `server_start`/`server_step` returns `SaslStepResult::Complete`.
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] if the username is not available (e.g.,
    /// authentication has not completed yet).
    pub fn get_username(&self) -> Result<String, SaslError> {
        let mut value: *const libc::c_void = ptr::null();

        // unsafe justification: calling sasl_getprop() with SASL_USERNAME to
        // retrieve the authenticated user identity. The returned pointer
        // points to memory owned by the connection and is valid until the
        // connection is disposed. We copy it immediately to an owned String.
        let rc = unsafe { ffi::sasl_getprop(self.conn, ffi::SASL_USERNAME, &mut value) };

        if rc != ffi::SASL_OK {
            return Err(SaslError::from_connection(self, rc));
        }

        if value.is_null() {
            return Err(SaslError {
                code: ffi::SASL_NOTDONE,
                message: "username property is null".to_string(),
            });
        }

        // unsafe justification: the value pointer for SASL_USERNAME is
        // documented to be a `const char *` (NUL-terminated C string).
        // We cast from void* to char* and read it as a CStr.
        let username = unsafe {
            CStr::from_ptr(value.cast::<libc::c_char>())
                .to_string_lossy()
                .into_owned()
        };

        Ok(username)
    }

    /// Set a SASL connection property.
    ///
    /// Used to set IP address information (`IpLocalPort`, `IpRemotePort`)
    /// or other connection properties before or during the SASL exchange.
    ///
    /// The value string format depends on the property:
    /// - `IpLocalPort` / `IpRemotePort`: `"addr;port"` (e.g., `"192.168.1.1;25"`)
    /// - `Ssf`: not typically set via string (use numeric SSF)
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] if the property cannot be set.
    pub fn set_prop(&mut self, prop: SaslProperty, value: &str) -> Result<(), SaslError> {
        let c_value = CString::new(value).map_err(|_| SaslError {
            code: ffi::SASL_BADPARAM,
            message: "property value contains interior NUL byte".to_string(),
        })?;

        let propnum = prop.to_c_propnum();

        // unsafe justification: calling sasl_setprop() to set a connection
        // property. The property number is a valid SASL_* constant. The value
        // is a valid CString cast to void*. For string properties (IPLOCALPORT,
        // IPREMOTEPORT), the library copies the string internally.
        let rc = unsafe {
            ffi::sasl_setprop(self.conn, propnum, c_value.as_ptr().cast::<libc::c_void>())
        };

        if rc != ffi::SASL_OK {
            return Err(SaslError::from_connection(self, rc));
        }

        Ok(())
    }

    /// Get detailed error information for this connection.
    ///
    /// Returns the most recent error detail string from the SASL library
    /// for this connection. This is more informative than the generic
    /// `SaslError::from_code()` as it includes mechanism-specific context.
    pub fn error_detail(&self) -> String {
        // unsafe justification: calling sasl_errdetail() to retrieve the
        // most recent connection-specific error message. The returned pointer
        // is valid until the next SASL API call on this connection. We
        // immediately copy it to an owned String.
        unsafe {
            let ptr = ffi::sasl_errdetail(self.conn);
            if ptr.is_null() {
                "(no error detail available)".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }
}

impl Drop for SaslConnection {
    fn drop(&mut self) {
        if !self.conn.is_null() {
            // unsafe justification: calling sasl_dispose() to release all
            // resources associated with this SASL connection. The function
            // takes a pointer-to-pointer and sets the inner pointer to NULL
            // after cleanup. We check for null before calling to avoid
            // double-dispose.
            unsafe {
                ffi::sasl_dispose(&mut self.conn);
            }
            // sasl_dispose sets conn to null, but we set it explicitly
            // for clarity and defense-in-depth.
            self.conn = ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------
// version_info — Retrieve SASL library version metadata.
// ---------------------------------------------------------------------------

/// Get Cyrus SASL library version information.
///
/// Calls the C `sasl_version_info()` function from libsasl2 to retrieve
/// the implementation name, version string, and numeric version components.
///
/// This function does not require the SASL library to be initialized
/// (i.e., it can be called without a [`SaslContext`]).
pub fn version_info() -> SaslVersionInfo {
    let mut c_impl: *const libc::c_char = ptr::null();
    let mut c_version: *const libc::c_char = ptr::null();
    let mut major: libc::c_int = 0;
    let mut minor: libc::c_int = 0;
    let mut step: libc::c_int = 0;
    let mut patch: libc::c_int = 0;

    // unsafe justification: calling sasl_version_info() to retrieve the SASL
    // library implementation name and version numbers. All output parameters
    // are mutable pointers to stack variables. The library writes to them
    // directly. The string pointers (implementation, version_string) point to
    // statically allocated memory within libsasl2 that is valid for the
    // process lifetime. We copy them to owned Strings immediately.
    unsafe {
        ffi::sasl_version_info(
            &mut c_impl,
            &mut c_version,
            &mut major,
            &mut minor,
            &mut step,
            &mut patch,
        );
    }

    let implementation = if c_impl.is_null() {
        "unknown".to_string()
    } else {
        // unsafe justification: reading the implementation name string returned
        // by sasl_version_info(). It points to static library memory.
        unsafe { CStr::from_ptr(c_impl).to_string_lossy().into_owned() }
    };

    let version_string = if c_version.is_null() {
        "unknown".to_string()
    } else {
        // unsafe justification: reading the version string returned by
        // sasl_version_info(). It points to static library memory.
        unsafe { CStr::from_ptr(c_version).to_string_lossy().into_owned() }
    };

    SaslVersionInfo {
        implementation,
        version_string,
        version_major: major,
        version_minor: minor,
        version_step: step,
        version_patch: patch,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that SaslError can be created from a code and formats correctly.
    #[test]
    fn test_sasl_error_from_code() {
        let err = SaslError::from_code(ffi::SASL_FAIL);
        assert_eq!(err.code(), ffi::SASL_FAIL);
        assert!(!err.message().is_empty());
        let display = format!("{err}");
        assert!(display.contains("SASL error"));
    }

    /// Verify SaslError Display and Error trait implementations.
    #[test]
    fn test_sasl_error_display() {
        let err = SaslError {
            code: -1,
            message: "test error".to_string(),
        };
        assert_eq!(format!("{err}"), "SASL error -1: test error");
        // Verify std::error::Error is implemented (method exists).
        let _: &dyn std::error::Error = &err;
    }

    /// Verify SaslProperty to C property number conversion.
    #[test]
    fn test_sasl_property_to_c() {
        assert_eq!(SaslProperty::Username.to_c_propnum(), 0);
        assert_eq!(SaslProperty::Ssf.to_c_propnum(), 1);
        assert_eq!(SaslProperty::MaxOutBuf.to_c_propnum(), 2);
        assert_eq!(SaslProperty::IpLocalPort.to_c_propnum(), 8);
        assert_eq!(SaslProperty::IpRemotePort.to_c_propnum(), 9);
    }

    /// Verify version_info returns non-empty data.
    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(
            !info.implementation.is_empty(),
            "implementation should not be empty"
        );
        assert!(
            !info.version_string.is_empty(),
            "version_string should not be empty"
        );
        assert!(info.version_major >= 2, "expected SASL major version >= 2");
    }

    /// Verify SaslStepResult variants can be constructed.
    #[test]
    fn test_step_result_variants() {
        let complete = SaslStepResult::Complete(vec![1, 2, 3]);
        let cont = SaslStepResult::Continue(vec![4, 5, 6]);
        match complete {
            SaslStepResult::Complete(data) => assert_eq!(data, vec![1, 2, 3]),
            SaslStepResult::Continue(_) => panic!("expected Complete"),
        }
        match cont {
            SaslStepResult::Continue(data) => assert_eq!(data, vec![4, 5, 6]),
            SaslStepResult::Complete(_) => panic!("expected Continue"),
        }
    }

    /// Verify SaslVersionInfo clone and debug.
    #[test]
    fn test_version_info_clone_debug() {
        let info = SaslVersionInfo {
            implementation: "test".to_string(),
            version_string: "1.0.0".to_string(),
            version_major: 1,
            version_minor: 0,
            version_step: 0,
            version_patch: 0,
        };
        let cloned = info.clone();
        assert_eq!(cloned.implementation, "test");
        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("test"));
    }

    /// Verify SaslContext initialization and cleanup.
    #[test]
    fn test_sasl_context_lifecycle() {
        let ctx = SaslContext::new("exim_test");
        assert!(
            ctx.is_ok(),
            "SaslContext::new should succeed: {:?}",
            ctx.err()
        );
        // Drop triggers sasl_done()
        drop(ctx.unwrap());
    }

    /// Verify SaslConnection creation and mechanism listing.
    #[test]
    fn test_sasl_connection_list_mechanisms() {
        let _ctx = SaslContext::new("exim_test").expect("failed to init SASL");
        let conn = SaslConnection::new("smtp", "localhost", None);
        assert!(
            conn.is_ok(),
            "SaslConnection::new should succeed: {:?}",
            conn.err()
        );
        let conn = conn.unwrap();
        let mechs = conn.list_mechanisms();
        assert!(
            mechs.is_ok(),
            "list_mechanisms should succeed: {:?}",
            mechs.err()
        );
        let mechs = mechs.unwrap();
        // At minimum, the SASL library should know about some mechanism.
        // In test environments, PLAIN or LOGIN are usually available.
        assert!(!mechs.is_empty(), "mechanism list should not be empty");
    }

    /// Verify error_detail returns a string (even without a prior error).
    #[test]
    fn test_sasl_connection_error_detail() {
        let _ctx = SaslContext::new("exim_test").expect("failed to init SASL");
        let conn = SaslConnection::new("smtp", "localhost", None).expect("failed to create conn");
        let detail = conn.error_detail();
        // Even without a prior error, errdetail should return something.
        assert!(!detail.is_empty());
    }
}
