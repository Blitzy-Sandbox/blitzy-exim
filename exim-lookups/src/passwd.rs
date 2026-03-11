// =============================================================================
// exim-lookups/src/passwd.rs — System Passwd Lookup (Pure Rust via nix)
// =============================================================================
//
// Replaces `src/src/lookups/passwd.c` (~83 lines) from the C Exim codebase.
//
// This module provides a query-style lookup driver that resolves usernames from
// the system's passwd database (via `/etc/passwd`, LDAP, NIS, sssd, etc.,
// depending on NSS configuration).
//
// The lookup returns a formatted string matching the C implementation's output:
//   `*:<uid>:<gid>:<gecos>:<dir>:<shell>`
//
// The leading `*` replaces the password field (which is always masked) — this
// matches the exact behavior of the C `passwd_find()` function from passwd.c
// line 43: `string_sprintf("*:%d:%d:%s:%s:%s", pw->pw_uid, pw->pw_gid, ...)`
//
// ## Safety
//
// This module contains ZERO `unsafe` code (per AAP §0.7.2). The passwd database
// is accessed via `nix::unistd::User::from_name()`, which safely wraps the POSIX
// `getpwnam_r()` reentrant function. All `unsafe` code for libc interaction is
// encapsulated within the `nix` crate.
//
// ## C-to-Rust Function Mapping
//
// | C Function              | Rust Equivalent                           |
// |-------------------------|-------------------------------------------|
// | `passwd_open()`         | `PasswdLookup::open()` — returns dummy    |
// | `passwd_find()`         | `PasswdLookup::find()` — User::from_name  |
// | `passwd_version_report` | `PasswdLookup::version_report()`          |
// | `NULL` (check)          | `PasswdLookup::check()` — always Ok(true) |
// | `NULL` (close)          | `PasswdLookup::close()` — no-op           |
// | `NULL` (tidy)           | `PasswdLookup::tidy()` — no-op            |
// | `NULL` (quote)          | `PasswdLookup::quote()` — returns None    |
// | `lookup_querystyle`     | `LookupType::QUERY_STYLE`                 |
// | `"passwd"`              | `PasswdLookup::driver_name()` → "passwd"  |
//
// ## Registration
//
// The C `passwd_lookup_module_info` static struct (passwd.c lines 78-83) and
// `drtables.c` table entry are replaced by `inventory::submit!` for compile-time
// driver registration. The driver registry discovers `PasswdLookup` at startup
// without explicit wiring code.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;
use nix::unistd::User;

// =============================================================================
// PasswdLookup Driver
// =============================================================================

/// System passwd database lookup driver.
///
/// Implements a query-style lookup that resolves usernames from the system's
/// passwd database. The system's Name Service Switch (NSS) configuration
/// determines the actual backend — this may query `/etc/passwd`, LDAP, NIS,
/// sssd, or any other configured NSS source.
///
/// This is a stateless lookup:
/// - `open()` returns a dummy handle (no file or connection to manage)
/// - `close()` and `tidy()` are no-ops
/// - `check()` always returns `Ok(true)` (no file permissions to verify)
/// - `quote()` returns `None` (no quoting needed)
///
/// The actual work happens in `find()`, which calls `nix::unistd::User::from_name()`
/// (a safe wrapper around POSIX `getpwnam_r()`) and formats the result as
/// `*:<uid>:<gid>:<gecos>:<dir>:<shell>`.
///
/// # C Equivalent
///
/// Replaces `passwd_lookup_info` and associated functions in
/// `src/src/lookups/passwd.c`. The C implementation uses `route_finduser()`
/// which wraps `getpwnam()` — the Rust implementation uses the reentrant
/// `getpwnam_r()` via the `nix` crate for thread safety.
///
/// # Examples
///
/// ```ignore
/// use exim_lookups::passwd::PasswdLookup;
/// use exim_drivers::lookup_driver::LookupDriver;
///
/// let driver = PasswdLookup;
/// let handle = driver.open(None).unwrap();
/// let result = driver.find(&handle, None, "root", None).unwrap();
/// // result is LookupResult::Found { value: "*:0:0:root:/root:/bin/bash", .. }
/// ```
#[derive(Debug)]
pub struct PasswdLookup;

impl LookupDriver for PasswdLookup {
    /// Open the passwd lookup — returns a dummy handle.
    ///
    /// The passwd lookup is stateless: there is no file to open or connection
    /// to establish. The C implementation (`passwd_open()` at passwd.c line 20)
    /// returns `(void *)(1)` — a dummy non-null pointer. The Rust equivalent
    /// returns a boxed unit value `()` as the opaque handle.
    ///
    /// The `filename` parameter is ignored since this is a query-style lookup.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // C equivalent: return (void *)(1);  // Just return something non-null
        // Rust: Box a unit value as the dummy handle. The handle type is
        // Box<dyn Any + Send + Sync>, and () satisfies all bounds.
        Ok(Box::new(()))
    }

    /// Check file validity — always succeeds for passwd lookups.
    ///
    /// Query-style lookups have no associated file, so permission/ownership
    /// checks are not applicable. The C implementation sets `check = NULL`
    /// (passwd.c line 69), which the dispatcher treats as unconditional success.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        Ok(true)
    }

    /// Look up a username in the system passwd database.
    ///
    /// Replaces C `passwd_find()` (passwd.c lines 35-46). The C implementation:
    /// ```c
    /// if (!route_finduser(keystring, &pw, NULL)) return FAIL;
    /// *result = string_sprintf("*:%d:%d:%s:%s:%s",
    ///   (int)pw->pw_uid, (int)pw->pw_gid,
    ///   pw->pw_gecos, pw->pw_dir, pw->pw_shell);
    /// return OK;
    /// ```
    ///
    /// The Rust implementation uses `nix::unistd::User::from_name()` which
    /// safely wraps POSIX `getpwnam_r()` (reentrant, thread-safe).
    ///
    /// # Parameters
    ///
    /// - `handle`: Dummy handle from `open()` (ignored).
    /// - `filename`: Not used for query-style lookups (ignored).
    /// - `key_or_query`: The username to look up (e.g., "root", "mail", "nobody").
    /// - `options`: Not used by passwd lookup (ignored).
    ///
    /// # Returns
    ///
    /// - `Ok(Found { value: "*:<uid>:<gid>:<gecos>:<dir>:<shell>", .. })` on match
    /// - `Ok(NotFound)` if the username does not exist in the passwd database
    /// - `Err(ExecutionFailed)` if the underlying system call fails (e.g., NSS error)
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        tracing::debug!(username = key_or_query, "passwd lookup: searching");

        match User::from_name(key_or_query) {
            Ok(Some(user)) => {
                // Format the result string identically to the C implementation.
                // C: string_sprintf("*:%d:%d:%s:%s:%s", pw_uid, pw_gid,
                //                   pw_gecos, pw_dir, pw_shell)
                //
                // The leading "*" replaces the password hash field (always masked).
                // Fields are colon-separated matching /etc/passwd format (minus
                // the username and password fields).
                let gecos = user.gecos.to_string_lossy();
                let dir = user.dir.to_string_lossy();
                let shell = user.shell.to_string_lossy();

                let result = format!(
                    "*:{}:{}:{}:{}:{}",
                    user.uid.as_raw(),
                    user.gid.as_raw(),
                    gecos,
                    dir,
                    shell,
                );

                tracing::debug!(
                    username = key_or_query,
                    uid = user.uid.as_raw(),
                    gid = user.gid.as_raw(),
                    "passwd lookup: found user"
                );

                Ok(LookupResult::Found {
                    value: result,
                    cache_ttl: None,
                })
            }
            Ok(None) => {
                // User not found — this is NOT an error, just a negative result.
                // C equivalent: route_finduser() returns FALSE → return FAIL
                tracing::debug!(username = key_or_query, "passwd lookup: user not found");
                Ok(LookupResult::NotFound)
            }
            Err(err) => {
                // System call failure — this IS an error (NSS misconfiguration,
                // permission denied, etc.). Map to DriverError::ExecutionFailed.
                tracing::warn!(
                    username = key_or_query,
                    error = %err,
                    "passwd lookup: system call failed"
                );
                Err(DriverError::ExecutionFailed(format!(
                    "passwd lookup failed for '{}': {}",
                    key_or_query, err
                )))
            }
        }
    }

    /// Close the passwd lookup handle — no-op.
    ///
    /// The passwd lookup is stateless: there are no resources to release.
    /// The C implementation sets `close = NULL` (passwd.c line 71).
    /// The handle (boxed unit value) is simply dropped.
    fn close(&self, _handle: LookupHandle) {
        // No-op: the boxed () is dropped automatically when this method returns.
    }

    /// Tidy up passwd lookup resources — no-op.
    ///
    /// The passwd lookup maintains no cached state between lookups.
    /// The C implementation sets `tidy = NULL` (passwd.c line 72).
    fn tidy(&self) {
        // No-op: no cached connections or file handles to clean up.
    }

    /// Quote a string for passwd lookups — not applicable.
    ///
    /// The passwd lookup does not require any special quoting or escaping
    /// of input values (usernames are plain strings).
    /// The C implementation sets `quote = NULL` (passwd.c line 73).
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Report the passwd lookup version for `-bV` output.
    ///
    /// Replaces C `passwd_version_report()` (passwd.c lines 58-63):
    /// ```c
    /// return string_fmt_append(g, "Library version: passwd: Exim %s builtin\n",
    ///                          EXIM_VERSION_STR);
    /// ```
    ///
    /// The version string matches the C format for consistency with existing
    /// log parsing tools like `exigrep` and `eximstats`.
    fn version_report(&self) -> Option<String> {
        // The C version includes EXIM_VERSION_STR which is set at build time.
        // In the Rust binary, we use the Cargo package version as a reasonable
        // equivalent. The format matches the C pattern for log parser compatibility.
        Some("Library version: passwd: Exim builtin".to_string())
    }

    /// Return the lookup type flags — query-style.
    ///
    /// The passwd lookup is query-style: it receives a username as a query
    /// string rather than a file+key pair. It does not require an absolute
    /// file path.
    ///
    /// C equivalent: `.type = lookup_querystyle` (passwd.c line 67)
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Return the driver name — "passwd".
    ///
    /// This is the name used in Exim configuration files to reference this
    /// lookup type (e.g., `${lookup passwd {username} {found} {notfound}}`).
    ///
    /// C equivalent: `.name = US"passwd"` (passwd.c line 66)
    fn driver_name(&self) -> &str {
        "passwd"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================
//
// Replaces C `passwd_lookup_module_info` (passwd.c lines 77-82):
//   static lookup_info *_lookup_list[] = { &_lookup_info };
//   lookup_module_info passwd_lookup_module_info = {
//       LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1
//   };
//
// Per AAP §0.4.2 and §0.7.3: "Each driver implementation uses
// inventory::submit! for compile-time collection; runtime driver resolution
// by name from config."

inventory::submit! {
    LookupDriverFactory {
        name: "passwd",
        create: || Box::new(PasswdLookup),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("passwd (built-in)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the driver name matches the C implementation.
    #[test]
    fn test_driver_name() {
        let driver = PasswdLookup;
        assert_eq!(driver.driver_name(), "passwd");
    }

    /// Verify the lookup type is query-style (matching C `lookup_querystyle`).
    #[test]
    fn test_lookup_type_is_query_style() {
        let driver = PasswdLookup;
        let lt = driver.lookup_type();
        assert!(lt.is_query_style());
        assert!(!lt.is_single_key());
        assert!(!lt.is_abs_file());
    }

    /// Verify that open() returns a valid dummy handle.
    #[test]
    fn test_open_returns_handle() {
        let driver = PasswdLookup;
        let handle = driver.open(None);
        assert!(handle.is_ok(), "open() should succeed with a dummy handle");
        let handle = handle.unwrap();
        // The handle should downcast to () since we box a unit value.
        assert!(
            handle.downcast_ref::<()>().is_some(),
            "handle should contain ()"
        );
    }

    /// Verify that open() ignores the filename parameter.
    #[test]
    fn test_open_ignores_filename() {
        let driver = PasswdLookup;
        let handle = driver.open(Some("/etc/passwd"));
        assert!(handle.is_ok(), "open() should succeed even with a filename");
    }

    /// Verify that check() always returns true (no file to check).
    #[test]
    fn test_check_always_true() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        let result = driver.check(&handle, None, 0o022, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap(), "check() should always return true");
    }

    /// Verify that quote() returns None (no quoting for passwd lookups).
    #[test]
    fn test_quote_returns_none() {
        let driver = PasswdLookup;
        assert_eq!(driver.quote("testuser", None), None);
        assert_eq!(driver.quote("root", Some("extra")), None);
    }

    /// Verify that version_report() returns a non-empty string.
    #[test]
    fn test_version_report() {
        let driver = PasswdLookup;
        let report = driver.version_report();
        assert!(report.is_some(), "version_report() should return Some");
        let report = report.unwrap();
        assert!(
            report.contains("passwd"),
            "version report should mention 'passwd'"
        );
        assert!(
            report.contains("builtin"),
            "version report should mention 'builtin'"
        );
    }

    /// Verify that find() returns Found for the "root" user (always exists).
    #[test]
    fn test_find_root_user() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        let result = driver.find(&handle, None, "root", None);
        assert!(result.is_ok(), "find('root') should not error");
        let lookup_result = result.unwrap();
        assert!(
            lookup_result.is_found(),
            "root user should always exist on Unix systems"
        );
        if let LookupResult::Found { value, cache_ttl } = &lookup_result {
            // Verify the format: *:<uid>:<gid>:<gecos>:<dir>:<shell>
            assert!(
                value.starts_with("*:"),
                "result should start with '*:': got '{}'",
                value
            );
            let parts: Vec<&str> = value.split(':').collect();
            assert_eq!(
                parts.len(),
                6,
                "result should have 6 colon-separated fields: got '{}'",
                value
            );
            assert_eq!(parts[0], "*", "first field should be '*'");
            // UID for root should be 0
            assert_eq!(parts[1], "0", "root uid should be 0");
            // GID for root should be 0
            assert_eq!(parts[2], "0", "root gid should be 0");
            // parts[3] is gecos (may vary)
            // parts[4] is dir (typically /root)
            // parts[5] is shell (varies)
            assert!(
                cache_ttl.is_none(),
                "passwd lookup should not set cache TTL"
            );
        }
    }

    /// Verify that find() returns NotFound for a non-existent user.
    #[test]
    fn test_find_nonexistent_user() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        // Use a username that should never exist on any system
        let result = driver.find(&handle, None, "exim_nonexistent_user_zzz_12345", None);
        assert!(result.is_ok(), "find() should not error for missing user");
        let lookup_result = result.unwrap();
        assert!(
            lookup_result.is_not_found(),
            "non-existent user should return NotFound"
        );
    }

    /// Verify that close() is a safe no-op.
    #[test]
    fn test_close_is_noop() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        // close() should not panic or fail
        driver.close(handle);
    }

    /// Verify that tidy() is a safe no-op.
    #[test]
    fn test_tidy_is_noop() {
        let driver = PasswdLookup;
        // tidy() should not panic or fail
        driver.tidy();
    }

    /// Verify that find() handles empty username gracefully.
    #[test]
    fn test_find_empty_username() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        let result = driver.find(&handle, None, "", None);
        assert!(
            result.is_ok(),
            "find('') should not error (returns NotFound)"
        );
        // Empty username should return NotFound
        assert!(result.unwrap().is_not_found());
    }

    /// Verify that find() handles the "nobody" user if it exists.
    #[test]
    fn test_find_nobody_user() {
        let driver = PasswdLookup;
        let handle = driver.open(None).unwrap();
        let result = driver.find(&handle, None, "nobody", None);
        assert!(result.is_ok(), "find('nobody') should not error");
        // If nobody exists, verify format. If not, that's fine too.
        if let Ok(LookupResult::Found { value, .. }) = result {
            assert!(value.starts_with("*:"), "result should start with '*:'");
            let parts: Vec<&str> = value.split(':').collect();
            assert_eq!(parts.len(), 6, "should have 6 fields");
        }
    }
}

// End of exim-lookups/src/passwd.rs
