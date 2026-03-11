// =============================================================================
// exim-ffi/build.rs — Build Script for C FFI Binding Generation
// =============================================================================
//
// This build script uses `bindgen` to generate Rust FFI bindings from C library
// headers and `cc` to compile C glue code for the `exim-ffi` crate. Each FFI
// module is feature-gated so only the libraries present on the build system
// are wrapped.
//
// Feature → C Library Mapping:
//   ffi-pam       → libpam          (PAM authentication)
//   ffi-radius    → radiusclient    (RADIUS authentication)
//   ffi-perl      → libperl         (embedded Perl interpreter)
//   ffi-gsasl     → libgsasl        (GNU SASL / SCRAM)
//   ffi-krb5      → libkrb5+gssapi  (Kerberos GSSAPI via Heimdal/MIT)
//   ffi-spf       → libspf2         (SPF validation)
//   hintsdb-bdb   → libdb           (Berkeley DB hints backend)
//   hintsdb-gdbm  → libgdbm         (GDBM hints backend)
//   hintsdb-ndbm  → libndbm         (NDBM hints backend)
//   hintsdb-tdb   → libtdb          (TDB hints backend)
//
// Usage:
//   cargo build -p exim-ffi                       # No FFI modules
//   cargo build -p exim-ffi --features ffi-pam    # Build with PAM support
//   cargo build -p exim-ffi --all-features        # Build all FFI modules
// =============================================================================

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    // Trigger rebuild when build script itself or key environment vars change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");
    println!("cargo:rerun-if-env-changed=EXIM_PERL_BIN");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo"));

    // Write active feature manifest for build diagnostics and to ensure
    // OUT_DIR is always referenced regardless of which features are active.
    write_feature_manifest(&out_dir);

    // Feature-gated binding generation for each C library wrapper.
    // Each generator:
    //   1. Probes for the library via pkg-config (or manual detection)
    //   2. Creates a small wrapper header in OUT_DIR
    //   3. Configures bindgen with allowlisted types/functions/constants
    //   4. Generates bindings to OUT_DIR/<module>_bindings.rs
    //   5. Emits cargo:rustc-link-lib and cargo:rustc-link-search as needed

    #[cfg(feature = "ffi-pam")]
    generate_pam_bindings(&out_dir);

    #[cfg(feature = "ffi-radius")]
    generate_radius_bindings(&out_dir);

    #[cfg(feature = "ffi-perl")]
    generate_perl_bindings(&out_dir);

    #[cfg(feature = "ffi-gsasl")]
    generate_gsasl_bindings(&out_dir);

    #[cfg(feature = "ffi-krb5")]
    generate_krb5_bindings(&out_dir);

    #[cfg(feature = "ffi-spf")]
    generate_spf_bindings(&out_dir);

    #[cfg(feature = "ffi-dmarc")]
    generate_dmarc_bindings(&out_dir);

    #[cfg(feature = "hintsdb-bdb")]
    generate_bdb_bindings(&out_dir);

    #[cfg(feature = "hintsdb-gdbm")]
    generate_gdbm_bindings(&out_dir);

    #[cfg(feature = "hintsdb-ndbm")]
    generate_ndbm_bindings(&out_dir);

    #[cfg(feature = "hintsdb-tdb")]
    generate_tdb_bindings(&out_dir);

    #[cfg(feature = "ffi-whoson")]
    generate_whoson_link(&out_dir);

    #[cfg(feature = "ffi-nis")]
    generate_nis_link(&out_dir);

    #[cfg(feature = "ffi-cyrus-sasl")]
    generate_cyrus_sasl_link(&out_dir);
}

// =============================================================================
// Shared Helper Functions
// =============================================================================

/// Writes a manifest listing active FFI features to OUT_DIR for build
/// diagnostics. This also ensures `out_dir` and `fs::write` are always
/// exercised regardless of which features are active.
fn write_feature_manifest(out_dir: &Path) {
    let mut features: Vec<&str> = Vec::new();
    if cfg!(feature = "ffi-pam") {
        features.push("ffi-pam");
    }
    if cfg!(feature = "ffi-radius") {
        features.push("ffi-radius");
    }
    if cfg!(feature = "ffi-perl") {
        features.push("ffi-perl");
    }
    if cfg!(feature = "ffi-gsasl") {
        features.push("ffi-gsasl");
    }
    if cfg!(feature = "ffi-krb5") {
        features.push("ffi-krb5");
    }
    if cfg!(feature = "ffi-spf") {
        features.push("ffi-spf");
    }
    if cfg!(feature = "ffi-dmarc") {
        features.push("ffi-dmarc");
    }
    if cfg!(feature = "ffi-whoson") {
        features.push("ffi-whoson");
    }
    if cfg!(feature = "ffi-nis") {
        features.push("ffi-nis");
    }
    if cfg!(feature = "ffi-cyrus-sasl") {
        features.push("ffi-cyrus-sasl");
    }
    if cfg!(feature = "hintsdb-bdb") {
        features.push("hintsdb-bdb");
    }
    if cfg!(feature = "hintsdb-gdbm") {
        features.push("hintsdb-gdbm");
    }
    if cfg!(feature = "hintsdb-ndbm") {
        features.push("hintsdb-ndbm");
    }
    if cfg!(feature = "hintsdb-tdb") {
        features.push("hintsdb-tdb");
    }

    let content = if features.is_empty() {
        "# exim-ffi: No FFI features enabled\n".to_string()
    } else {
        format!("# exim-ffi active features:\n{}\n", features.join("\n"))
    };

    fs::write(out_dir.join("ffi_features.txt"), content)
        .expect("Failed to write feature manifest to OUT_DIR");
}

/// Creates a pre-configured `bindgen::Builder` with common settings shared
/// by all FFI generators. Each generator customises this further with
/// specific function/type/constant allowlists.
///
/// Common settings:
/// - `derive_debug(true)`  — `Debug` impl on generated structs
/// - `derive_default(true)` — `Default` impl on generated structs
/// - `size_t_is_usize(true)` — map C `size_t` to Rust `usize`
#[cfg(any(
    feature = "ffi-pam",
    feature = "ffi-radius",
    feature = "ffi-perl",
    feature = "ffi-gsasl",
    feature = "ffi-krb5",
    feature = "ffi-spf",
    feature = "ffi-dmarc",
    feature = "hintsdb-bdb",
    feature = "hintsdb-gdbm",
    feature = "hintsdb-ndbm",
    feature = "hintsdb-tdb",
))]
fn create_builder(header_path: &str) -> bindgen::Builder {
    bindgen::Builder::default()
        .header(header_path)
        .derive_debug(true)
        .derive_default(true)
        .size_t_is_usize(true)
}

/// Appends `-I<path>` clang arguments for each include path so that
/// bindgen can locate the relevant C headers.
#[cfg(any(
    feature = "ffi-pam",
    feature = "ffi-radius",
    feature = "ffi-perl",
    feature = "ffi-gsasl",
    feature = "ffi-krb5",
    feature = "ffi-spf",
    feature = "hintsdb-bdb",
    feature = "hintsdb-gdbm",
    feature = "hintsdb-ndbm",
    feature = "hintsdb-tdb",
))]
fn add_include_paths(mut builder: bindgen::Builder, paths: &[PathBuf]) -> bindgen::Builder {
    for path in paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }
    builder
}

/// Probes for a system library via `pkg-config`.
///
/// On success the `pkg-config` crate automatically emits
/// `cargo:rustc-link-lib` and `cargo:rustc-link-search` directives.
/// The function returns `(include_paths, link_paths)` for the caller
/// to feed into `bindgen`.
///
/// On failure it falls back to emitting a bare link directive for
/// `fallback_lib` and returns empty path vectors.
///
/// Note: `ffi-perl` is excluded because Perl uses its own discovery
/// mechanism via `perl -MExtUtils::Embed` rather than pkg-config.
#[cfg(any(
    feature = "ffi-pam",
    feature = "ffi-radius",
    feature = "ffi-gsasl",
    feature = "ffi-krb5",
    feature = "ffi-spf",
    feature = "hintsdb-bdb",
    feature = "hintsdb-gdbm",
    feature = "hintsdb-ndbm",
    feature = "hintsdb-tdb",
))]
fn probe_library(pkg_name: &str, fallback_lib: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
    match pkg_config::Config::new().probe(pkg_name) {
        Ok(lib) => {
            // pkg-config already emitted cargo link directives.
            // Return include/link paths for bindgen and any extra usage.
            let include_paths = lib.include_paths;
            let link_paths = lib.link_paths;
            (include_paths, link_paths)
        }
        Err(_) => {
            // Manual fallback — emit the link directive ourselves.
            println!("cargo:rustc-link-lib={}", fallback_lib);
            (Vec::new(), Vec::new())
        }
    }
}

/// Parses a `#define NAME VALUE` directive from C header content.
///
/// Handles both `#define NAME VALUE` and `# define NAME VALUE` forms
/// with arbitrary whitespace/tabs between tokens.
#[cfg(any(feature = "ffi-gsasl", feature = "hintsdb-bdb"))]
fn parse_define_value(content: &str, name: &str) -> Option<u32> {
    for line in content.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Form 1: #define NAME VALUE
        if tokens.len() >= 3 && tokens[0] == "#define" && tokens[1] == name {
            return tokens[2].parse().ok();
        }
        // Form 2: # define NAME VALUE  (or #\tdefine …)
        if tokens.len() >= 4 && tokens[0] == "#" && tokens[1] == "define" && tokens[2] == name {
            return tokens[3].parse().ok();
        }
    }
    None
}

// =============================================================================
// PAM Binding Generator (ffi-pam)
// =============================================================================
// Source context: src/src/miscmods/pam.c — #include <security/pam_appl.h>
//   or <pam/pam_appl.h> on Solaris (lines 30-34).
// =============================================================================

#[cfg(feature = "ffi-pam")]
fn generate_pam_bindings(out_dir: &Path) {
    // Probe via pkg-config first; fall back to direct -lpam.
    let (include_paths, _link_paths) = probe_library("pam", "pam");

    // PAM header location is platform-dependent:
    //   Linux:   <security/pam_appl.h>
    //   Solaris: <pam/pam_appl.h>
    let wrapper_content = if PathBuf::from("/usr/include/security/pam_appl.h").exists() {
        "#include <security/pam_appl.h>\n"
    } else if PathBuf::from("/usr/include/pam/pam_appl.h").exists() {
        "#include <pam/pam_appl.h>\n"
    } else {
        // Let clang search its own include path
        "#include <security/pam_appl.h>\n"
    };

    let wrapper = out_dir.join("wrapper_pam.h");
    fs::write(&wrapper, wrapper_content).expect("Failed to write PAM wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("PAM wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Functions
        .allowlist_function("pam_start")
        .allowlist_function("pam_end")
        .allowlist_function("pam_authenticate")
        .allowlist_function("pam_acct_mgmt")
        .allowlist_function("pam_strerror")
        .allowlist_function("pam_set_item")
        .allowlist_function("pam_get_item")
        // Types
        .allowlist_type("pam_handle_t")
        .allowlist_type("pam_conv")
        .allowlist_type("pam_message")
        .allowlist_type("pam_response")
        // Constants
        .allowlist_var("PAM_SUCCESS")
        .allowlist_var("PAM_AUTH_ERR")
        .allowlist_var("PAM_CONV_ERR")
        .allowlist_var("PAM_PROMPT_ECHO_ON")
        .allowlist_var("PAM_PROMPT_ECHO_OFF")
        .allowlist_var("PAM_TEXT_INFO")
        .allowlist_var("PAM_ERROR_MSG")
        .allowlist_var("PAM_USER")
        .allowlist_var("PAM_SERVICE")
        .allowlist_var("PAM_SILENT")
        .allowlist_var("PAM_USER_UNKNOWN")
        .allowlist_var("PAM_ACCT_EXPIRED")
        .generate()
        .expect("Failed to generate PAM FFI bindings");

    bindings
        .write_to_file(out_dir.join("pam_bindings.rs"))
        .expect("Failed to write PAM bindings file");
}

// =============================================================================
// RADIUS Binding Generator (ffi-radius)
// =============================================================================
// Source context: src/src/miscmods/radius.c — three library variants:
//   radlib.h          (RADIUS_LIB_RADLIB — FreeBSD)
//   freeradius-client.h (RADIUS_LIB_RADIUSCLIENTNEW)
//   radiusclient.h    (RADIUS_LIB_RADIUSCLIENT — default)
// =============================================================================

#[cfg(feature = "ffi-radius")]
fn generate_radius_bindings(out_dir: &Path) {
    // Detect which RADIUS client library is installed.
    let freeradius_hdr = PathBuf::from("/usr/include/freeradius-client.h");
    let radiusclient_hdr = PathBuf::from("/usr/include/radiusclient.h");
    let radlib_hdr = PathBuf::from("/usr/include/radlib.h");

    let (header_content, pkg_name, fallback_lib, is_radlib) = if freeradius_hdr.exists() {
        (
            "#include <freeradius-client.h>\n",
            "freeradius-client",
            "freeradius-client",
            false,
        )
    } else if radiusclient_hdr.exists() {
        (
            "#include <radiusclient.h>\n",
            "radiusclient",
            "radiusclient",
            false,
        )
    } else if radlib_hdr.exists() {
        ("#include <radlib.h>\n", "radius", "rad", true)
    } else {
        panic!(
            "ffi-radius feature is enabled but no RADIUS client library \
                 header was found.  Install one of: \
                 libfreeradius-client-dev, libradiusclient-ng-dev, \
                 or libradius-dev (FreeBSD)."
        );
    };

    let (include_paths, _link_paths) = probe_library(pkg_name, fallback_lib);

    let wrapper = out_dir.join("wrapper_radius.h");
    fs::write(&wrapper, header_content).expect("Failed to write RADIUS wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let mut builder = create_builder(
        wrapper
            .to_str()
            .expect("RADIUS wrapper path not valid UTF-8"),
    );
    builder = add_include_paths(builder, &include_paths);

    if is_radlib {
        // FreeBSD radlib API
        println!("cargo:rustc-cfg=radius_lib_radlib");
        builder = builder
            .allowlist_function("rad_auth_open")
            .allowlist_function("rad_acct_open")
            .allowlist_function("rad_close")
            .allowlist_function("rad_config")
            .allowlist_function("rad_create_request")
            .allowlist_function("rad_put_string")
            .allowlist_function("rad_put_int")
            .allowlist_function("rad_send_request")
            .allowlist_function("rad_strerror")
            .allowlist_type("rad_handle");
    } else {
        // radiusclient / freeradius-client API
        println!("cargo:rustc-cfg=radius_lib_radiusclient");
        builder = builder
            .allowlist_function("rc_read_config")
            .allowlist_function("rc_read_dictionary")
            .allowlist_function("rc_avpair_add")
            .allowlist_function("rc_auth")
            .allowlist_function("rc_acct")
            .allowlist_function("rc_openlog")
            .allowlist_function("rc_conf_str")
            .allowlist_type("rc_handle")
            .allowlist_type("VALUE_PAIR")
            .allowlist_var("PW_USER_NAME")
            .allowlist_var("PW_USER_PASSWORD")
            .allowlist_var("PW_SERVICE_TYPE")
            .allowlist_var("PW_AUTHENTICATE_ONLY");
    }

    let bindings = builder
        .generate()
        .expect("Failed to generate RADIUS FFI bindings");

    bindings
        .write_to_file(out_dir.join("radius_bindings.rs"))
        .expect("Failed to write RADIUS bindings file");
}

// =============================================================================
// Perl Binding Generator (ffi-perl)
// =============================================================================
// Source context: src/src/miscmods/perl.c lines 34-36:
//   #include <EXTERN.h>
//   #include <perl.h>
//   #include <XSUB.h>
//
// Perl headers are extremely complex — many "functions" (SvPV, ERRSV, etc.)
// are in fact deeply nested macros.  We compile a small C wrapper via the
// `cc` crate that expands these macros into real functions, then generate
// bindings for both the real Perl API and our wrappers.
// =============================================================================

#[cfg(feature = "ffi-perl")]
fn generate_perl_bindings(out_dir: &Path) {
    // Allow overriding the Perl binary via environment variable.
    let perl_bin = env::var_os("EXIM_PERL_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("perl"));

    // ── Step 1: Discover Perl CORE include directory ─────────────────────
    let archlib_output = std::process::Command::new(&perl_bin)
        .arg("-MConfig")
        .arg("-e")
        .arg("print $Config{archlib}")
        .output()
        .expect("Failed to execute `perl -MConfig -e 'print $Config{archlib}'`");

    if !archlib_output.status.success() {
        panic!(
            "ffi-perl feature is enabled but `perl -MConfig` failed.  \
             Is Perl installed?  stderr: {}",
            String::from_utf8_lossy(&archlib_output.stderr)
        );
    }
    let archlib =
        String::from_utf8(archlib_output.stdout).expect("Non-UTF-8 output from perl archlib");
    let perl_core_dir = PathBuf::from(archlib.trim()).join("CORE");

    // ── Step 2: Obtain compile and link flags ────────────────────────────
    let ccopts_output = std::process::Command::new(&perl_bin)
        .arg("-MExtUtils::Embed")
        .arg("-e")
        .arg("ccopts")
        .output()
        .expect("Failed to execute `perl -MExtUtils::Embed -e ccopts`");
    let ccopts = String::from_utf8(ccopts_output.stdout)
        .expect("Non-UTF-8 output from perl ccopts")
        .trim()
        .to_string();

    let ldopts_output = std::process::Command::new(&perl_bin)
        .arg("-MExtUtils::Embed")
        .arg("-e")
        .arg("ldopts")
        .output()
        .expect("Failed to execute `perl -MExtUtils::Embed -e ldopts`");
    let ldopts = String::from_utf8(ldopts_output.stdout)
        .expect("Non-UTF-8 output from perl ldopts")
        .trim()
        .to_string();

    // ── Step 3: Emit cargo link directives from ldopts ───────────────────
    for token in ldopts.split_whitespace() {
        if let Some(lib) = token.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={}", lib);
        } else if let Some(path) = token.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={}", path);
        }
    }

    // ── Step 4: Write C wrapper for Perl macros ──────────────────────────
    // SvPV, SvPV_nolen, newSVpv, newSViv, ERRSV are macros that cannot be
    // handled by bindgen directly.  We expand them in a thin C shim that
    // exposes real callable symbols.
    let perl_wrapper_c = out_dir.join("perl_wrapper.c");
    let perl_wrapper_c_src = "\
/* Auto-generated Perl macro wrappers for exim-ffi */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

/* Wrapper for SvPV macro — extracts string value with length */
const char* exim_ffi_SvPV(pTHX_ SV* sv, STRLEN* len) {
    return SvPV(sv, *len);
}

/* Wrapper for SvPV_nolen — extracts string without length output */
const char* exim_ffi_SvPV_nolen(pTHX_ SV* sv) {
    return SvPV_nolen(sv);
}

/* Wrapper for newSVpv — creates a new SV from a C string */
SV* exim_ffi_newSVpv(pTHX_ const char* s, STRLEN len) {
    return newSVpv(s, len);
}

/* Wrapper for newSViv — creates a new SV from an integer */
SV* exim_ffi_newSViv(pTHX_ IV iv) {
    return newSViv(iv);
}

/* Wrapper for ERRSV — returns the Perl $@ error SV */
SV* exim_ffi_ERRSV(pTHX) {
    return ERRSV;
}
";
    fs::write(&perl_wrapper_c, perl_wrapper_c_src).expect("Failed to write Perl wrapper C source");

    // ── Step 5: Compile the C wrapper via cc::Build ──────────────────────
    let mut cc_build = cc::Build::new();
    cc_build.file(
        perl_wrapper_c
            .to_str()
            .expect("Perl wrapper C path not valid UTF-8"),
    );
    cc_build.include(
        perl_core_dir
            .to_str()
            .expect("Perl CORE dir path not valid UTF-8"),
    );

    // Forward relevant compile flags from perl ccopts
    for flag in ccopts.split_whitespace() {
        if flag.starts_with("-D") || flag.starts_with("-f") || flag.starts_with("-I") {
            cc_build.flag(flag);
        }
    }
    cc_build.compile("perl_wrapper");

    // ── Step 6: Create wrapper header for bindgen ────────────────────────
    let perl_wrapper_h = out_dir.join("wrapper_perl.h");
    let wrapper_h_content = "\
/* Auto-generated Perl wrapper header for bindgen */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

/* Macro wrappers declared as real C functions */
const char* exim_ffi_SvPV(pTHX_ SV* sv, STRLEN* len);
const char* exim_ffi_SvPV_nolen(pTHX_ SV* sv);
SV* exim_ffi_newSVpv(pTHX_ const char* s, STRLEN len);
SV* exim_ffi_newSViv(pTHX_ IV iv);
SV* exim_ffi_ERRSV(pTHX);
";
    fs::write(&perl_wrapper_h, wrapper_h_content).expect("Failed to write Perl wrapper header");
    println!("cargo:rerun-if-changed={}", perl_wrapper_h.display());

    // ── Step 7: Generate bindings ────────────────────────────────────────
    let mut builder = create_builder(
        perl_wrapper_h
            .to_str()
            .expect("Perl wrapper header path not valid UTF-8"),
    );

    // Collect all include directories: Perl CORE dir + any -I from ccopts
    let mut perl_includes: Vec<PathBuf> = vec![perl_core_dir];
    for flag in ccopts.split_whitespace() {
        if let Some(path) = flag.strip_prefix("-I") {
            perl_includes.push(PathBuf::from(path));
        }
    }
    builder = add_include_paths(builder, &perl_includes);

    // Forward -D preprocessor definitions so clang can parse perl.h
    for flag in ccopts.split_whitespace() {
        if flag.starts_with("-D") {
            builder = builder.clang_arg(flag.to_string());
        }
    }

    let bindings = builder
        // Core Perl embedding functions
        .allowlist_function("perl_alloc")
        .allowlist_function("perl_construct")
        .allowlist_function("perl_destruct")
        .allowlist_function("perl_free")
        .allowlist_function("perl_parse")
        .allowlist_function("perl_run")
        .allowlist_function("Perl_call_pv")
        .allowlist_function("Perl_eval_pv")
        .allowlist_function("Perl_newXS")
        .allowlist_function("boot_DynaLoader")
        // Our macro-wrapper functions
        .allowlist_function("exim_ffi_.*")
        // Essential types
        .allowlist_type("PerlInterpreter")
        .allowlist_type("SV")
        .allowlist_type("CV")
        .allowlist_type("STRLEN")
        .allowlist_type("IV")
        // Calling convention constants
        .allowlist_var("G_SCALAR")
        .allowlist_var("G_ARRAY")
        .allowlist_var("G_DISCARD")
        .allowlist_var("G_EVAL")
        .allowlist_var("G_NOARGS")
        .generate()
        .expect("Failed to generate Perl FFI bindings");

    bindings
        .write_to_file(out_dir.join("perl_bindings.rs"))
        .expect("Failed to write Perl bindings file");
}

// =============================================================================
// GSASL Binding Generator (ffi-gsasl)
// =============================================================================
// Source context: src/src/auths/gsasl.c line 39: #include <gsasl.h>
// Version gating: lines 43-71 branch on GSASL 2.x vs 1.x
// =============================================================================

#[cfg(feature = "ffi-gsasl")]
fn generate_gsasl_bindings(out_dir: &Path) {
    let (include_paths, _link_paths) = probe_library("libgsasl", "gsasl");

    // Emit cargo:rustc-check-cfg directives so the compiler knows about
    // our custom cfg attributes (required for -D warnings / check-cfg lint).
    println!("cargo::rustc-check-cfg=cfg(gsasl_have_scram_sha_256)");
    println!("cargo::rustc-check-cfg=cfg(gsasl_scram_s_key)");
    println!("cargo::rustc-check-cfg=cfg(gsasl_have_exporter)");
    println!("cargo::rustc-check-cfg=cfg(gsasl_channelbind_hack)");

    // Detect GSASL version and emit cfg attributes for version-dependent
    // features (matching the C preprocessor gating in gsasl.c lines 43-71).
    detect_gsasl_version();

    let wrapper = out_dir.join("wrapper_gsasl.h");
    fs::write(&wrapper, "#include <gsasl.h>\n").expect("Failed to write GSASL wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(
        wrapper
            .to_str()
            .expect("GSASL wrapper path not valid UTF-8"),
    );
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Session lifecycle
        .allowlist_function("gsasl_init")
        .allowlist_function("gsasl_done")
        // Mechanism operations
        .allowlist_function("gsasl_client_start")
        .allowlist_function("gsasl_server_start")
        .allowlist_function("gsasl_step")
        .allowlist_function("gsasl_finish")
        // Properties
        .allowlist_function("gsasl_property_set")
        .allowlist_function("gsasl_property_get")
        // Utility
        .allowlist_function("gsasl_strerror")
        .allowlist_function("gsasl_check_version")
        .allowlist_function("gsasl_callback_set")
        .allowlist_function("gsasl_callback")
        // Hook functions (for callback data passing)
        .allowlist_function("gsasl_callback_hook_set")
        .allowlist_function("gsasl_callback_hook_get")
        .allowlist_function("gsasl_session_hook_set")
        .allowlist_function("gsasl_session_hook_get")
        // Memory management
        .allowlist_function("gsasl_free")
        // Types
        .allowlist_type("Gsasl")
        .allowlist_type("Gsasl_session")
        .allowlist_type("Gsasl_property")
        .allowlist_type("Gsasl_rc")
        // Status constants
        .allowlist_var("GSASL_OK")
        .allowlist_var("GSASL_NEEDS_MORE")
        .allowlist_var("GSASL_AUTHENTICATION_ERROR")
        .allowlist_var("GSASL_NO_CALLBACK")
        .allowlist_var("GSASL_UNKNOWN_MECHANISM")
        .allowlist_var("GSASL_MALLOC_ERROR")
        // Version constants (for runtime checks)
        .allowlist_var("GSASL_VERSION_MAJOR")
        .allowlist_var("GSASL_VERSION_MINOR")
        .allowlist_var("GSASL_VERSION_PATCH")
        .allowlist_var("GSASL_VERSION_NUMBER")
        .generate()
        .expect("Failed to generate GSASL FFI bindings");

    bindings
        .write_to_file(out_dir.join("gsasl_bindings.rs"))
        .expect("Failed to write GSASL bindings file");
}

/// Detects the installed GSASL version by parsing `gsasl-version.h` and
/// emits `cargo:rustc-cfg` attributes that mirror the C preprocessor
/// feature gating in `src/src/auths/gsasl.c` lines 43-71.
///
/// Emitted cfgs:
///   gsasl_have_scram_sha_256 — SCRAM-SHA-256 support
///   gsasl_scram_s_key        — SCRAM server key support
///   gsasl_have_exporter      — SASL EXPORTER extension
///   gsasl_channelbind_hack   — channel-binding workaround needed
#[cfg(feature = "ffi-gsasl")]
fn detect_gsasl_version() {
    // Try standard location first, then fall back to /usr/include
    let version_header_candidates = [
        "/usr/include/gsasl-version.h",
        "/usr/local/include/gsasl-version.h",
    ];

    let content = version_header_candidates
        .iter()
        .find_map(|path| fs::read_to_string(path).ok());

    let content = match content {
        Some(c) => c,
        None => {
            eprintln!(
                "cargo:warning=Could not find gsasl-version.h; \
                 GSASL version-dependent cfg attributes will not be emitted."
            );
            return;
        }
    };

    let major = parse_define_value(&content, "GSASL_VERSION_MAJOR").unwrap_or(0);
    let minor = parse_define_value(&content, "GSASL_VERSION_MINOR").unwrap_or(0);
    let patch = parse_define_value(&content, "GSASL_VERSION_PATCH").unwrap_or(0);

    eprintln!("Detected GSASL version: {}.{}.{}", major, minor, patch);

    // Mirror the C preprocessor logic from gsasl.c:
    if major >= 2 {
        println!("cargo:rustc-cfg=gsasl_have_scram_sha_256");
        println!("cargo:rustc-cfg=gsasl_scram_s_key");
        if minor >= 1 || patch >= 1 {
            println!("cargo:rustc-cfg=gsasl_have_exporter");
        }
    } else if major == 1 {
        if minor >= 10 {
            println!("cargo:rustc-cfg=gsasl_have_scram_sha_256");
            println!("cargo:rustc-cfg=gsasl_scram_s_key");
        } else if minor == 9 {
            println!("cargo:rustc-cfg=gsasl_have_scram_sha_256");
            if patch >= 1 {
                println!("cargo:rustc-cfg=gsasl_scram_s_key");
            }
            if patch < 2 {
                println!("cargo:rustc-cfg=gsasl_channelbind_hack");
            }
        } else {
            println!("cargo:rustc-cfg=gsasl_channelbind_hack");
        }
    }
}

// =============================================================================
// Kerberos / GSSAPI Binding Generator (ffi-krb5)
// =============================================================================
// Source context: src/src/auths/heimdal_gssapi.c lines 53-57:
//   #include <gssapi/gssapi.h>
//   #include <gssapi/gssapi_krb5.h>
//   #include <krb5.h>
// =============================================================================

#[cfg(feature = "ffi-krb5")]
fn generate_krb5_bindings(out_dir: &Path) {
    // Probe MIT Kerberos GSS-API and KRB5 via pkg-config.
    let (gss_includes, _gss_links) = probe_library("krb5-gssapi", "gssapi_krb5");

    // pkg-config for krb5 may re-emit link directives — that is harmless.
    let (krb_includes, _krb_links) = probe_library("krb5", "krb5");

    // Merge include paths, de-duplicating
    let mut all_includes = gss_includes;
    for path in krb_includes {
        if !all_includes.contains(&path) {
            all_includes.push(path);
        }
    }

    let wrapper = out_dir.join("wrapper_krb5.h");
    let wrapper_content = "\
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
";
    fs::write(&wrapper, wrapper_content).expect("Failed to write KRB5 wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("KRB5 wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &all_includes);

    let bindings = builder
        // GSSAPI context functions
        .allowlist_function("gss_accept_sec_context")
        .allowlist_function("gss_init_sec_context")
        .allowlist_function("gss_delete_sec_context")
        .allowlist_function("gss_inquire_context")
        // GSSAPI name functions
        .allowlist_function("gss_import_name")
        .allowlist_function("gss_display_name")
        .allowlist_function("gss_release_name")
        // GSSAPI buffer/cred functions
        .allowlist_function("gss_release_buffer")
        .allowlist_function("gss_release_cred")
        // Heimdal-specific
        .allowlist_function("gsskrb5_register_acceptor_identity")
        // KRB5 context
        .allowlist_function("krb5_init_context")
        .allowlist_function("krb5_free_context")
        // GSSAPI types
        .allowlist_type("gss_ctx_id_t")
        .allowlist_type("gss_ctx_id_desc.*")
        .allowlist_type("gss_name_t")
        .allowlist_type("gss_cred_id_t")
        .allowlist_type("gss_buffer_desc")
        .allowlist_type("gss_OID_desc.*")
        .allowlist_type("OM_uint32")
        // KRB5 types
        .allowlist_type("krb5_context")
        // GSSAPI constants (GSS_C_*, GSS_S_*)
        .allowlist_var("GSS_C_.*")
        .allowlist_var("GSS_S_.*")
        .generate()
        .expect("Failed to generate KRB5/GSSAPI FFI bindings");

    bindings
        .write_to_file(out_dir.join("krb5_bindings.rs"))
        .expect("Failed to write KRB5 bindings file");
}

// =============================================================================
// SPF Binding Generator (ffi-spf)
// =============================================================================
// Source context: src/src/miscmods/spf.h lines 21-24:
//   #include <spf2/spf.h>
//   #include <spf2/spf_dns_resolv.h>
//   #include <spf2/spf_dns_cache.h>
// =============================================================================

#[cfg(feature = "ffi-spf")]
fn generate_spf_bindings(out_dir: &Path) {
    let (include_paths, _link_paths) = probe_library("libspf2", "spf2");

    // The SPF headers require system types (size_t, in_addr, in6_addr)
    // and redefine ns_type unless HAVE_NS_TYPE is set.
    // (See src/src/miscmods/spf.h lines 19-21.)
    let wrapper = out_dir.join("wrapper_spf.h");
    let wrapper_content = "\
#include <sys/types.h>
#include <netinet/in.h>
#ifndef HAVE_NS_TYPE
#define HAVE_NS_TYPE
#endif
#include <spf2/spf.h>
#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_dns_cache.h>
";
    fs::write(&wrapper, wrapper_content).expect("Failed to write SPF wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("SPF wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Server lifecycle
        .allowlist_function("SPF_server_new")
        .allowlist_function("SPF_server_free")
        // Request lifecycle
        .allowlist_function("SPF_request_new")
        .allowlist_function("SPF_request_free")
        .allowlist_function("SPF_request_set_ipv4_str")
        .allowlist_function("SPF_request_set_ipv6_str")
        .allowlist_function("SPF_request_set_helo_dom")
        .allowlist_function("SPF_request_set_env_from")
        // Query operations
        .allowlist_function("SPF_request_query_mailfrom")
        .allowlist_function("SPF_request_query_rcptto")
        // Response lifecycle and accessors
        .allowlist_function("SPF_response_result")
        .allowlist_function("SPF_response_reason")
        .allowlist_function("SPF_response_free")
        .allowlist_function("SPF_strresult")
        .allowlist_function("SPF_strreason")
        // Library version
        .allowlist_function("SPF_get_lib_version")
        // DNS resolver functions
        .allowlist_function("SPF_dns_.*")
        // Types
        .allowlist_type("SPF_server_t")
        .allowlist_type("SPF_request_t")
        .allowlist_type("SPF_response_t")
        .allowlist_type("SPF_dns_rr_t")
        .allowlist_type("SPF_dns_server_t")
        .allowlist_type("SPF_result_t")
        .allowlist_type("SPF_reason_t")
        // Constants (SPF_RESULT_*, SPF_REASON_*, etc.)
        .allowlist_var("SPF_.*")
        .generate()
        .expect("Failed to generate SPF2 FFI bindings");

    bindings
        .write_to_file(out_dir.join("spf_bindings.rs"))
        .expect("Failed to write SPF bindings file");
}

// =============================================================================
// libopendmarc Binding Generator (ffi-dmarc)
// =============================================================================
// Source context: src/src/miscmods/dmarc.c — DMARC policy evaluation via
//   libopendmarc. The library does not ship a pkg-config file so we link
//   directly via -lopendmarc and use the system header <opendmarc/dmarc.h>.
//
// The OPENDMARC_LIB_T struct contains platform-dependent fields (MAXPATHLEN,
// MAXNS, struct sockaddr_in) so bindgen is required for correct layout.
// =============================================================================

#[cfg(feature = "ffi-dmarc")]
fn generate_dmarc_bindings(out_dir: &Path) {
    // libopendmarc has no pkg-config — emit the link directive manually.
    println!("cargo:rustc-link-lib=opendmarc");

    // The opendmarc header includes <sys/param.h>, <sys/socket.h>,
    // <netinet/in.h>, and <resolv.h>, so we create a thin wrapper that
    // ensures all prerequisite system headers are present.
    let wrapper = out_dir.join("wrapper_dmarc.h");
    let wrapper_content = "\
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <opendmarc/dmarc.h>
";
    fs::write(&wrapper, wrapper_content).expect("Failed to write DMARC wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(
        wrapper
            .to_str()
            .expect("DMARC wrapper path not valid UTF-8"),
    );

    let bindings = builder
        // Library lifecycle
        .allowlist_function("opendmarc_policy_library_init")
        .allowlist_function("opendmarc_policy_library_shutdown")
        // Connection / policy context lifecycle
        .allowlist_function("opendmarc_policy_connect_init")
        .allowlist_function("opendmarc_policy_connect_clear")
        .allowlist_function("opendmarc_policy_connect_rset")
        .allowlist_function("opendmarc_policy_connect_shutdown")
        // Store information
        .allowlist_function("opendmarc_policy_store_from_domain")
        .allowlist_function("opendmarc_policy_store_dkim")
        .allowlist_function("opendmarc_policy_store_spf")
        .allowlist_function("opendmarc_policy_store_dmarc")
        .allowlist_function("opendmarc_policy_query_dmarc")
        .allowlist_function("opendmarc_policy_parse_dmarc")
        // Policy evaluation
        .allowlist_function("opendmarc_get_policy_to_enforce")
        .allowlist_function("opendmarc_get_policy_token_used")
        // Fetch DMARC record attributes
        .allowlist_function("opendmarc_policy_fetch_alignment")
        .allowlist_function("opendmarc_policy_fetch_pct")
        .allowlist_function("opendmarc_policy_fetch_adkim")
        .allowlist_function("opendmarc_policy_fetch_aspf")
        .allowlist_function("opendmarc_policy_fetch_p")
        .allowlist_function("opendmarc_policy_fetch_sp")
        .allowlist_function("opendmarc_policy_fetch_rua")
        .allowlist_function("opendmarc_policy_fetch_ruf")
        .allowlist_function("opendmarc_policy_fetch_utilized_domain")
        .allowlist_function("opendmarc_policy_fetch_from_domain")
        // Utility
        .allowlist_function("opendmarc_policy_status_to_str")
        .allowlist_function("opendmarc_policy_check_alignment")
        .allowlist_function("opendmarc_policy_to_buf")
        // TLD file loading
        .allowlist_function("opendmarc_tld_read_file")
        .allowlist_function("opendmarc_tld_shutdown")
        // Types
        .allowlist_type("OPENDMARC_LIB_T")
        .allowlist_type("DMARC_POLICY_T")
        .allowlist_type("OPENDMARC_STATUS_T")
        // Constants — allow all DMARC_*, OPENDMARC_*, ARES_* defines
        .allowlist_var("DMARC_.*")
        .allowlist_var("OPENDMARC_.*")
        .allowlist_var("ARES_.*")
        .generate()
        .expect("Failed to generate libopendmarc FFI bindings");

    bindings
        .write_to_file(out_dir.join("dmarc_bindings.rs"))
        .expect("Failed to write DMARC bindings file");
}

// =============================================================================
// Berkeley DB Binding Generator (hintsdb-bdb)
// =============================================================================
// Source context: src/src/hintsdb/hints_bdb.h
//   - Rejects BDB >= 6  (#error Version 6 and later BDB API is not supported)
//   - API change at BDB 4.1 (DB_ENV as EXIM_DB vs DB)
//   - Error callback API change at BDB 4.3
// =============================================================================

#[cfg(feature = "hintsdb-bdb")]
fn generate_bdb_bindings(out_dir: &Path) {
    let (include_paths, _link_paths) = probe_library("db", "db");

    // ── Version detection ────────────────────────────────────────────────
    // Read db.h to extract DB_VERSION_MAJOR / DB_VERSION_MINOR.
    // This mirrors the C-side version gating in hints_bdb.h.
    let db_header_path = "/usr/include/db.h";
    let db_content = fs::read_to_string(db_header_path).unwrap_or_else(|_| {
        // Try include paths obtained from pkg-config
        for ipath in &include_paths {
            let candidate = ipath.join("db.h");
            if let Ok(c) = fs::read_to_string(&candidate) {
                return c;
            }
        }
        panic!(
            "hintsdb-bdb feature is enabled but db.h could not be found.  \
             Install libdb-dev or equivalent."
        );
    });

    let major = parse_define_value(&db_content, "DB_VERSION_MAJOR")
        .expect("Cannot parse DB_VERSION_MAJOR from db.h");
    let minor = parse_define_value(&db_content, "DB_VERSION_MINOR")
        .expect("Cannot parse DB_VERSION_MINOR from db.h");

    eprintln!("Detected Berkeley DB version: {}.{}", major, minor);

    // Reject BDB >= 6 (matching hints_bdb.h)
    if major >= 6 {
        panic!(
            "Berkeley DB version {}.{} is not supported \
             (version 6+ rejected per hints_bdb.h).  \
             Please install BDB 3.x–5.x.",
            major, minor
        );
    }

    // Emit cfg attributes for version-dependent API branching
    if major >= 3 {
        println!("cargo:rustc-cfg=bdb_3_plus");
    }
    if major > 4 || (major == 4 && minor >= 1) {
        // BDB 4.1+ uses DB_ENV as EXIM_DB
        println!("cargo:rustc-cfg=bdb_41_plus");
    }
    if major > 4 || (major == 4 && minor >= 3) {
        // Error callback API changed at 4.3
        println!("cargo:rustc-cfg=bdb_43_plus");
    }

    // ── Generate bindings ────────────────────────────────────────────────
    let wrapper = out_dir.join("wrapper_bdb.h");
    fs::write(&wrapper, "#include <db.h>\n").expect("Failed to write BDB wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("BDB wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Creation functions
        .allowlist_function("db_create")
        .allowlist_function("db_env_create")
        .allowlist_function("db_version")
        // Types
        .allowlist_type("DB")
        .allowlist_type("DB_ENV")
        .allowlist_type("DBC")
        .allowlist_type("DBT")
        .allowlist_type("DB_LOCK")
        .allowlist_type("DB_TXN")
        // Flag constants
        .allowlist_var("DB_CREATE")
        .allowlist_var("DB_RDONLY")
        .allowlist_var("DB_TRUNCATE")
        .allowlist_var("DB_BTREE")
        .allowlist_var("DB_HASH")
        .allowlist_var("DB_INIT_.*")
        .allowlist_var("DB_NOTFOUND")
        .allowlist_var("DB_KEYEXIST")
        .allowlist_var("DB_FORCESYNC")
        // Version constants (for runtime checks)
        .allowlist_var("DB_VERSION_MAJOR")
        .allowlist_var("DB_VERSION_MINOR")
        .allowlist_var("DB_VERSION_PATCH")
        .allowlist_var("DB_VERSION_STRING")
        .generate()
        .expect("Failed to generate BDB FFI bindings");

    bindings
        .write_to_file(out_dir.join("bdb_bindings.rs"))
        .expect("Failed to write BDB bindings file");
}

// =============================================================================
// GDBM Binding Generator (hintsdb-gdbm)
// =============================================================================
// Source context: src/src/hintsdb/hints_gdbm.h — #include <gdbm.h>
// =============================================================================

#[cfg(feature = "hintsdb-gdbm")]
fn generate_gdbm_bindings(out_dir: &Path) {
    let (include_paths, _link_paths) = probe_library("gdbm", "gdbm");

    let wrapper = out_dir.join("wrapper_gdbm.h");
    fs::write(&wrapper, "#include <gdbm.h>\n").expect("Failed to write GDBM wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("GDBM wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Functions
        .allowlist_function("gdbm_open")
        .allowlist_function("gdbm_close")
        .allowlist_function("gdbm_fetch")
        .allowlist_function("gdbm_store")
        .allowlist_function("gdbm_delete")
        .allowlist_function("gdbm_firstkey")
        .allowlist_function("gdbm_nextkey")
        .allowlist_function("gdbm_strerror")
        // Types
        .allowlist_type("GDBM_FILE")
        .allowlist_type("datum")
        // Open-mode constants
        .allowlist_var("GDBM_READER")
        .allowlist_var("GDBM_WRITER")
        .allowlist_var("GDBM_WRCREAT")
        .allowlist_var("GDBM_NEWDB")
        // Store-mode constants
        .allowlist_var("GDBM_INSERT")
        .allowlist_var("GDBM_REPLACE")
        .generate()
        .expect("Failed to generate GDBM FFI bindings");

    bindings
        .write_to_file(out_dir.join("gdbm_bindings.rs"))
        .expect("Failed to write GDBM bindings file");
}

// =============================================================================
// NDBM Binding Generator (hintsdb-ndbm)
// =============================================================================
// Source context: src/src/hintsdb/hints_ndbm.h — #include <ndbm.h>
// On some systems ndbm.h is provided by the gdbm-compat package.
// =============================================================================

#[cfg(feature = "hintsdb-ndbm")]
fn generate_ndbm_bindings(out_dir: &Path) {
    // NDBM header location varies by platform:
    //   Standard:    /usr/include/ndbm.h    (may be provided by libndbm-dev OR libgdbm-compat-dev)
    //   GDBM compat: /usr/include/gdbm-ndbm.h  (always link against gdbm_compat)
    //
    // On most modern Linux distributions, /usr/include/ndbm.h is actually provided by
    // libgdbm-compat-dev (it includes <gdbm.h> internally) and the NDBM functions live
    // in libgdbm_compat.so, NOT libndbm.so. We detect this by checking whether the
    // gdbm-compat header also exists alongside the standard ndbm.h.
    let ndbm_standard = PathBuf::from("/usr/include/ndbm.h");
    let ndbm_gdbm_compat = PathBuf::from("/usr/include/gdbm-ndbm.h");
    let libndbm_so = PathBuf::from("/usr/lib/x86_64-linux-gnu/libndbm.so");

    let (header_include, fallback_lib) = if ndbm_standard.exists() && libndbm_so.exists() {
        // A real standalone libndbm is present — use it directly.
        ("#include <ndbm.h>\n", "ndbm")
    } else if ndbm_standard.exists() && ndbm_gdbm_compat.exists() {
        // ndbm.h is provided by gdbm-compat — link against gdbm_compat + gdbm.
        ("#include <ndbm.h>\n", "gdbm_compat")
    } else if ndbm_standard.exists() {
        // ndbm.h exists but origin unclear — try gdbm_compat first (most common).
        ("#include <ndbm.h>\n", "gdbm_compat")
    } else if ndbm_gdbm_compat.exists() {
        ("#include <gdbm-ndbm.h>\n", "gdbm_compat")
    } else {
        panic!(
            "hintsdb-ndbm feature is enabled but ndbm.h could not be \
             found.  Install libndbm-dev, libgdbm-compat-dev, or \
             equivalent."
        );
    };

    // Use probe_library for consistent pkg-config detection; falls back
    // to manual link directive when pkg-config has no ndbm entry.
    let (include_paths, _link_paths) = probe_library("ndbm", fallback_lib);

    let wrapper = out_dir.join("wrapper_ndbm.h");
    fs::write(&wrapper, header_include).expect("Failed to write NDBM wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("NDBM wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Functions
        .allowlist_function("dbm_open")
        .allowlist_function("dbm_close")
        .allowlist_function("dbm_fetch")
        .allowlist_function("dbm_store")
        .allowlist_function("dbm_delete")
        .allowlist_function("dbm_firstkey")
        .allowlist_function("dbm_nextkey")
        .allowlist_function("dbm_error")
        .allowlist_function("dbm_clearerr")
        // Types
        .allowlist_type("DBM")
        .allowlist_type("datum")
        // Store-mode constants
        .allowlist_var("DBM_INSERT")
        .allowlist_var("DBM_REPLACE")
        .generate()
        .expect("Failed to generate NDBM FFI bindings");

    bindings
        .write_to_file(out_dir.join("ndbm_bindings.rs"))
        .expect("Failed to write NDBM bindings file");
}

// =============================================================================
// TDB Binding Generator (hintsdb-tdb)
// =============================================================================
// Source context: src/src/hintsdb/hints_tdb.h — #include <tdb.h>
// TDB supports transactions (unlike GDBM/NDBM).
// =============================================================================

#[cfg(feature = "hintsdb-tdb")]
fn generate_tdb_bindings(out_dir: &Path) {
    let (include_paths, _link_paths) = probe_library("tdb", "tdb");

    let wrapper = out_dir.join("wrapper_tdb.h");
    // tdb.h requires sys/types.h for mode_t
    fs::write(&wrapper, "#include <sys/types.h>\n#include <tdb.h>\n")
        .expect("Failed to write TDB wrapper header");
    println!("cargo:rerun-if-changed={}", wrapper.display());

    let builder = create_builder(wrapper.to_str().expect("TDB wrapper path not valid UTF-8"));
    let builder = add_include_paths(builder, &include_paths);

    let bindings = builder
        // Lifecycle
        .allowlist_function("tdb_open")
        .allowlist_function("tdb_close")
        // CRUD operations
        .allowlist_function("tdb_fetch")
        .allowlist_function("tdb_store")
        .allowlist_function("tdb_delete")
        // Iteration
        .allowlist_function("tdb_firstkey")
        .allowlist_function("tdb_nextkey")
        // Transactions (TDB-specific — not available in GDBM/NDBM)
        .allowlist_function("tdb_transaction_start")
        .allowlist_function("tdb_transaction_commit")
        .allowlist_function("tdb_transaction_cancel")
        // Error handling
        .allowlist_function("tdb_errorstr")
        .allowlist_function("tdb_error")
        // Types
        .allowlist_type("TDB_CONTEXT")
        .allowlist_type("TDB_DATA")
        // Flag constants
        .allowlist_var("TDB_DEFAULT")
        .allowlist_var("TDB_CLEAR_IF_FIRST")
        .allowlist_var("TDB_NOLOCK")
        .allowlist_var("TDB_INSERT")
        .allowlist_var("TDB_REPLACE")
        .allowlist_var("TDB_MODIFY")
        .generate()
        .expect("Failed to generate TDB FFI bindings");

    bindings
        .write_to_file(out_dir.join("tdb_bindings.rs"))
        .expect("Failed to write TDB bindings file");
}

// =============================================================================
// WHOSON (ffi-whoson) — libwhoson link directives
// =============================================================================
//
// libwhoson has a minimal API (only 2 functions: wso_query, wso_version) so
// hand-written extern "C" declarations in whoson.rs are used instead of
// bindgen. This function only needs to emit the linker directive.
//
// When running tests without libwhoson installed, a tiny C mock is compiled
// to satisfy the linker so that the safe-wrapper unit tests can execute.

#[cfg(feature = "ffi-whoson")]
fn generate_whoson_link(out_dir: &Path) {
    // For test builds, compile a mock C implementation so unit tests can
    // exercise the safe Rust wrappers without requiring libwhoson installed.
    // In release/non-test builds, link against the real system library.
    let mock_c = out_dir.join("whoson_mock.c");
    fs::write(
        &mock_c,
        r#"
/* Mock libwhoson for unit tests — NOT linked in production builds */
#include <stddef.h>
#include <string.h>

int wso_query(const char *query, char *buffer, size_t bufsize) {
    /* Return "not found" for all mock queries */
    if (buffer && bufsize > 0) buffer[0] = '\0';
    return 1;
}

const char *wso_version(void) {
    return "mock-0.0.0";
}
"#,
    )
    .expect("Failed to write WHOSON mock C file");

    // Always compile the mock into a static library so the tests link.
    // When the real libwhoson is installed and preferred, the user can
    // set WHOSON_NO_MOCK=1 to skip the mock and link against the system lib.
    let use_mock = std::env::var("WHOSON_NO_MOCK").is_err();

    if use_mock {
        cc::Build::new()
            .file(&mock_c)
            .warnings(false)
            .compile("whoson");
        // cc::Build automatically emits cargo:rustc-link-lib=static=whoson
        // and cargo:rustc-link-search=native=<out_dir>
    } else {
        // Link against the real system libwhoson.
        println!("cargo:rustc-link-lib=whoson");
    }
}

// =============================================================================
// NIS/YP (ffi-nis) — libnsl link directives
// =============================================================================
//
// NIS/YP has a minimal lookup API (only 2 functions: yp_get_default_domain,
// yp_match) so hand-written extern "C" declarations in nis.rs are used
// instead of bindgen.
//
// When running tests without a NIS server configured, a tiny C mock is
// compiled to satisfy the linker and provide deterministic test results.

#[cfg(feature = "ffi-nis")]
fn generate_nis_link(out_dir: &Path) {
    // Compile a mock C library that stubs the NIS/YP functions so unit tests
    // exercise the safe Rust wrappers without requiring NIS to be configured.
    let mock_c = out_dir.join("nis_mock.c");
    fs::write(
        &mock_c,
        r#"
/* Mock libnsl NIS/YP functions for unit tests — NOT linked in production builds.
 * Provides deterministic return values so Rust unit tests can verify error
 * handling and data conversion without a running NIS server.
 */
#include <stddef.h>
#include <string.h>

/* Static domain string returned by the mock — mimics the real libnsl
 * behavior of returning a pointer to a static buffer. */
static char mock_domain[] = "mock.localdomain";

int yp_get_default_domain(char **outdomain) {
    if (outdomain) *outdomain = mock_domain;
    return 0;  /* YPERR_SUCCESS */
}

int yp_match(const char *indomain, const char *inmap,
             const char *inkey, int inkeylen,
             char **outval, int *outvallen) {
    (void)indomain; (void)inmap; (void)inkey; (void)inkeylen;
    (void)outval; (void)outvallen;
    /* Return YPERR_KEY (5) for all mock queries — simulates "key not found",
     * the most common non-error failure mode in NIS lookups. */
    return 5;
}
"#,
    )
    .expect("Failed to write NIS mock C file");

    // Always compile the mock into a static library so the tests link.
    // When the real libnsl is installed and preferred, the user can
    // set NIS_NO_MOCK=1 to skip the mock and link against the system lib.
    let use_mock = std::env::var("NIS_NO_MOCK").is_err();

    if use_mock {
        cc::Build::new()
            .file(&mock_c)
            .warnings(false)
            .compile("nsl");
        // cc::Build automatically emits cargo:rustc-link-lib=static=nsl
        // and cargo:rustc-link-search=native=<out_dir>
    } else {
        // Link against the real system libnsl.
        println!("cargo:rustc-link-lib=nsl");
    }
}

// =============================================================================
// Cyrus SASL (ffi-cyrus-sasl) — libsasl2 link directives
// =============================================================================
//
// Cyrus SASL has a stable C API (<sasl/sasl.h>) with a small surface area
// (about 15 functions), so hand-written extern "C" declarations in cyrus_sasl.rs
// are used instead of bindgen. This function emits the linker directive to
// link against the system libsasl2.
//
// When running tests without libsasl2 mechanism plugins configured, a tiny
// C mock is compiled to satisfy the linker and provide deterministic behavior.

#[cfg(feature = "ffi-cyrus-sasl")]
fn generate_cyrus_sasl_link(out_dir: &Path) {
    // Compile a mock C library that stubs the Cyrus SASL functions so unit
    // tests exercise the safe Rust wrappers without requiring full SASL
    // mechanism plugins to be configured.
    let mock_c = out_dir.join("cyrus_sasl_mock.c");
    fs::write(
        &mock_c,
        r#"
/* Mock libsasl2 for unit tests -- NOT linked in production builds.
 * Provides minimal stubs for the Cyrus SASL API functions used by
 * exim-ffi/src/cyrus_sasl.rs so that the safe wrapper unit tests
 * can verify error handling and type conversions.
 */
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

typedef struct sasl_conn { int dummy; } sasl_conn_t;

#define SASL_OK       0
#define SASL_CONTINUE 1
#define SASL_FAIL    -1

static sasl_conn_t mock_conn;
static const char *mock_mechs = "PLAIN LOGIN";
static const char *mock_impl = "Cyrus SASL (mock)";
static const char *mock_version_str = "2.1.0";
static const char *mock_errstr = "mock error";
static const char *mock_username = "testuser";

typedef struct {
    unsigned long id;
    int (*proc)(void);
    void *context;
} sasl_callback_t;

int sasl_server_init(const sasl_callback_t *cb, const char *app) {
    (void)cb; (void)app;
    return SASL_OK;
}

int sasl_server_new(const char *svc, const char *fqdn,
                    const char *realm, const char *lp,
                    const char *rp, const sasl_callback_t *cb,
                    unsigned int flags, sasl_conn_t **pc) {
    (void)svc; (void)fqdn; (void)realm;
    (void)lp; (void)rp; (void)cb; (void)flags;
    if (pc) *pc = &mock_conn;
    return SASL_OK;
}

int sasl_listmech(sasl_conn_t *c, const char *u,
                  const char *pfx, const char *sep, const char *sfx,
                  const char **res, unsigned int *pl, int *cnt) {
    (void)c; (void)u; (void)pfx; (void)sep; (void)sfx;
    if (res) *res = mock_mechs;
    if (pl) *pl = (unsigned int)strlen(mock_mechs);
    if (cnt) *cnt = 2;
    return SASL_OK;
}

int sasl_server_start(sasl_conn_t *c, const char *m,
                      const char *ci, unsigned int cl,
                      const char **so, unsigned int *sl) {
    (void)c; (void)m; (void)ci; (void)cl;
    if (so) *so = NULL;
    if (sl) *sl = 0;
    return SASL_OK;
}

int sasl_server_step(sasl_conn_t *c, const char *ci,
                     unsigned int cl,
                     const char **so, unsigned int *sl) {
    (void)c; (void)ci; (void)cl;
    if (so) *so = NULL;
    if (sl) *sl = 0;
    return SASL_OK;
}

int sasl_getprop(sasl_conn_t *c, int pn, const void **pv) {
    (void)c;
    if (pn == 0 && pv) {
        *pv = mock_username;
        return SASL_OK;
    }
    return SASL_FAIL;
}

int sasl_setprop(sasl_conn_t *c, int pn, const void *v) {
    (void)c; (void)pn; (void)v;
    return SASL_OK;
}

void sasl_dispose(sasl_conn_t **pc) {
    if (pc) *pc = NULL;
}

void sasl_done(void) { }

const char *sasl_errstring(int e, const char *l, const char **ol) {
    (void)e; (void)l;
    if (ol) *ol = NULL;
    return mock_errstr;
}

const char *sasl_errdetail(sasl_conn_t *c) {
    (void)c;
    return "mock error detail";
}

void sasl_version_info(const char **impl, const char **vs,
                       int *ma, int *mi, int *st, int *pa) {
    if (impl) *impl = mock_impl;
    if (vs) *vs = mock_version_str;
    if (ma) *ma = 2;
    if (mi) *mi = 1;
    if (st) *st = 0;
    if (pa) *pa = 0;
}
"#,
    )
    .expect("Failed to write Cyrus SASL mock C file");

    // Use mock for tests by default. Set CYRUS_SASL_NO_MOCK=1 to link
    // against the real libsasl2 instead.
    let use_mock = std::env::var("CYRUS_SASL_NO_MOCK").is_err();

    if use_mock {
        cc::Build::new()
            .file(&mock_c)
            .warnings(false)
            .compile("sasl2");
        // cc::Build automatically emits cargo:rustc-link-lib=static=sasl2
    } else {
        // Link against the real system libsasl2.
        println!("cargo:rustc-link-lib=sasl2");
    }
}
