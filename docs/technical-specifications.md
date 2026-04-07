# Technical Specification

# 0. Agent Action Plan

## 0.1 Intent Clarification


### 0.1.1 Core Refactoring Objective

Based on the prompt, the Blitzy platform understands that the refactoring objective is to **perform a complete tech stack migration** of the Exim Mail Transfer Agent from C to Rust — rewriting 182,614 lines of C across 242 source files (165 `.c`, 77 `.h`) into a Rust crate workspace that produces a functionally equivalent `exim` binary. This is one of the most comprehensive C-to-Rust rewrites ever specified for a production Internet infrastructure daemon.

- **Refactoring type**: Tech stack migration (C → Rust) with architectural restructuring
- **Target repository**: Same repository — the Rust workspace is created alongside the existing C source tree, and the existing `Makefile` is extended (not replaced) to add a `make rust` target
- **Primary driver**: Memory safety — replacing all manual memory management (440 allocation call sites across 5 taint-aware pool types) with Rust ownership semantics, lifetimes, and scoped arenas
- **Behavioral constraint**: Every existing feature MUST be preserved with identical behavior — this is a language migration, not a feature change
- **Acceptance criteria**: 142 test script directories (1,205 test files) and 14 C test programs executed by the Perl `test/runtest` harness must all pass with zero test modifications

The refactoring goals, in order of priority, are:

- **Eliminate all manual memory management** — Replace Exim's custom stacking memory allocator (`src/src/store.c`) with Rust ownership semantics, using `bumpalo` arenas for per-message allocations and `Arc<Config>` for immutable configuration
- **Eradicate global mutable state** — Replace 714 global variables in `src/src/globals.c`/`globals.h` with 4 scoped context structs (`ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`) passed explicitly through call chains
- **Replace preprocessor-driven feature toggling** — Convert 1,677 `#ifdef`/`#ifndef` preprocessor conditionals into Cargo feature flags, enabling type-safe, IDE-discoverable compile-time configuration
- **Enforce compile-time taint tracking** — Replace Exim's runtime taint tracking with `Tainted<T>` / `Clean<T>` newtype wrappers enforced at compile time with zero runtime cost
- **Modernize the driver architecture** — Replace the `driver_info` C struct inheritance pattern with Rust trait objects and compile-time registration via the `inventory` crate
- **Deliver auxiliary artifacts** — Produce a benchmarking suite, benchmarking report, and executive presentation alongside the rewritten binary

### 0.1.2 Technical Interpretation

This refactoring translates to the following technical transformation strategy:

**Current Architecture (C)**:
- Monolithic single-binary MTA compiled from 242 C source files via POSIX Make
- Custom taint-aware stacking allocator with 5 pool types (`POOL_MAIN`, `POOL_PERM`, `POOL_CONFIG`, `POOL_SEARCH`, `POOL_MESSAGE`) and paired tainted counterparts
- 714 global variables providing implicit shared state across all subsystems
- 1,677 preprocessor conditionals controlling compile-time feature selection
- Pluggable driver model via C struct "inheritance" (`driver_info` base struct cast pattern)
- Fork-per-connection concurrency model with pipe-based IPC

**Target Architecture (Rust)**:
- Cargo workspace with 18 crates producing a single `exim` binary
- `bumpalo::Bump` arenas for per-message allocations, `Arc<Config>` for frozen config, standard `Vec`/`String` for permanent data, `HashMap` with explicit `clear()` for lookup cache
- 4 scoped context structs replacing all global mutable state, passed as explicit parameters
- Cargo feature flags replacing all preprocessor conditionals
- Trait-based driver system with `inventory` crate for compile-time driver registration
- Same fork-per-connection concurrency model preserved — `tokio` is scoped ONLY to async lookup execution via `block_on()`, never used for the daemon event loop
- All `unsafe` code confined to a single `exim-ffi` crate wrapping C libraries without viable Rust alternatives

The transformation must maintain exact behavioral parity across all external interfaces: SMTP wire protocol (RFC 5321/6531/3207/8314/7672), CLI flags and exit codes, configuration file syntax, spool file format, and log output format.


## 0.2 Source Analysis


### 0.2.1 Comprehensive Source File Discovery

The Exim C codebase targeted for rewriting spans the entire `src/src/` tree (excluding `src/exim_monitor/`) and is organized into a flat core directory with seven driver/module subdirectories. Every file listed below has been verified through repository inspection.

**Current Structure Mapping:**

```
src/src/                          (Core MTA Engine — ~82 .c files, ~25 .h files)
├── exim.c                        (6,274 lines — main() + mode dispatch)
├── expand.c                      (9,210 lines — string expansion DSL)
├── deliver.c                     (9,104 lines — delivery orchestration)
├── smtp_in.c                     (6,022 lines — SMTP inbound server)
├── acl.c                         (5,147 lines — ACL policy engine)
├── readconf.c                    (4,765 lines — configuration parser)
├── daemon.c                      (daemon process management)
├── receive.c                     (message reception + spool write)
├── queue.c                       (queue enumeration + management)
├── route.c                       (router chain orchestration)
├── transport.c                   (transport dispatch framework)
├── dns.c / dnsbl.c / host.c      (DNS resolution + DNSBL)
├── smtp_out.c                    (outbound SMTP I/O)
├── tls.c / tls-openssl.c         (5,323 lines — TLS OpenSSL backend)
├── tls-gnu.c                     (4,491 lines — TLS GnuTLS backend)
├── dane.c / dane-openssl.c       (DANE/TLSA support)
├── store.c / store.h             (custom allocator — 5 pools + taint)
├── globals.c / globals.h         (714 global variables)
├── search.c                      (lookup dispatcher + cache)
├── dbfn.c                        (hints database access)
├── spool_in.c / spool_out.c      (spool file I/O)
├── spool_mbox.c                  (content scanning .eml materialization)
├── string.c / tree.c / match.c   (string/tree/matching utilities)
├── debug.c / log.c               (debugging + logging)
├── verify.c                      (address verification)
├── retry.c / enq.c               (retry logic + serialization)
├── parse.c / rewrite.c           (address parsing + header rewriting)
├── header.c / moan.c             (header manipulation + bounces)
├── mime.c / regex.c              (MIME processing + regex)
├── spam.c / malware.c / dcc.c    (content scanning clients)
├── hash.c / md5.c / crypt16.c    (cryptographic primitives)
├── base64.c / rfc2047.c          (encoding utilities)
├── ip.c / host_address.c         (socket + host address ops)
├── child.c / directory.c         (process + directory management)
├── priv.c / environment.c        (privilege + environment hardening)
├── os.c / setenv.c               (OS portability layer)
├── filtertest.c / local_scan.c   (filter test + local scan hook)
├── drtables.c                    (driver/module registration tables)
├── buildconfig.c / macro_predef.c (build-time generators)
├── version.c / tod.c             (version info + time-of-day)
├── utf8.c / imap_utf7.c          (internationalization)
├── xclient.c / atrn.c            (XCLIENT + ATRN SMTP extensions)
├── lss.c / dummies.c             (local scan stubs)
├── bmi_spam.c / std-crypto.c     (BMI + built-in DH params)
├── regex_cache.c / xtextencode.c (regex cache + xtext encoding)
│
├── auths/                        (9 auth drivers — 15 .c, 11 .h)
│   ├── cram_md5.c/.h             (CRAM-MD5 HMAC challenge)
│   ├── cyrus_sasl.c/.h           (Cyrus SASL via libsasl2)
│   ├── dovecot.c/.h              (Dovecot socket auth)
│   ├── external.c/.h             (SASL EXTERNAL)
│   ├── gsasl.c/.h                (GNU SASL / SCRAM)
│   ├── heimdal_gssapi.c/.h       (Kerberos GSSAPI)
│   ├── plaintext.c/.h            (PLAIN/LOGIN)
│   ├── spa.c/.h + auth-spa.c/.h  (SPA/NTLM with built-in MD4/DES)
│   ├── tls.c/.h                  (TLS client cert auth)
│   ├── check_serv_cond.c         (server condition helper)
│   ├── get_data.c / get_no64_data.c (base64/non-base64 I/O)
│   ├── call_saslauthd.c          (saslauthd integration)
│   └── pwcheck.c/.h              (saslauthd socket helper)
│
├── routers/                      (7 router drivers — 17 .c, 8 .h)
│   ├── accept.c/.h               (catch-all local delivery)
│   ├── dnslookup.c/.h            (DNS MX/A/AAAA/SRV routing)
│   ├── ipliteral.c/.h            (IP-literal domain routing)
│   ├── iplookup.c/.h             (external host query routing)
│   ├── manualroute.c/.h          (admin-defined route lists)
│   ├── queryprogram.c/.h         (external program routing)
│   ├── redirect.c/.h             (alias/filter/Sieve redirect)
│   └── rf_*.c + rf_functions.h   (10 shared router helpers)
│
├── transports/                   (6 transport drivers — 7 .c, 7 .h)
│   ├── appendfile.c/.h           (mbox/MBX/Maildir/Mailstore)
│   ├── autoreply.c/.h            (vacation auto-response)
│   ├── lmtp.c/.h                 (LMTP client transport)
│   ├── pipe.c/.h                 (pipe to command)
│   ├── queuefile.c/.h            (experimental spool copy)
│   ├── smtp.c/.h                 (6,573 lines — outbound SMTP)
│   └── tf_maildir.c/.h           (Maildir helper)
│
├── lookups/                      (25+ lookup backends — 25 .c, 1 .h)
│   ├── cdb.c                     (CDB file lookup)
│   ├── dbmdb.c                   (DBM hints glue)
│   ├── dnsdb.c                   (DNS query lookup)
│   ├── dsearch.c                 (directory entry search)
│   ├── json.c                    (Jansson JSON traversal)
│   ├── ldap.c                    (LDAP/AD directory)
│   ├── lmdb.c                    (LMDB key-value)
│   ├── lsearch.c                 (line-scan file lookup)
│   ├── mysql.c                   (MySQL/MariaDB SQL)
│   ├── nis.c / nisplus.c         (NIS/NIS+ directory)
│   ├── nmh.c                     (NMH datagram)
│   ├── oracle.c                  (Oracle OCI SQL)
│   ├── passwd.c                  (system passwd lookup)
│   ├── pgsql.c                   (PostgreSQL SQL)
│   ├── psl.c                     (Public Suffix List)
│   ├── readsock.c                (socket request/response)
│   ├── redis.c                   (Redis commands)
│   ├── spf.c                     (SPF lookup shim)
│   ├── sqlite.c                  (SQLite query)
│   ├── testdb.c                  (test/synthetic backends)
│   ├── whoson.c                  (Whoson adapter)
│   └── lf_*.c + lf_functions.h   (3 shared lookup helpers)
│
├── miscmods/                     (20+ modules — 18 .c, 16 .h)
│   ├── dkim.c/.h + dkim_transport.c (DKIM sign/verify)
│   ├── arc.c + arc_api.h         (ARC verify/sign)
│   ├── spf.c/.h + spf_api.h     (SPF via libspf2)
│   ├── dmarc.c/.h + dmarc_common.c (DMARC via libopendmarc)
│   ├── dmarc_native.c            (native DMARC parser)
│   ├── exim_filter.c             (Exim filter interpreter)
│   ├── sieve_filter.c            (RFC 5228 Sieve)
│   ├── proxy.c                   (HAProxy PROXY v1/v2)
│   ├── socks.c                   (SOCKS5 client)
│   ├── xclient.c                 (XCLIENT handler)
│   ├── pam.c                     (PAM authentication)
│   ├── radius.c                  (RADIUS authentication)
│   ├── perl.c                    (embedded Perl interpreter)
│   ├── dscp.c                    (DSCP traffic marking)
│   ├── spf_perl.c               (Perl-based SPF alternative)
│   ├── dummy.c                   (empty-archive placeholder)
│   └── pdkim/                    (in-tree PDKIM library — 2 .c, 4 .h)
│       ├── pdkim.c/.h            (DKIM streaming parser)
│       ├── signing.c/.h          (crypto backend abstraction)
│       ├── crypt_ver.h           (crypto backend selection)
│       └── pdkim_hash.h          (hash include aggregator)
│
└── hintsdb/                      (5 hints DB backends — 0 .c, 5 .h)
    ├── hints_bdb.h               (Berkeley DB adapter)
    ├── hints_sqlite.h            (SQLite3 adapter)
    ├── hints_gdbm.h              (GDBM adapter)
    ├── hints_ndbm.h              (NDBM adapter)
    └── hints_tdb.h               (TDB adapter)
```

### 0.2.2 Source File Inventory Summary

| Directory | .c Files | .h Files | Total | Key Characteristics |
|-----------|----------|----------|-------|-------------------|
| `src/src/` (root) | ~82 | ~25 | ~107 | Core MTA engine, 714 globals, custom allocator |
| `src/src/auths/` | 15 | 11 | 26 | 9 auth drivers + shared helpers |
| `src/src/routers/` | 17 | 8 | 25 | 7 router drivers + 10 rf_* helpers |
| `src/src/transports/` | 7 | 7 | 14 | 6 transport drivers + maildir helper |
| `src/src/lookups/` | 25 | 1 | 26 | 25+ lookup backends + 3 lf_* helpers |
| `src/src/miscmods/` | 18 | 16 | 34 | 20+ policy/auth/filter modules |
| `src/src/miscmods/pdkim/` | 2 | 4 | 6 | In-tree DKIM library |
| `src/src/hintsdb/` | 0 | 5 | 5 | 5 hints DB backend headers |
| **Total** | **~166** | **~77** | **~243** | **182,614 lines of C** |

### 0.2.3 Critical Complexity Hotspots

The following files represent the highest complexity and largest transformation challenges:

| Source File | Lines | Complexity Factor |
|------------|-------|------------------|
| `src/src/expand.c` | 9,210 | Monolithic `${...}` DSL interpreter — must be rewritten as tokenizer → parser → evaluator pipeline |
| `src/src/deliver.c` | 9,104 | Delivery orchestration with subprocess pool, retry logic, parallel remote delivery |
| `src/src/transports/smtp.c` | 6,573 | Full outbound SMTP state machine with TLS/DANE/PIPELINING/CHUNKING |
| `src/src/exim.c` | 6,274 | Main entry point with multi-mode dispatch (daemon, delivery, queue-runner, verify, etc.) |
| `src/src/smtp_in.c` | 6,022 | Inbound SMTP state machine with ACL integration at every phase |
| `src/src/tls-openssl.c` | 5,323 | OpenSSL TLS backend with DANE, OCSP, SNI, session cache |
| `src/src/acl.c` | 5,147 | ACL evaluation engine spanning 7+ SMTP phases |
| `src/src/readconf.c` | 4,765 | Configuration parser with macro expansion, conditionals, driver instantiation |
| `src/src/tls-gnu.c` | 4,491 | GnuTLS TLS backend with version-specific capability detection |
| `src/src/globals.c` | ~3,000+ | 714 global variable definitions — all must be scoped into context structs |
| `src/src/store.c` | ~1,500+ | Custom stacking allocator with 5 pools + taint tracking — replaced entirely by Rust ownership |

### 0.2.4 Preserved Artifacts (Not Rewritten)

The following source directories are explicitly preserved unchanged and are NOT part of the rewrite:

- `src/exim_monitor/` — X11 GUI, excluded from scope entirely
- `src/src/utils/*.src` — Perl utility script templates (`exiqgrep`, `exiqsumm`, `exipick`, `exigrep`, `eximstats`, `exicyclog`, `exinext`, `exiwhat`, `exim_checkaccess`, `exim_msgdate`, `exim_id_update`, `eximon`)
- `src/util/` — Standalone admin/developer tools (shell/Perl scripts + `gen_pkcs3.c`)
- `src/scripts/` — Build-time generator scripts (`Configure-config.h`, `Configure-os.c`, `Configure-os.h`)
- `test/` — Entire test harness (142 directories, 1,205 files, 14 C test programs, Perl TAP framework)
- `doc/` — Documentation tree
- `.github/` — GitHub metadata templates
- `configs/` — System integration guidance


## 0.3 Scope Boundaries


### 0.3.1 Exhaustively In Scope

**Source Transformations (C → Rust rewrite):**
- `src/src/*.c` — All core MTA C source files (~82 files)
- `src/src/*.h` — All core MTA header files (~25 files), translated into Rust type definitions and module interfaces
- `src/src/auths/*.c` and `src/src/auths/*.h` — All 9 authenticator drivers + shared helpers (26 files)
- `src/src/routers/*.c` and `src/src/routers/*.h` — All 7 router drivers + rf_* helpers (25 files)
- `src/src/transports/*.c` and `src/src/transports/*.h` — All 6 transport drivers + maildir helper (14 files)
- `src/src/lookups/*.c` and `src/src/lookups/*.h` — All 25+ lookup backends + lf_* helpers (26 files)
- `src/src/miscmods/*.c` and `src/src/miscmods/*.h` — All 20+ policy/auth/filter modules (34 files)
- `src/src/miscmods/pdkim/*.c` and `src/src/miscmods/pdkim/*.h` — In-tree PDKIM library (6 files)
- `src/src/hintsdb/*.h` — All 5 hints database backend headers (5 files)

**Rust Workspace Creation (new files):**
- `Cargo.toml` — Root workspace manifest
- `exim-core/` — Main binary crate (replaces `exim.c`)
- `exim-config/` — Configuration parser crate (replaces `readconf.c`)
- `exim-expand/` — String expansion engine crate (replaces `expand.c`)
- `exim-smtp/` — SMTP protocol handling crate (replaces `smtp_in.c`, `smtp_out.c`)
- `exim-deliver/` — Delivery orchestration crate (replaces `deliver.c`, `route.c`)
- `exim-acl/` — ACL evaluation engine crate (replaces `acl.c`)
- `exim-tls/` — TLS abstraction crate (replaces `tls.c`, `tls-openssl.c`, `tls-gnu.c`)
- `exim-store/` — Rust memory management crate (replaces `store.c`)
- `exim-drivers/` — Driver trait definitions and registry crate
- `exim-auths/` — 9 auth driver implementations crate
- `exim-routers/` — 7 router implementations crate
- `exim-transports/` — 6 transport implementations crate
- `exim-lookups/` — 28 lookup module implementations crate
- `exim-miscmods/` — Optional modules crate (DKIM, DMARC, ARC, SPF, Sieve, etc.)
- `exim-dns/` — DNS resolution crate
- `exim-spool/` — Spool file I/O crate
- `exim-ffi/` — Minimal C FFI shim layer (only crate with `unsafe`)

**Benchmarking Artifacts (new files):**
- `bench/run_benchmarks.sh` — Benchmarking script measuring throughput, latency, memory, parse time
- `bench/BENCHMARK_REPORT.md` — Generated benchmarking report with side-by-side C vs Rust comparisons

**Executive Presentation (new file):**
- `docs/executive_presentation.html` — Self-contained reveal.js presentation for C-suite audience

**Build System Extension:**
- `src/Makefile` — Extended (not replaced) to add `make rust` target invoking `cargo build --release`

**Configuration Compatibility:**
- Existing Exim configuration files must parse identically on both C and Rust binaries
- `src/src/configure.default` (or equivalent default config) must parse without errors or warnings

**Spool File Compatibility:**
- Spool files written by C Exim must be readable by Rust Exim and vice versa
- `-D` (data) and `-H` (header/metadata) file formats must be byte-level compatible

### 0.3.2 Explicitly Out of Scope

**Excluded from rewriting — NEVER modify:**
- `test/` — All 142 test script directories, 1,205 test files, and 14 C test programs (immutable acceptance criteria)
- `test/runtest` — Perl test harness preserved as-is
- `test/lib/` — Perl test support library (`Exim::Runtest`, `Exim::Utils`)
- `doc/` — Entire documentation tree (DocBook, xfpt, doc-scripts, doc-txt)
- `release-process/` — Release process scripts (if present)
- `.github/` — GitHub metadata (issue and PR templates)
- `src/src/utils/*.src` — All Perl utility script templates (`exiqgrep`, `exiqsumm`, `exipick`, `exigrep`, `eximstats`, `exicyclog`, `exinext`, `exiwhat`, `exim_checkaccess`, `exim_msgdate`, `exim_id_update`, `eximon`)
- `src/util/` — Standalone admin/developer tools (10 scripts + 1 C helper)
- `src/exim_monitor/` — X11 GUI (`eximon`) — not rewritten, not compiled
- `src/scripts/` — POSIX shell build helper scripts
- `configs/` — System integration guidance

**Behavioral exclusions — NEVER alter:**
- SMTP wire protocol behavior (RFC 5321/6531/3207/8314/7672 compliance must be identical)
- CLI flags, exit codes, or log output format
- Exim configuration file backward compatibility
- Spool file format
- EHLO capability advertisement

**Code-level exclusions — NEVER permit:**
- `unsafe` code outside the `exim-ffi` crate
- `#[allow(...)]` attributes without inline justification referencing a specific technical reason


## 0.4 Target Design


### 0.4.1 Refactored Structure Planning

The Rust workspace is organized as 18 crates within the repository root, producing a single `exim` binary. Every crate, module, and file is listed below.

```
Cargo.toml                                  (workspace root manifest)
rust-toolchain.toml                         (pin Rust stable toolchain)
.cargo/config.toml                          (RUSTFLAGS, linker config)

exim-core/
├── Cargo.toml
└── src/
    ├── main.rs                             (entry point, mode dispatch)
    ├── cli.rs                              (CLI argument parsing via clap)
    ├── daemon.rs                           (daemon mode, poll event loop)
    ├── queue_runner.rs                     (queue enumeration + scheduled runs)
    ├── signal.rs                           (signal handling: SIGHUP, SIGTERM, SIGCHLD, SIGALRM)
    ├── process.rs                          (fork/exec, child management, smtp_slots)
    ├── modes.rs                            (verify, expand-test, filter-test, address-test, config-check)
    └── context.rs                          (ServerContext, MessageContext, DeliveryContext, ConfigContext)

exim-config/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── parser.rs                           (configuration file parser)
    ├── options.rs                          (option list processing for all driver types)
    ├── macros.rs                           (macro expansion, conditionals, includes)
    ├── driver_init.rs                      (driver instance creation from config)
    ├── validate.rs                         (config validation and -bP printing)
    └── types.rs                            (ConfigContext struct, Arc<Config> wrapper)

exim-expand/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── tokenizer.rs                        (lexical analysis of ${...} expressions)
    ├── parser.rs                           (AST construction from token stream)
    ├── evaluator.rs                        (AST evaluation engine)
    ├── variables.rs                        (variable substitution: $local_part, $domain, etc.)
    ├── conditions.rs                       (${if ...} conditional logic)
    ├── lookups.rs                          (${lookup ...} integration)
    ├── transforms.rs                       (${lc}, ${uc}, ${hash}, ${nhash}, ${substr}, etc.)
    ├── run.rs                              (${run ...} via std::process::Command)
    ├── dlfunc.rs                           (${dlfunc} dynamic function calls)
    └── perl.rs                             (${perl} integration via FFI)

exim-smtp/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── inbound/
    │   ├── mod.rs
    │   ├── command_loop.rs                 (SMTP command state machine)
    │   ├── pipelining.rs                   (PIPELINING support)
    │   ├── chunking.rs                     (CHUNKING/BDAT support)
    │   ├── prdr.rs                         (Per-Recipient Data Response)
    │   └── atrn.rs                         (ATRN extension)
    └── outbound/
        ├── mod.rs
        ├── connection.rs                   (connection management + reuse)
        ├── parallel.rs                     (parallel delivery dispatch)
        ├── tls_negotiation.rs              (STARTTLS initiation)
        └── response.rs                     (SMTP response parsing)

exim-deliver/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── orchestrator.rs                     (per-recipient router chain → transport dispatch)
    ├── routing.rs                          (router chain evaluation + preconditions)
    ├── transport_dispatch.rs               (transport selection and execution)
    ├── parallel.rs                         (subprocess pool for remote delivery)
    ├── retry.rs                            (retry scheduling + hints DB integration)
    ├── bounce.rs                           (bounce/DSN message generation)
    └── journal.rs                          (journal file management + crash recovery)

exim-acl/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── engine.rs                           (ACL evaluation core)
    ├── verbs.rs                            (accept, deny, defer, discard, drop, require, warn)
    ├── conditions.rs                       (ACL condition evaluation)
    ├── phases.rs                           (connect, helo, mail, rcpt, data, mime, dkim, prdr)
    └── variables.rs                        (ACL variable management)

exim-tls/
├── Cargo.toml
└── src/
    ├── lib.rs                              (TLS abstraction trait)
    ├── rustls_backend.rs                   (default: rustls backend)
    ├── openssl_backend.rs                  (optional: openssl crate backend)
    ├── dane.rs                             (DANE/TLSA support)
    ├── ocsp.rs                             (OCSP stapling)
    ├── sni.rs                              (Server Name Indication)
    ├── client_cert.rs                      (client certificate verification)
    └── session_cache.rs                    (TLS session resumption)

exim-store/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API)
    ├── arena.rs                            (bumpalo::Bump per-message arena)
    ├── config_store.rs                     (Arc<Config> frozen after parse)
    ├── search_cache.rs                     (HashMap with explicit clear())
    ├── message_store.rs                    (scoped per-message struct)
    └── taint.rs                            (Tainted<T> / Clean<T> newtypes)

exim-drivers/
├── Cargo.toml
└── src/
    ├── lib.rs                              (public API + trait definitions)
    ├── auth_driver.rs                      (AuthDriver trait)
    ├── router_driver.rs                    (RouterDriver trait + result enum)
    ├── transport_driver.rs                 (TransportDriver trait)
    ├── lookup_driver.rs                    (LookupDriver trait)
    └── registry.rs                         (inventory-based compile-time registration)

exim-auths/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── cram_md5.rs                         (CRAM-MD5 HMAC challenge)
    ├── cyrus_sasl.rs                       (Cyrus SASL via FFI)
    ├── dovecot.rs                          (Dovecot socket auth)
    ├── external.rs                         (SASL EXTERNAL)
    ├── gsasl.rs                            (GNU SASL via FFI)
    ├── heimdal_gssapi.rs                   (Kerberos GSSAPI via FFI)
    ├── plaintext.rs                        (PLAIN/LOGIN)
    ├── spa.rs                              (SPA/NTLM with built-in primitives)
    ├── tls_auth.rs                         (TLS client cert auth)
    └── helpers/
        ├── mod.rs
        ├── base64_io.rs                    (shared base64 I/O)
        ├── server_condition.rs             (server condition evaluation)
        └── saslauthd.rs                    (saslauthd socket integration)

exim-routers/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── accept.rs                           (catch-all local delivery)
    ├── dnslookup.rs                        (DNS MX/A/AAAA/SRV)
    ├── ipliteral.rs                        (IP-literal domains)
    ├── iplookup.rs                         (external host queries)
    ├── manualroute.rs                      (admin-defined routes)
    ├── queryprogram.rs                     (external program)
    ├── redirect.rs                         (alias/filter/Sieve)
    └── helpers/
        ├── mod.rs
        ├── queue_add.rs                    (rf_queue_add equivalent)
        ├── self_action.rs                  (rf_self_action equivalent)
        ├── change_domain.rs                (rf_change_domain equivalent)
        ├── expand_data.rs                  (rf_expand_data equivalent)
        ├── get_transport.rs                (rf_get_transport equivalent)
        ├── get_errors_address.rs           (rf_get_errors_address equivalent)
        ├── get_munge_headers.rs            (rf_get_munge_headers equivalent)
        ├── lookup_hostlist.rs              (rf_lookup_hostlist equivalent)
        └── ugid.rs                         (rf_get_ugid + rf_set_ugid equivalent)

exim-transports/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── appendfile.rs                       (mbox/MBX/Maildir/Mailstore)
    ├── autoreply.rs                        (vacation auto-response)
    ├── lmtp.rs                             (LMTP client via command or socket)
    ├── pipe.rs                             (pipe to command)
    ├── queuefile.rs                        (experimental spool copy)
    ├── smtp.rs                             (outbound SMTP/LMTP — largest driver)
    └── maildir.rs                          (Maildir helper — quota, directory mgmt)

exim-lookups/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── cdb.rs                              (CDB read-only — pure Rust parser)
    ├── dbmdb.rs                            (DBM hints glue)
    ├── dnsdb.rs                            (DNS resolver lookup)
    ├── dsearch.rs                          (directory entry search)
    ├── json.rs                             (JSON file traversal — serde_json)
    ├── ldap.rs                             (LDAP — ldap3 crate)
    ├── lmdb.rs                             (LMDB — Rust lmdb crate)
    ├── lsearch.rs                          (line-scan file lookup)
    ├── mysql.rs                            (MySQL — mysql_async + block_on)
    ├── nis.rs                              (NIS via FFI)
    ├── nisplus.rs                          (NIS+ via FFI)
    ├── nmh.rs                              (NMH datagram)
    ├── oracle.rs                           (Oracle via FFI)
    ├── passwd.rs                           (system passwd)
    ├── pgsql.rs                            (PostgreSQL — tokio-postgres + block_on)
    ├── psl.rs                              (Public Suffix List)
    ├── readsock.rs                         (socket request/response)
    ├── redis.rs                            (Redis — redis crate)
    ├── spf.rs                              (SPF lookup shim)
    ├── sqlite.rs                           (SQLite — rusqlite)
    ├── testdb.rs                           (synthetic test backends)
    ├── whoson.rs                           (Whoson via FFI)
    └── helpers/
        ├── mod.rs
        ├── check_file.rs                   (lf_check_file equivalent)
        ├── quote.rs                        (lf_quote equivalent)
        └── sql_perform.rs                  (lf_sqlperform equivalent)

exim-miscmods/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── dkim/
    │   ├── mod.rs                          (DKIM verify/sign orchestration)
    │   ├── transport.rs                    (DKIM transport signing shim)
    │   └── pdkim/
    │       ├── mod.rs                      (streaming DKIM parser)
    │       └── signing.rs                  (crypto backend abstraction)
    ├── arc.rs                              (ARC verify/sign)
    ├── spf.rs                              (SPF via libspf2 FFI)
    ├── dmarc.rs                            (DMARC via libopendmarc FFI)
    ├── dmarc_native.rs                     (experimental native DMARC)
    ├── exim_filter.rs                      (Exim filter interpreter)
    ├── sieve_filter.rs                     (RFC 5228 Sieve interpreter)
    ├── proxy.rs                            (HAProxy PROXY v1/v2)
    ├── socks.rs                            (SOCKS5 client)
    ├── xclient.rs                          (XCLIENT handler)
    ├── pam.rs                              (PAM via FFI)
    ├── radius.rs                           (RADIUS via FFI)
    ├── perl.rs                             (embedded Perl via FFI)
    └── dscp.rs                             (DSCP traffic marking)

exim-dns/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── resolver.rs                         (A/AAAA/MX/SRV/TLSA/PTR resolution)
    └── dnsbl.rs                            (DNSBL checking)

exim-spool/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── header_file.rs                      (-H file read/write — byte-level compat)
    ├── data_file.rs                        (-D file read/write — byte-level compat)
    ├── message_id.rs                       (message ID generation)
    └── format.rs                           (spool format constants and helpers)

exim-ffi/
├── Cargo.toml
├── build.rs                                (bindgen/cc for C library wrapping)
└── src/
    ├── lib.rs                              (ONLY crate with unsafe code)
    ├── pam.rs                              (libpam FFI bindings)
    ├── radius.rs                           (libradius FFI bindings)
    ├── perl.rs                             (libperl FFI bindings)
    ├── gsasl.rs                            (libgsasl FFI bindings)
    ├── krb5.rs                             (libkrb5/Heimdal FFI bindings)
    ├── hintsdb/
    │   ├── mod.rs
    │   ├── bdb.rs                          (Berkeley DB FFI)
    │   ├── gdbm.rs                         (GDBM FFI)
    │   ├── ndbm.rs                         (NDBM FFI)
    │   └── tdb.rs                          (TDB FFI)
    └── spf.rs                              (libspf2 FFI bindings)

bench/
├── run_benchmarks.sh                       (benchmarking script)
└── BENCHMARK_REPORT.md                     (generated benchmarking report)

docs/
└── executive_presentation.html             (reveal.js executive presentation)
```

### 0.4.2 Design Pattern Applications

The following design patterns are applied systematically across the Rust workspace:

- **Type-state pattern** — The SMTP inbound command loop uses type-state encoding to enforce valid SMTP command ordering at compile time (e.g., `Connected` → `Greeted` → `MailFrom` → `RcptTo` → `Data`)
- **Trait-based driver system** — `AuthDriver`, `RouterDriver`, `TransportDriver`, and `LookupDriver` traits replace the `driver_info` C struct inheritance pattern, with `inventory::submit!` for compile-time registration
- **Arena allocation** — `bumpalo::Bump` provides per-message arenas dropped at message completion, replacing `POOL_MAIN`
- **Newtype wrappers** — `Tainted<T>` / `Clean<T>` enforce taint tracking at compile time with zero runtime cost
- **Scoped context passing** — Four context structs (`ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`) replace 714 global variables, passed explicitly through all call chains
- **Feature flags** — Cargo feature flags replace all 1,677 preprocessor conditionals, supporting dead-code elimination and type-safe compile-time configuration
- **Abstraction traits** — `TlsBackend` trait unifies the dual TLS implementations behind a common interface, with `rustls` as default and `openssl` as optional

### 0.4.3 Memory Model Replacement

| C Store Pool | Rust Replacement | Semantics |
|-------------|-----------------|-----------|
| `POOL_MAIN` (+ taint) | `bumpalo::Bump` arena, dropped at message completion | Per-message short-lived allocations |
| `POOL_PERM` (+ taint) | Owned `String`/`Vec`/structs with process lifetime | Permanent data, freed at exit |
| `POOL_CONFIG` (+ taint) | `Arc<Config>` frozen after parse | Immutable config, shared across threads |
| `POOL_SEARCH` (+ taint) | `HashMap` with explicit `clear()` on lookup tidyup | Lookup cache |
| `POOL_MESSAGE` (+ taint) | Scoped struct dropped at end of message transaction | Medium-lifetime per-message (DKIM, transport state) |
| Taint tracking | `Tainted<T>` / `Clean<T>` newtypes | Compile-time enforcement, no runtime cost |

### 0.4.4 Global State Replacement

714 global variables in `globals.c`/`globals.h` are replaced with 4 scoped context structs:

- **`ServerContext`** — Daemon-lifetime state: listening sockets, process table, signal state, TLS credentials
- **`MessageContext`** — Per-message state: sender, recipients, headers, body reference, message ID, ACL variables
- **`DeliveryContext`** — Per-delivery-attempt state: current address, router/transport results, retry data
- **`ConfigContext`** — Parsed configuration: all options, driver instances, ACL definitions, rewrite rules

### 0.4.5 Web Search Research Conducted

Research was conducted for the following topics to inform the target design:

- **C-to-Rust migration best practices** — Validated the `exim-ffi` isolation pattern for unsafe code, arena allocation strategy for replacing C malloc pools, and `inventory` crate for plugin registration
- **Rust arena allocators** — Confirmed `bumpalo` 3.20.2 as the preferred arena allocator for high-throughput per-message allocation patterns
- **Rust TLS libraries** — Verified `rustls` 0.23.37 as mature production-grade TLS with DANE support; `openssl` 0.10.75 as fallback for environments requiring OpenSSL
- **Rust async bridging** — Confirmed `tokio::runtime::Runtime::block_on()` as the correct pattern for bridging async database lookup crates into a synchronous fork-per-connection model
- **reveal.js** — Confirmed CDN delivery via `https://cdn.jsdelivr.net/npm/reveal.js@5.1.0/` for self-contained HTML presentations


## 0.5 Transformation Mapping


### 0.5.1 File-by-File Transformation Plan

Every target file is mapped to its source origin. The entire refactor executes in ONE phase — no multi-phase splitting.

**Transformation Modes:**
- **CREATE** — New Rust file translating functionality from the C source
- **UPDATE** — Existing file modified to accommodate the Rust build
- **REFERENCE** — Existing file used as a pattern/example but not directly translated

#### Workspace Root Files

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `Cargo.toml` | CREATE | `src/Makefile` | Workspace manifest defining 18 member crates, shared dependencies, feature flags |
| `rust-toolchain.toml` | CREATE | — | Pin Rust stable edition |
| `.cargo/config.toml` | CREATE | — | `RUSTFLAGS="-D warnings"`, linker settings for FFI libraries |
| `src/Makefile` | UPDATE | `src/Makefile` | Add `make rust` target invoking `cargo build --release` |

#### exim-core Crate (replaces `exim.c`, `daemon.c`, `queue.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-core/Cargo.toml` | CREATE | — | Dependencies on all workspace crates, clap for CLI |
| `exim-core/src/main.rs` | CREATE | `src/src/exim.c` | Main entry point, mode dispatch (daemon/delivery/queue-runner/verify/expand/filter/address/config) |
| `exim-core/src/cli.rs` | CREATE | `src/src/exim.c` | CLI argument parsing: -bd, -bp, -bt, -be, -bV, -d, -q, -M* families |
| `exim-core/src/daemon.rs` | CREATE | `src/src/daemon.c` | Poll-based event loop, socket binding, connection acceptance, queue scheduling |
| `exim-core/src/queue_runner.rs` | CREATE | `src/src/queue.c` | Queue enumeration, operator actions, scheduled queue runs |
| `exim-core/src/signal.rs` | CREATE | `src/src/daemon.c` | SIGHUP re-exec, SIGTERM shutdown, SIGCHLD reaping, SIGALRM scheduling |
| `exim-core/src/process.rs` | CREATE | `src/src/child.c` | Fork/exec, child_open_uid, child management, smtp_slots array |
| `exim-core/src/modes.rs` | CREATE | `src/src/exim.c`, `src/src/filtertest.c` | Verify, expand-test, filter-test, address-test, config-check modes |
| `exim-core/src/context.rs` | CREATE | `src/src/globals.c`, `src/src/globals.h` | ServerContext, MessageContext, DeliveryContext, ConfigContext struct definitions |

#### exim-config Crate (replaces `readconf.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-config/Cargo.toml` | CREATE | — | Dependencies on exim-store, exim-drivers |
| `exim-config/src/lib.rs` | CREATE | `src/src/readconf.c` | Public API for config parsing |
| `exim-config/src/parser.rs` | CREATE | `src/src/readconf.c` | Full config file parser with backward-compatible syntax |
| `exim-config/src/options.rs` | CREATE | `src/src/readconf.c` | Option list processing for all driver types (optionlist tables) |
| `exim-config/src/macros.rs` | CREATE | `src/src/readconf.c` | Macro expansion, .include, .ifdef/.ifndef conditionals |
| `exim-config/src/driver_init.rs` | CREATE | `src/src/readconf.c`, `src/src/drtables.c` | Driver instance creation from config, registry lookup |
| `exim-config/src/validate.rs` | CREATE | `src/src/readconf.c` | Config validation, -bP printing |
| `exim-config/src/types.rs` | CREATE | `src/src/globals.c`, `src/src/structs.h` | ConfigContext struct with Arc<Config> wrapper |

#### exim-expand Crate (replaces `expand.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-expand/Cargo.toml` | CREATE | — | Dependencies on exim-store, exim-lookups |
| `exim-expand/src/lib.rs` | CREATE | `src/src/expand.c` | Public API |
| `exim-expand/src/tokenizer.rs` | CREATE | `src/src/expand.c` | Tokenizer for ${...} DSL (new architecture replacing monolithic function) |
| `exim-expand/src/parser.rs` | CREATE | `src/src/expand.c` | AST construction from token stream |
| `exim-expand/src/evaluator.rs` | CREATE | `src/src/expand.c` | AST evaluation engine |
| `exim-expand/src/variables.rs` | CREATE | `src/src/expand.c` | Variable substitution: $local_part, $domain, $sender_address, etc. |
| `exim-expand/src/conditions.rs` | CREATE | `src/src/expand.c` | ${if ...} conditional logic |
| `exim-expand/src/lookups.rs` | CREATE | `src/src/expand.c` | ${lookup ...} integration bridge |
| `exim-expand/src/transforms.rs` | CREATE | `src/src/expand.c` | ${lc}, ${uc}, ${hash}, ${nhash}, ${substr}, ${length}, etc. |
| `exim-expand/src/run.rs` | CREATE | `src/src/expand.c` | ${run ...} via std::process::Command |
| `exim-expand/src/dlfunc.rs` | CREATE | `src/src/expand.c` | ${dlfunc} dynamic function calls |
| `exim-expand/src/perl.rs` | CREATE | `src/src/expand.c` | ${perl} integration via exim-ffi |

#### exim-smtp Crate (replaces `smtp_in.c`, `smtp_out.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-smtp/Cargo.toml` | CREATE | — | Dependencies on exim-acl, exim-tls |
| `exim-smtp/src/lib.rs` | CREATE | — | Public API |
| `exim-smtp/src/inbound/mod.rs` | CREATE | `src/src/smtp_in.c` | Inbound SMTP module root |
| `exim-smtp/src/inbound/command_loop.rs` | CREATE | `src/src/smtp_in.c` | SMTP command state machine |
| `exim-smtp/src/inbound/pipelining.rs` | CREATE | `src/src/smtp_in.c` | PIPELINING support |
| `exim-smtp/src/inbound/chunking.rs` | CREATE | `src/src/smtp_in.c` | CHUNKING/BDAT support |
| `exim-smtp/src/inbound/prdr.rs` | CREATE | `src/src/smtp_in.c` | Per-Recipient Data Response |
| `exim-smtp/src/inbound/atrn.rs` | CREATE | `src/src/atrn.c` | ATRN extension |
| `exim-smtp/src/outbound/mod.rs` | CREATE | `src/src/smtp_out.c` | Outbound SMTP module root |
| `exim-smtp/src/outbound/connection.rs` | CREATE | `src/src/smtp_out.c` | Connection management + reuse |
| `exim-smtp/src/outbound/parallel.rs` | CREATE | `src/src/smtp_out.c` | Parallel delivery dispatch |
| `exim-smtp/src/outbound/tls_negotiation.rs` | CREATE | `src/src/smtp_out.c` | STARTTLS initiation on outbound |
| `exim-smtp/src/outbound/response.rs` | CREATE | `src/src/smtp_out.c` | SMTP response parsing |

#### exim-deliver Crate (replaces `deliver.c`, `route.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-deliver/Cargo.toml` | CREATE | — | Dependencies on exim-routers, exim-transports |
| `exim-deliver/src/lib.rs` | CREATE | `src/src/deliver.c` | Public API |
| `exim-deliver/src/orchestrator.rs` | CREATE | `src/src/deliver.c` | Per-recipient router chain → transport dispatch |
| `exim-deliver/src/routing.rs` | CREATE | `src/src/route.c` | Router chain evaluation + preconditions |
| `exim-deliver/src/transport_dispatch.rs` | CREATE | `src/src/deliver.c` | Transport selection and execution |
| `exim-deliver/src/parallel.rs` | CREATE | `src/src/deliver.c` | Subprocess pool for parallel remote delivery |
| `exim-deliver/src/retry.rs` | CREATE | `src/src/retry.c` | Retry scheduling + hints DB integration |
| `exim-deliver/src/bounce.rs` | CREATE | `src/src/moan.c` | Bounce/DSN/warning message generation |
| `exim-deliver/src/journal.rs` | CREATE | `src/src/deliver.c` | Journal file management + crash recovery |

#### exim-acl Crate (replaces `acl.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-acl/Cargo.toml` | CREATE | — | Dependencies on exim-expand, exim-lookups |
| `exim-acl/src/lib.rs` | CREATE | `src/src/acl.c` | Public API |
| `exim-acl/src/engine.rs` | CREATE | `src/src/acl.c` | ACL evaluation core |
| `exim-acl/src/verbs.rs` | CREATE | `src/src/acl.c` | accept, deny, defer, discard, drop, require, warn |
| `exim-acl/src/conditions.rs` | CREATE | `src/src/acl.c` | ACL condition evaluation |
| `exim-acl/src/phases.rs` | CREATE | `src/src/acl.c` | connect, helo, mail, rcpt, data, mime, dkim, prdr |
| `exim-acl/src/variables.rs` | CREATE | `src/src/acl.c` | ACL variable management ($acl_c0..$acl_c9, etc.) |

#### exim-tls Crate (replaces `tls.c`, `tls-openssl.c`, `tls-gnu.c`, `dane.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-tls/Cargo.toml` | CREATE | — | Features: tls-rustls (default), tls-openssl |
| `exim-tls/src/lib.rs` | CREATE | `src/src/tls.c` | TLS abstraction trait definition |
| `exim-tls/src/rustls_backend.rs` | CREATE | `src/src/tls-gnu.c` | REFERENCE — rustls implementation of TlsBackend trait |
| `exim-tls/src/openssl_backend.rs` | CREATE | `src/src/tls-openssl.c` | openssl crate implementation of TlsBackend trait |
| `exim-tls/src/dane.rs` | CREATE | `src/src/dane.c`, `src/src/dane-openssl.c` | DANE/TLSA support |
| `exim-tls/src/ocsp.rs` | CREATE | `src/src/tls-openssl.c` | OCSP stapling |
| `exim-tls/src/sni.rs` | CREATE | `src/src/tls-openssl.c` | Server Name Indication |
| `exim-tls/src/client_cert.rs` | CREATE | `src/src/tls-openssl.c` | Client certificate verification |
| `exim-tls/src/session_cache.rs` | CREATE | `src/src/tls-openssl.c` | TLS session resumption |

#### exim-store Crate (replaces `store.c`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-store/Cargo.toml` | CREATE | — | Dependencies: bumpalo |
| `exim-store/src/lib.rs` | CREATE | `src/src/store.c`, `src/src/store.h` | Public API |
| `exim-store/src/arena.rs` | CREATE | `src/src/store.c` | bumpalo::Bump per-message arena |
| `exim-store/src/config_store.rs` | CREATE | `src/src/store.c` | Arc<Config> frozen after parse |
| `exim-store/src/search_cache.rs` | CREATE | `src/src/store.c` | HashMap with explicit clear() |
| `exim-store/src/message_store.rs` | CREATE | `src/src/store.c` | Scoped per-message struct |
| `exim-store/src/taint.rs` | CREATE | `src/src/store.c` | Tainted<T>/Clean<T> newtypes |

#### exim-drivers Crate

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-drivers/Cargo.toml` | CREATE | — | Dependencies: inventory |
| `exim-drivers/src/lib.rs` | CREATE | `src/src/drtables.c` | Public API + re-exports |
| `exim-drivers/src/auth_driver.rs` | CREATE | `src/src/auths/*.h` | AuthDriver trait: server_condition(), server(), client() |
| `exim-drivers/src/router_driver.rs` | CREATE | `src/src/routers/*.h` | RouterDriver trait: route() → Accept/Pass/Decline/Fail/Defer |
| `exim-drivers/src/transport_driver.rs` | CREATE | `src/src/transports/*.h` | TransportDriver trait: transport_entry() |
| `exim-drivers/src/lookup_driver.rs` | CREATE | `src/src/lookupapi.h` | LookupDriver trait: find(), open(), close(), tidy() |
| `exim-drivers/src/registry.rs` | CREATE | `src/src/drtables.c` | inventory-based compile-time registration |

#### exim-auths Crate (replaces `src/src/auths/`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-auths/Cargo.toml` | CREATE | `src/src/auths/Makefile` | Feature flags per auth driver |
| `exim-auths/src/lib.rs` | CREATE | — | Module re-exports |
| `exim-auths/src/cram_md5.rs` | CREATE | `src/src/auths/cram_md5.c` | CRAM-MD5 with built-in HMAC |
| `exim-auths/src/cyrus_sasl.rs` | CREATE | `src/src/auths/cyrus_sasl.c` | Cyrus SASL via exim-ffi |
| `exim-auths/src/dovecot.rs` | CREATE | `src/src/auths/dovecot.c` | Dovecot socket auth |
| `exim-auths/src/external.rs` | CREATE | `src/src/auths/external.c` | SASL EXTERNAL |
| `exim-auths/src/gsasl.rs` | CREATE | `src/src/auths/gsasl.c` | GNU SASL via exim-ffi |
| `exim-auths/src/heimdal_gssapi.rs` | CREATE | `src/src/auths/heimdal_gssapi.c` | Kerberos GSSAPI via exim-ffi |
| `exim-auths/src/plaintext.rs` | CREATE | `src/src/auths/plaintext.c` | PLAIN/LOGIN |
| `exim-auths/src/spa.rs` | CREATE | `src/src/auths/spa.c`, `src/src/auths/auth-spa.c` | SPA/NTLM with built-in MD4/DES |
| `exim-auths/src/tls_auth.rs` | CREATE | `src/src/auths/tls.c` | TLS client cert auth |
| `exim-auths/src/helpers/base64_io.rs` | CREATE | `src/src/auths/get_data.c`, `src/src/auths/get_no64_data.c` | Shared base64 I/O |
| `exim-auths/src/helpers/server_condition.rs` | CREATE | `src/src/auths/check_serv_cond.c` | Server condition evaluation |
| `exim-auths/src/helpers/saslauthd.rs` | CREATE | `src/src/auths/call_saslauthd.c`, `src/src/auths/pwcheck.c` | saslauthd integration |

#### exim-routers Crate (replaces `src/src/routers/`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-routers/Cargo.toml` | CREATE | `src/src/routers/Makefile` | Feature flags per router |
| `exim-routers/src/lib.rs` | CREATE | — | Module re-exports |
| `exim-routers/src/accept.rs` | CREATE | `src/src/routers/accept.c` | Catch-all local delivery |
| `exim-routers/src/dnslookup.rs` | CREATE | `src/src/routers/dnslookup.c` | DNS MX/A/AAAA/SRV routing |
| `exim-routers/src/ipliteral.rs` | CREATE | `src/src/routers/ipliteral.c` | IP-literal domains |
| `exim-routers/src/iplookup.rs` | CREATE | `src/src/routers/iplookup.c` | External host queries |
| `exim-routers/src/manualroute.rs` | CREATE | `src/src/routers/manualroute.c` | Admin-defined routes |
| `exim-routers/src/queryprogram.rs` | CREATE | `src/src/routers/queryprogram.c` | External program routing |
| `exim-routers/src/redirect.rs` | CREATE | `src/src/routers/redirect.c` | Alias/filter/Sieve |
| `exim-routers/src/helpers/*.rs` | CREATE | `src/src/routers/rf_*.c` | 9 shared router helper functions |

#### exim-transports Crate (replaces `src/src/transports/`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-transports/Cargo.toml` | CREATE | `src/src/transports/Makefile` | Feature flags per transport |
| `exim-transports/src/lib.rs` | CREATE | — | Module re-exports |
| `exim-transports/src/appendfile.rs` | CREATE | `src/src/transports/appendfile.c` | mbox/MBX/Maildir/Mailstore with locking |
| `exim-transports/src/autoreply.rs` | CREATE | `src/src/transports/autoreply.c` | Vacation auto-response |
| `exim-transports/src/lmtp.rs` | CREATE | `src/src/transports/lmtp.c` | LMTP client |
| `exim-transports/src/pipe.rs` | CREATE | `src/src/transports/pipe.c` | Pipe to command |
| `exim-transports/src/queuefile.rs` | CREATE | `src/src/transports/queuefile.c` | Experimental spool copy |
| `exim-transports/src/smtp.rs` | CREATE | `src/src/transports/smtp.c` | Full outbound SMTP state machine |
| `exim-transports/src/maildir.rs` | CREATE | `src/src/transports/tf_maildir.c` | Maildir quota + directory management |

#### exim-lookups Crate (replaces `src/src/lookups/`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-lookups/Cargo.toml` | CREATE | `src/src/lookups/Makefile` | Feature flags per lookup backend |
| `exim-lookups/src/lib.rs` | CREATE | `src/src/search.c` | Public API, lookup dispatcher, cache/LRU |
| `exim-lookups/src/cdb.rs` | CREATE | `src/src/lookups/cdb.c` | Pure Rust CDB parser |
| `exim-lookups/src/dbmdb.rs` | CREATE | `src/src/lookups/dbmdb.c` | DBM hints (via exim-ffi for BDB/GDBM/NDBM) |
| `exim-lookups/src/dnsdb.rs` | CREATE | `src/src/lookups/dnsdb.c` | DNS query lookup via hickory-resolver |
| `exim-lookups/src/dsearch.rs` | CREATE | `src/src/lookups/dsearch.c` | Directory entry search (pure Rust) |
| `exim-lookups/src/json.rs` | CREATE | `src/src/lookups/json.c` | JSON traversal via serde_json |
| `exim-lookups/src/ldap.rs` | CREATE | `src/src/lookups/ldap.c` | LDAP via ldap3 crate |
| `exim-lookups/src/lmdb.rs` | CREATE | `src/src/lookups/lmdb.c` | LMDB via Rust lmdb crate |
| `exim-lookups/src/lsearch.rs` | CREATE | `src/src/lookups/lsearch.c` | Line-scan file lookup (pure Rust) |
| `exim-lookups/src/mysql.rs` | CREATE | `src/src/lookups/mysql.c` | MySQL via mysql_async + block_on |
| `exim-lookups/src/nis.rs` | CREATE | `src/src/lookups/nis.c` | NIS via exim-ffi |
| `exim-lookups/src/nisplus.rs` | CREATE | `src/src/lookups/nisplus.c` | NIS+ via exim-ffi |
| `exim-lookups/src/nmh.rs` | CREATE | `src/src/lookups/nmh.c` | NMH datagram protocol |
| `exim-lookups/src/oracle.rs` | CREATE | `src/src/lookups/oracle.c` | Oracle OCI via exim-ffi |
| `exim-lookups/src/passwd.rs` | CREATE | `src/src/lookups/passwd.c` | System passwd lookup (pure Rust) |
| `exim-lookups/src/pgsql.rs` | CREATE | `src/src/lookups/pgsql.c` | PostgreSQL via tokio-postgres + block_on |
| `exim-lookups/src/psl.rs` | CREATE | `src/src/lookups/psl.c` | Public Suffix List (pure Rust) |
| `exim-lookups/src/readsock.rs` | CREATE | `src/src/lookups/readsock.c` | Socket request/response (pure Rust) |
| `exim-lookups/src/redis.rs` | CREATE | `src/src/lookups/redis.c` | Redis via redis crate |
| `exim-lookups/src/spf.rs` | CREATE | `src/src/lookups/spf.c` | SPF lookup shim |
| `exim-lookups/src/sqlite.rs` | CREATE | `src/src/lookups/sqlite.c` | SQLite via rusqlite |
| `exim-lookups/src/testdb.rs` | CREATE | `src/src/lookups/testdb.c` | Synthetic test backends |
| `exim-lookups/src/whoson.rs` | CREATE | `src/src/lookups/whoson.c` | Whoson via exim-ffi |
| `exim-lookups/src/helpers/*.rs` | CREATE | `src/src/lookups/lf_*.c` | 3 shared lookup helpers |

#### exim-miscmods Crate (replaces `src/src/miscmods/`)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-miscmods/Cargo.toml` | CREATE | `src/src/miscmods/Makefile` | Feature flags per module |
| `exim-miscmods/src/lib.rs` | CREATE | — | Module re-exports |
| `exim-miscmods/src/dkim/mod.rs` | CREATE | `src/src/miscmods/dkim.c` | DKIM verify/sign orchestration |
| `exim-miscmods/src/dkim/transport.rs` | CREATE | `src/src/miscmods/dkim_transport.c` | DKIM transport signing |
| `exim-miscmods/src/dkim/pdkim/mod.rs` | CREATE | `src/src/miscmods/pdkim/pdkim.c` | DKIM streaming parser |
| `exim-miscmods/src/dkim/pdkim/signing.rs` | CREATE | `src/src/miscmods/pdkim/signing.c` | Crypto backend abstraction |
| `exim-miscmods/src/arc.rs` | CREATE | `src/src/miscmods/arc.c` | ARC verify/sign |
| `exim-miscmods/src/spf.rs` | CREATE | `src/src/miscmods/spf.c` | SPF via libspf2 FFI |
| `exim-miscmods/src/dmarc.rs` | CREATE | `src/src/miscmods/dmarc.c`, `src/src/miscmods/dmarc_common.c` | DMARC via libopendmarc FFI |
| `exim-miscmods/src/dmarc_native.rs` | CREATE | `src/src/miscmods/dmarc_native.c` | Native DMARC parser |
| `exim-miscmods/src/exim_filter.rs` | CREATE | `src/src/miscmods/exim_filter.c` | Exim filter interpreter |
| `exim-miscmods/src/sieve_filter.rs` | CREATE | `src/src/miscmods/sieve_filter.c` | RFC 5228 Sieve interpreter |
| `exim-miscmods/src/proxy.rs` | CREATE | `src/src/miscmods/proxy.c` | HAProxy PROXY v1/v2 |
| `exim-miscmods/src/socks.rs` | CREATE | `src/src/miscmods/socks.c` | SOCKS5 client |
| `exim-miscmods/src/xclient.rs` | CREATE | `src/src/miscmods/xclient.c` | XCLIENT handler |
| `exim-miscmods/src/pam.rs` | CREATE | `src/src/miscmods/pam.c` | PAM via exim-ffi |
| `exim-miscmods/src/radius.rs` | CREATE | `src/src/miscmods/radius.c` | RADIUS via exim-ffi |
| `exim-miscmods/src/perl.rs` | CREATE | `src/src/miscmods/perl.c` | Embedded Perl via exim-ffi |
| `exim-miscmods/src/dscp.rs` | CREATE | `src/src/miscmods/dscp.c` | DSCP traffic marking |

#### Remaining Crates (exim-dns, exim-spool, exim-ffi)

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `exim-dns/src/lib.rs` | CREATE | `src/src/dns.c` | Public API |
| `exim-dns/src/resolver.rs` | CREATE | `src/src/dns.c`, `src/src/host.c` | A/AAAA/MX/SRV/TLSA/PTR via hickory-resolver |
| `exim-dns/src/dnsbl.rs` | CREATE | `src/src/dnsbl.c` | DNSBL checking |
| `exim-spool/src/lib.rs` | CREATE | `src/src/spool_in.c`, `src/src/spool_out.c` | Public API |
| `exim-spool/src/header_file.rs` | CREATE | `src/src/spool_in.c`, `src/src/spool_out.c` | -H file read/write (byte-level compat) |
| `exim-spool/src/data_file.rs` | CREATE | `src/src/spool_in.c`, `src/src/spool_out.c` | -D file read/write (byte-level compat) |
| `exim-spool/src/message_id.rs` | CREATE | `src/src/spool_out.c` | Message ID generation (base-62) |
| `exim-spool/src/format.rs` | CREATE | `src/src/spool_in.c` | Spool format constants |
| `exim-ffi/Cargo.toml` | CREATE | — | bindgen, cc, libc dependencies |
| `exim-ffi/build.rs` | CREATE | — | bindgen for C library headers |
| `exim-ffi/src/lib.rs` | CREATE | — | ONLY crate with unsafe code |
| `exim-ffi/src/pam.rs` | CREATE | `src/src/miscmods/pam.c` | libpam FFI bindings |
| `exim-ffi/src/radius.rs` | CREATE | `src/src/miscmods/radius.c` | libradius FFI bindings |
| `exim-ffi/src/perl.rs` | CREATE | `src/src/miscmods/perl.c` | libperl FFI bindings |
| `exim-ffi/src/gsasl.rs` | CREATE | `src/src/auths/gsasl.c` | libgsasl FFI bindings |
| `exim-ffi/src/krb5.rs` | CREATE | `src/src/auths/heimdal_gssapi.c` | libkrb5/Heimdal FFI bindings |
| `exim-ffi/src/hintsdb/*.rs` | CREATE | `src/src/hintsdb/hints_*.h` | BDB/GDBM/NDBM/TDB FFI (4 files) |
| `exim-ffi/src/spf.rs` | CREATE | `src/src/miscmods/spf.c` | libspf2 FFI bindings |

#### Benchmarking and Presentation Artifacts

| Target File | Transformation | Source File | Key Changes |
|------------|---------------|-------------|-------------|
| `bench/run_benchmarks.sh` | CREATE | — | SMTP throughput, fork latency, memory RSS, config parse benchmarks |
| `bench/BENCHMARK_REPORT.md` | CREATE | — | Side-by-side C vs Rust comparison tables with pass/fail thresholds |
| `docs/executive_presentation.html` | CREATE | — | Self-contained reveal.js, 10–15 slides, C-suite audience |

### 0.5.2 Cross-File Dependencies

Import statement migration follows these patterns:

- **FROM (C)**: `#include "exim.h"` (includes `globals.h`, `functions.h`, `macros.h`, `structs.h`)
- **TO (Rust)**: `use exim_core::context::{ServerContext, MessageContext};` + crate-specific imports

- **FROM (C)**: `#include "store.h"` → `store_get()`, `store_mark()`, `store_reset()`
- **TO (Rust)**: `use exim_store::{MessageArena, Tainted, Clean};`

- **FROM (C)**: `extern optionlist_auths[]` in `globals.c`
- **TO (Rust)**: `use exim_drivers::registry::AuthRegistry;`

- **FROM (C)**: `#ifdef AUTH_CRAM_MD5` / `#include "auths/cram_md5.h"`
- **TO (Rust)**: `#[cfg(feature = "auth-cram-md5")] use exim_auths::cram_md5;`

### 0.5.3 One-Phase Execution

The entire refactor executes in ONE phase. All 18 crates, the benchmarking suite, and the executive presentation are delivered together. There is no phase splitting or incremental migration — the Rust workspace must compile and produce a functionally equivalent binary that passes all 142 test directories.


## 0.6 Dependency Inventory


### 0.6.1 Key Rust Crate Dependencies

All versions were verified against the crates.io registry. The `tokio` runtime is scoped ONLY to async lookup execution via `block_on()` and MUST NOT be used for the main daemon event loop.

| Registry | Package | Version | Purpose | Used By |
|----------|---------|---------|---------|---------|
| crates.io | `bumpalo` | 3.20.2 | Per-message arena allocator (replaces POOL_MAIN) | `exim-store` |
| crates.io | `typed-arena` | 2.0.2 | Alternative arena allocator | `exim-store` |
| crates.io | `inventory` | 0.3.22 | Compile-time driver registration (replaces drtables.c) | `exim-drivers`, all driver crates |
| crates.io | `clap` | 4.5.60 | CLI argument parsing | `exim-core` |
| crates.io | `rustls` | 0.23.37 | Default TLS backend (replaces tls-gnu.c/tls-openssl.c) | `exim-tls` |
| crates.io | `openssl` | 0.10.75 | Optional TLS backend (behind `tls-openssl` feature) | `exim-tls` |
| crates.io | `rusqlite` | 0.38.0 | SQLite lookup + hintsdb-sqlite backend | `exim-lookups`, `exim-ffi` |
| crates.io | `redis` | 1.0.5 | Redis lookup backend | `exim-lookups` |
| crates.io | `tokio-postgres` | 0.7.16 | PostgreSQL lookup (async, bridged via block_on) | `exim-lookups` |
| crates.io | `deadpool-postgres` | 0.14.1 | PostgreSQL connection pooling | `exim-lookups` |
| crates.io | `mysql_async` | 0.36.1 | MySQL/MariaDB lookup (async, bridged via block_on) | `exim-lookups` |
| crates.io | `ldap3` | 0.12.1 | LDAP directory lookup | `exim-lookups` |
| crates.io | `hickory-resolver` | 0.25.0 | DNS resolution (A/AAAA/MX/SRV/TLSA/PTR) | `exim-dns` |
| crates.io | `tokio` | 1.50.0 | Async runtime (scoped to lookup block_on ONLY) | `exim-lookups` |
| crates.io | `serde` | 1.0.228 | Serialization framework | workspace-wide |
| crates.io | `serde_json` | 1.0.149 | JSON parsing (replaces Jansson for json lookup) | `exim-lookups` |
| crates.io | `regex` | 1.12.3 | Rust-native regex (supplements PCRE2 where safe) | workspace-wide |
| crates.io | `pcre2` | 0.2.11 | PCRE2 bindings for Exim-compatible pattern matching | `exim-acl`, `exim-expand` |
| crates.io | `libc` | 0.2.183 | C type definitions and system call bindings | `exim-ffi`, `exim-core` |
| crates.io | `nix` | 0.31.2 | Safe POSIX API wrappers (fork, signal, socket, chown) | `exim-core` |
| crates.io | `thiserror` | 2.0.18 | Error type derivation | workspace-wide |
| crates.io | `anyhow` | 1.0.102 | Application error handling | `exim-core` |
| crates.io | `tracing` | 0.1.44 | Structured logging/debugging (replaces debug.c/log.c) | workspace-wide |
| crates.io | `tracing-subscriber` | 0.3.22 | Log output formatting | `exim-core` |
| crates.io | `log` | 0.4.29 | Logging facade (for crate compatibility) | workspace-wide |
| crates.io | `bindgen` | 0.72.1 | C header → Rust FFI binding generation (build dep) | `exim-ffi` |
| crates.io | `cc` | 1.2.56 | C compilation orchestration (build dep) | `exim-ffi` |
| crates.io | `libloading` | 0.9.0 | Dynamic library loading (replaces dlopen/dlsym) | `exim-ffi` |
| system | `hyperfine` | 1.20.0 | Binary-level benchmark timing (CLI tool) | `bench/run_benchmarks.sh` |
| CDN | `reveal.js` | 5.1.0 | Presentation framework (CDN-loaded, not a Rust dep) | `docs/executive_presentation.html` |

### 0.6.2 Preserved C Library Dependencies (FFI)

These C libraries have no viable Rust-native replacement and are wrapped via the `exim-ffi` crate:

| Library | FFI Wrapper | Purpose | Rust Alternative Status |
|---------|------------|---------|------------------------|
| `libpam` | `exim-ffi/src/pam.rs` | PAM authentication | No mature Rust PAM crate with full conversation callback |
| `libradius` / `radiusclient` | `exim-ffi/src/radius.rs` | RADIUS authentication | No stable Rust RADIUS client library |
| `libperl` | `exim-ffi/src/perl.rs` | Embedded Perl interpreter for ${perl} and perl_startup | No alternative — Perl embedding is inherently FFI |
| `libgsasl` | `exim-ffi/src/gsasl.rs` | GNU SASL (SCRAM, channel-binding) | No comprehensive Rust GSASL equivalent |
| `libkrb5` / Heimdal | `exim-ffi/src/krb5.rs` | Kerberos GSSAPI authentication | No mature Rust Kerberos client |
| `libspf2` | `exim-ffi/src/spf.rs` | SPF validation with Exim DNS hooks | No drop-in Rust SPF library with DNS callback |
| Berkeley DB (`libdb`) | `exim-ffi/src/hintsdb/bdb.rs` | BDB hintsdb backend | No Rust BDB bindings; feature-gated |
| `libgdbm` | `exim-ffi/src/hintsdb/gdbm.rs` | GDBM hintsdb backend | No Rust GDBM bindings |
| NDBM (`libndbm`) | `exim-ffi/src/hintsdb/ndbm.rs` | NDBM hintsdb backend | No Rust NDBM bindings |
| `libtdb` | `exim-ffi/src/hintsdb/tdb.rs` | TDB hintsdb backend | No Rust TDB bindings |

### 0.6.3 Import Refactoring

All Rust crates use workspace-level dependency sharing to avoid version conflicts:

- **Workspace-wide** (`[workspace.dependencies]` in root `Cargo.toml`):
  - `serde`, `serde_json`, `thiserror`, `anyhow`, `tracing`, `log`, `libc`, `regex`
- **Feature-gated lookups** (in `exim-lookups/Cargo.toml`):
  - `rusqlite` behind `lookup-sqlite`
  - `redis` behind `lookup-redis`
  - `tokio-postgres` + `deadpool-postgres` behind `lookup-pgsql`
  - `mysql_async` behind `lookup-mysql`
  - `ldap3` behind `lookup-ldap`
- **Feature-gated TLS** (in `exim-tls/Cargo.toml`):
  - `rustls` behind `tls-rustls` (default)
  - `openssl` behind `tls-openssl`

### 0.6.4 External Reference Updates

| File | Update Required |
|------|----------------|
| `src/Makefile` | Add `rust:` target invoking `cargo build --release` with proper `--target-dir` |
| `Cargo.toml` (root) | New workspace manifest with all 18 member crates and shared dependencies |
| `rust-toolchain.toml` | Pin to Rust stable edition for reproducible builds |
| `.cargo/config.toml` | Set `RUSTFLAGS="-D warnings"`, linker search paths for FFI libraries |
| `bench/run_benchmarks.sh` | New script referencing both C and Rust binary paths |
| `docs/executive_presentation.html` | New self-contained HTML referencing CDN reveal.js |


## 0.7 Refactoring Rules


### 0.7.1 Mandatory Behavioral Preservation Rules

The following rules are explicitly specified by the user and are non-negotiable:

- **All 142 test script directories MUST pass** via `test/runtest` with zero test modifications — tests are immutable acceptance criteria
- **All 14 C test programs** in `test/mail/` MUST pass unmodified
- **Existing Exim configuration files MUST parse identically** — no syntax changes, no new warnings, no behavioral differences from the C parser
- **Spool file format MUST be byte-level compatible** — C Exim must read Rust-written spool files and vice versa; verified by cross-version queue flush test
- **SMTP wire protocol behavior MUST be identical** — RFC 5321/6531/3207/8314/7672 compliance, EHLO capability advertisement lists identical extensions for identical configuration
- **CLI flags, exit codes, and log output format MUST be preserved** — main log, reject log, and panic log entries must match C Exim format (parseable by existing `exigrep`/`eximstats`)
- **The `test/runtest` harness MUST operate against the Rust-produced `exim` binary** by pointing at its build output path

### 0.7.2 Code Safety Rules

- **Zero `unsafe` blocks outside the `exim-ffi` crate** — any `unsafe` found outside `exim-ffi` is a blocking defect
- **Total `unsafe` block count MUST be below 50** — if count exceeds 50, each site must have a formal review comment and a corresponding test exercising the unsafe boundary
- **Every `unsafe` block MUST be documented** with an inline comment justifying necessity
- **No `#[allow(...)]` attributes permitted** except with inline justification comment referencing a specific technical reason
- **`RUSTFLAGS="-D warnings"` and `cargo clippy -- -D warnings"` MUST produce zero diagnostics** — builds that emit warnings must fail
- **`cargo fmt --check` MUST pass** — consistent formatting enforced

### 0.7.3 Architectural Rules

- **The Makefile MUST be extended (not replaced)** to add a `make rust` target invoking `cargo build --release`
- **`tokio` runtime MUST be scoped to lookup execution only** — bridged via `tokio::runtime::Runtime::block_on()` within the synchronous fork-per-connection model; tokio MUST NOT be used for the main daemon event loop
- **Database lookup crates use async APIs bridged via `block_on()`** — the tokio runtime is created per-lookup-execution, not process-wide
- **Config data stored in `Arc<Config>`** made immutable after parsing — no mutable shared config state
- **Driver registration via `inventory` crate** — each driver implementation uses `inventory::submit!` for compile-time collection; runtime driver resolution by name from config
- **Cargo feature flags replace ALL 1,677 preprocessor conditionals** — no `#[cfg]` attributes that duplicate the exact C `#ifdef` logic; instead, use semantically meaningful Cargo features

### 0.7.4 Preservation Boundaries

- **NEVER modify any file in `test/`** — all test directories, test files, and C test programs are immutable
- **NEVER modify `test/runtest`** or any file in `test/lib/`
- **NEVER modify files in `doc/`, `release-process/`, `.github/`**
- **NEVER modify `src/src/utils/*.src`** — all Perl utility scripts preserved unchanged
- **NEVER modify `src/util/`** — standalone admin tools preserved
- **NEVER break SMTP wire protocol behavior**
- **NEVER alter CLI flags, exit codes, or log output format**
- **`src/exim_monitor/`** is excluded from scope entirely — not rewritten, not compiled

### 0.7.5 Performance Thresholds

- **SMTP transaction throughput**: Rust Exim within 10% of C Exim (10,000 messages via localhost)
- **Fork-per-connection latency**: Rust within 5% of C (1,000 concurrent SMTP connections, time-to-first-response)
- **Peak RSS memory**: Rust MUST NOT exceed 120% of C Exim RSS (10MB message processing)
- **Config parse time**: Directional comparison reported for `configure.default`
- **Assumed parity is NOT acceptable** — every metric MUST be measured and reported with numerical values

### 0.7.6 Deliverable Specifications

- **Benchmarking script** (`bench/run_benchmarks.sh`):
  - Measures 4 metrics (throughput, fork latency, peak RSS, config parse time)
  - Uses `hyperfine` for binary-level timing, `swaks` or custom SMTP load script for throughput
  - Minimum 1,000 iterations (100 for memory/connection tests) for statistical significance
  - Outputs structured results (JSON or CSV)

- **Benchmarking report** (`bench/BENCHMARK_REPORT.md`):
  - Side-by-side comparison tables with percentage delta
  - Pass/fail against stated thresholds
  - System specification for reproducibility
  - Methodology description

- **Executive presentation** (`docs/executive_presentation.html`):
  - Self-contained single HTML file with reveal.js via CDN (`https://cdn.jsdelivr.net/npm/reveal.js@5.1.0/`)
  - 10–15 slides for C-suite audience with no technical background
  - Required sections: Why This Migration, What Changed, Performance Results, Security Posture, Risk Assessment, Migration Timeline
  - MUST NOT contain: code snippets, terminal output, jargon without inline definitions, slides with more than 40 words body text

### 0.7.7 Validation Gates

Eight validation gates must be passed:

| Gate | Description | Pass Condition |
|------|-------------|----------------|
| Gate 1 | End-to-End Boundary Verification | Rust binary accepts SMTP, delivers to mailbox (swaks → 250 OK) |
| Gate 2 | Zero-Warning Build | `RUSTFLAGS="-D warnings"` + `cargo clippy -- -D warnings` + `cargo fmt --check` = zero diagnostics |
| Gate 3 | Performance Baseline | All 4 metrics measured and within thresholds |
| Gate 4 | Named Real-World Validation | swaks local delivery + remote TLS relay both succeed |
| Gate 5 | API/Interface Contract | CLI, SMTP EHLO, config parse, spool compat, log format all identical |
| Gate 6 | Unsafe/Low-Level Audit | Zero unsafe outside exim-ffi, total count < 50, all documented |
| Gate 7 | Prompt Tier / Scope Matching | Extended tier specification applied |
| Gate 8 | Integration Sign-Off | Live smoke test + API contract + performance baseline + unsafe audit |


## 0.8 References


### 0.8.1 Repository Files and Folders Searched

The following files and directories were comprehensively explored to derive the conclusions in this Agent Action Plan:

**Root Level:**
- `.editorconfig` — Editor configuration (indent rules, line endings)
- `.gitattributes` — Git merge policy for documentation files
- `README.md` — Repository orientation and canonical URL redirect
- `SECURITY.md` — Security policy and disclosure process

**Source Tree (`src/`):**
- `src/Makefile` — Top-level build orchestration (142 lines, fully read)
- `src/conf` — Perl integration configuration
- `src/.gitattributes` — Encoding hint for ACKNOWLEDGMENTS
- `src/src/` — Core MTA C source directory (107 files examined via folder listing)
- `src/src/globals.c` — Global variable definitions (partial read, lines 1–80)
- `src/src/globals.h` — Global variable declarations (partial read, lines 1–60)
- `src/src/store.h` — Memory allocator header (fully read, 93 lines — 5 pool types + taint)
- `src/src/auths/` — 9 authenticator drivers (26 files cataloged)
- `src/src/routers/` — 7 router drivers + 10 helpers (25 files cataloged)
- `src/src/transports/` — 6 transport drivers + maildir helper (14 files cataloged)
- `src/src/lookups/` — 25+ lookup backends + 3 helpers (26 files cataloged)
- `src/src/miscmods/` — 20+ policy/auth/filter modules (34 files cataloged)
- `src/src/miscmods/pdkim/` — In-tree PDKIM library (6 files cataloged)
- `src/src/hintsdb/` — 5 hints DB backend headers (5 files cataloged)
- `src/src/utils/` — 13 Perl utility script templates (cataloged — preserved, not rewritten)
- `src/util/` — 10 standalone admin/developer tools (cataloged — preserved)
- `src/scripts/` — 3 POSIX shell build helper scripts (cataloged — preserved)
- `src/exim_monitor/` — X11 GUI source (noted as excluded from scope)

**Test Tree (`test/`):**
- `test/` — Test harness root (8 subdirectories cataloged)
- `test/aux-fixed/` — Fixed byte-stable auxiliary fixtures
- `test/src/` — Standalone test helper programs (C, Perl, shell)
- `test/dnszones-src/` — Fake DNS zone sources
- `test/mail/` — Raw email corpus and mailbox fixtures
- `test/t/` — Perl TAP entrypoints
- `test/lib/` — Perl test support library (Exim::Runtest, Exim::Utils)
- `test/aux-var-src/` — Template-driven fixtures

**Other Directories:**
- `doc/` — Documentation tree (4 subdirectories cataloged)
- `configs/` — System integration guidance (1 subdirectory cataloged)
- `.github/` — Issue and PR templates (2 files cataloged)

### 0.8.2 Technical Specification Sections Retrieved

| Section | Content Used For |
|---------|-----------------|
| 1.1 Executive Summary | Project overview, version (4.99), license (GPL-2.0-or-later), stakeholder context |
| 1.3 Scope | In-scope features, implementation boundaries, exclusions |
| 3.1 Programming Languages | C99+ as core language, Perl test/admin role, POSIX shell build |
| 3.2 Frameworks & Libraries | PCRE2 hard dependency, TLS backends, auth libraries, lookup libraries, PDKIM |
| 3.3 Open Source Dependencies | Hard/optional dependencies, version constraints, dynamic module loading |
| 5.1 High-Level Architecture | System overview, core components, data flow, integration points |
| 5.2 Component Details | Daemon architecture, router/transport/auth/lookup/hints subsystems |

### 0.8.3 External Research Conducted

| Topic | Source | Key Finding |
|-------|--------|-------------|
| Rust crate versions | crates.io API | bumpalo 3.20.2, inventory 0.3.22, rustls 0.23.37, rusqlite 0.38.0, redis 1.0.5, tokio 1.50.0, clap 4.5.60, and 20+ additional crates verified |
| reveal.js CDN | jsdelivr.net | Version 5.1.0 available for self-contained HTML presentations |
| hyperfine | crates.io | Version 1.20.0 for binary-level benchmark timing |
| hickory-resolver | crates.io | Version 0.25.0 stable (0.26.0-alpha.1 pre-release exists) |

### 0.8.4 Attachments

No Figma screens or external attachments were provided with this specification. All source material derives from the user prompt, repository inspection, and crate version verification via the crates.io API.