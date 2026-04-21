# Blitzy Project Guide — Exim C-to-Rust Migration

---

## 1. Executive Summary

### 1.1 Project Overview

This project implements a complete tech-stack migration of the Exim Mail Transfer Agent (v4.99) from C to Rust — rewriting 182,614 lines of C across 242 source files into a Cargo workspace of 17 Rust crates that produces a functionally-equivalent `exim` binary. The rewrite eliminates all manual memory management (440 allocation call sites across 5 pool types), eradicates 714 global mutable variables, replaces 1,677 preprocessor conditionals with Cargo feature flags, and introduces compile-time taint tracking. The target users are mail-server administrators and ISPs running Exim in production. The business impact is a memory-safe MTA binary that eliminates the entire class of use-after-free, buffer-overflow, and double-free vulnerabilities that have historically affected C-based Internet infrastructure daemons.

### 1.2 Completion Status

```mermaid
pie title Project Completion — 67.9%
    "Completed (760h)" : 760
    "Remaining (360h)" : 360
```

| Metric                                | Value     |
|---------------------------------------|-----------|
| **Total Project Hours**               | 1,120     |
| **Completed Hours (AI)**              | 760       |
| **Completed Hours (Manual)**          | 0         |
| **Remaining Hours**                   | 360       |
| **Completion Percentage**             | **67.9%** |

**Formula**: 760 completed hours / (760 + 360) total hours = 760 / 1,120 = **67.9% complete**

*(Color reference: Completed = Dark Blue `#5B39F3`; Remaining = White `#FFFFFF`.)*

### 1.3 Key Accomplishments

- ✅ All 17 Rust crates implemented and compile cleanly (190 source files, ~250,769 lines of Rust)
- ✅ 2,898 unit tests passing with zero failures across all 17 crates; 39 tests intentionally ignored (missing C FFI libs)
- ✅ Zero-warning build: `RUSTFLAGS="-D warnings"` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all --check` all pass
- ✅ ~165 MB debug-profile `exim` binary produced; `exim -bV`, `exim -bP`, `exim --help` all run successfully against `src/src/configure.default` (44 KB)
- ✅ 714 global variables replaced with 4 scoped context structs (`ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`)
- ✅ Custom 5-pool stacking allocator replaced with `bumpalo::Bump` per-message arenas, `Arc<Config>` frozen config, and explicit-clear `HashMap` lookup cache
- ✅ All 1,677 C preprocessor conditionals replaced with Cargo feature flags (workspace-wide)
- ✅ Compile-time taint tracking via `Tainted<T>` / `Clean<T>` newtypes (zero runtime cost)
- ✅ Trait-based driver system (`AuthDriver`, `RouterDriver`, `TransportDriver`, `LookupDriver`) with `inventory::submit!` compile-time registration
- ⚠️ `exim-miscmods` structural scaffolding complete (DKIM, ARC, DMARC, SPF, Sieve, exim-filter, proxy, socks, xclient, pam, radius, perl, dscp) — **crypto and DNS callbacks stubbed; see Phase 5 caveats in Section 1.4**
- ✅ `exim-ffi` isolates 53 `unsafe` blocks to the only crate permitted to have them (other crates carry `#![forbid(unsafe_code)]`)
- ✅ Build system extension: `make rust` and `clean_rust` targets added to `src/Makefile` (clean_rust integrated into `distclean`)
- ✅ Benchmarking script `bench/run_benchmarks.sh` (1,388 lines) and report `bench/BENCHMARK_REPORT.md` (148 lines) delivered
- ✅ Executive presentation `docs/executive_presentation.html` (245 lines, 14 reveal.js slides) delivered
- ✅ Zero test files modified in `test/` directory — preservation boundary from AAP §0.3.2 respected
- ✅ GitHub Actions CI workflow (`.github/workflows/ci.yml`, 95 lines) enforces fmt / clippy / test / release-build gates

### 1.4 Critical Unresolved Issues

| Issue                                                                                                                                                                 | Impact                                                                                  | Owner              | ETA              |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|--------------------|------------------|
| **Phase 5 P1 CRITICAL** — DKIM `crypto_sign()` / `crypto_verify()` stubs return empty / unconditional `true`; DKIM DNS TXT callback hardcoded to `None`               | All outbound DKIM signatures malformed; all inbound DKIM verifications return temperror | Human Developer    | 2–3 weeks        |
| **Phase 5 P1 CRITICAL** — DMARC FFI DNS lookup stubbed; SPF DNS hook trampoline not wired; ARC cascade-fails on DKIM stubs                                            | Mail-authentication verdicts are synthetic — blocks DMARC-enforcing deployments         | Human Developer    | 2 weeks          |
| **Phase 5 P1 CRITICAL** — Sieve `sieve_interpret` public API missing; Sieve `reject`/`ereject`/`setflag`/`addflag`/`removeflag`/`hasflag`/`mark`/`unmark` undispatched | Sieve filter scripts using these commands fail at parse or execution                    | Human Developer    | 1–2 weeks        |
| **AAP §0.7.1** — 142 test-script directories (1,205 files) not executed via `test/runtest`                                                                            | Primary AAP acceptance criterion UNMET; behavioral parity unvalidated                   | Human Developer    | 3–4 weeks        |
| **AAP §0.7.5** — All 4 performance benchmarks DEFERRED (throughput, fork latency, RSS, config parse); "Assumed parity is NOT acceptable" clause violated              | Gate 3 / Gate 4 / Gate 8 FAIL; performance parity unconfirmed                           | Human Developer    | 1 week           |
| **AAP §0.7.2** — `unsafe` block count is 53, AAP limit is 50 (exceeds by 3)                                                                                           | Gate 6 PARTIAL; unsafe-audit escape clause unverified                                   | Human Developer    | 2–3 days         |
| **Phase 5 CRITICAL correctness** — retry `senders:` filter ignored, IPv6 retry-key parser truncates at first `:`, bounce DSN leaks `Bcc:` header, Sieve `:count` hardcoded to 1, DMARC native `pct=` sampling not applied, SPF `SPF_server_set_rec_dom` not called, DMARC FFI PSL uses naive `splitn(2, '.')` | Correctness bugs in retry scheduling, DSN privacy, and SPF / DMARC evaluation           | Human Developer    | 3–5 days         |
| **Phase 6 P1 FACTUAL** — Executive presentation slides 10 / 13 / 14 claim "Migration complete", "1,205 tests passing", "All metrics within target limits"             | Misinformation risk for C-suite audience consuming the deck                             | Presentation Owner | 2 hours          |
| End-to-end SMTP delivery not tested with live mail flow                                                                                                               | Wire-protocol parity (RFC 5321 / 6531 / 3207 / 8314 / 7672) unconfirmed                 | Human Developer    | 1 week           |
| Spool-file byte-level compatibility not verified (C↔Rust cross-version queue flush)                                                                                   | Cross-version migration path unproven                                                   | Human Developer    | 3–5 days         |

### 1.5 Access Issues

| System / Resource         | Type of Access      | Issue Description                                                                                                                  | Resolution Status                            | Owner              |
|---------------------------|---------------------|------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|--------------------|
| Benchmark tooling         | CLI tools           | `hyperfine`, `swaks`, `jq`, `/usr/bin/time -v` not installed in validation environment                                             | Unresolved — requires `apt-get install`      | DevOps             |
| Exim test harness         | Environment config  | `test/runtest` needs Perl modules, dedicated `exim` user / group, TLS test certificates, fake-DNS zone files, and a C-Exim baseline | Unresolved — requires environment provisioning | Human Developer    |
| C-Exim reference binary   | Build artifact      | `src/Local/Makefile` not authored; no `build-<osname>/` tree; C comparison binary cannot be produced for side-by-side benchmarks   | Unresolved — requires authoring `Local/Makefile` per Exim docs | DevOps             |
| FFI system libraries      | System packages     | `libpam`, `libradiusclient`, `libgsasl`, `libkrb5` (Heimdal), `libspf2`, `libperl`, `libdb` (BDB), `libgdbm`, `libtdb`, `libndbm` not installed; 39 unit tests ignore FFI-dependent paths | Unresolved — requires per-feature `apt-get install` for full-coverage testing | DevOps             |
| Production mail-flow test | Network + MX record | Live outbound test requires a DNS-resolvable sender domain, SPF-aligned MX, and TLS certificate                                    | Unresolved — requires staging DNS + cert provisioning | Human Developer    |

### 1.6 Recommended Next Steps

1. **[High]** Implement DKIM RSA-PKCS1v1.5 / RSA-PSS / Ed25519 signing and verification (findings S1, S2) and wire DKIM DNS TXT callback (finding D1). Without these, all cascade findings A1 / A2 / A3 (ARC) and T1 / T2 (DKIM transport) remain broken. `exim-miscmods/src/dkim/pdkim/signing.rs` + `exim-miscmods/src/dkim/mod.rs`.
2. **[High]** Wire DMARC FFI DNS callback (finding DM1, `exim-miscmods/src/dmarc.rs`) and SPF DNS hook trampoline (finding SP1, `exim-miscmods/src/spf.rs` + `exim-ffi/src/spf.rs`) so mail-authentication verdicts stop being synthetic.
3. **[High]** Implement the missing Sieve `reject` / `ereject` / `setflag` / `addflag` / `removeflag` / `hasflag` / `mark` / `unmark` command parsers and dispatchers (finding SV4), and widen `sieve_interpret` return type to `(SieveResult, Vec<GeneratedAction>)` (finding SV1). `exim-miscmods/src/sieve_filter.rs`.
4. **[High]** Provision the `test/runtest` environment (Perl modules, `exim` user / group, fake-DNS zones, TLS test certs, C-Exim baseline binary) and execute all 142 test-script directories against `target/release/exim` — this is the AAP's primary acceptance gate (§0.7.1).
5. **[High]** Install `hyperfine 1.20.0+`, `swaks`, and `jq`; build the C-Exim reference binary; run `bench/run_benchmarks.sh` to produce all 4 performance metrics (throughput, fork latency, RSS, config parse) and satisfy AAP §0.7.5 Gate 3.
6. **[Medium]** Fix the 7 Phase 5 CRITICAL correctness bugs (R1 retry senders-filter, R2 IPv6 retry-key, B1 Bcc DSN leak, SV3 Sieve `:count`, DN1 DMARC native `pct=`, SP2 SPF `rec_dom`, DM2 DMARC FFI PSL) before the integration test sweep — these bugs are high-probability test-failure drivers.
7. **[Medium]** Reduce `unsafe` block count in `exim-ffi` from 53 to < 50 (AAP §0.7.2 Gate 6) by consolidating equivalent FFI wrappers; document each remaining block with a SAFETY comment and a unit-test exercising the unsafe boundary.
8. **[Medium]** Correct the 4 factual claims on executive presentation slides 10 / 13 / 14 (`docs/executive_presentation.html`) before external distribution; either defer / qualify the claims or withhold the deck until the supporting evidence is in hand.

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component                                                          | Hours | Description                                                                                                                                                         |
|--------------------------------------------------------------------|------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Workspace Setup & Configuration                                    |    12 | Root `Cargo.toml` (17-member workspace), `rust-toolchain.toml`, `.cargo/config.toml` (`RUSTFLAGS="-D warnings"`), `.github/workflows/ci.yml` CI pipeline             |
| **exim-core** crate (8 files, ~15,886 lines)                       |    48 | Binary entry point (`main.rs`), daemon poll-event loop, queue runner, CLI (clap 4.5.60), signal handling, fork/exec process management, operational modes, 4 context structs |
| **exim-config** crate (7 files, ~12,436 lines)                     |    36 | Configuration parser, option-list processing, macro / `.include` / `.ifdef` expansion, driver instantiation, `-bP` validation, `ConfigContext` types                  |
| **exim-expand** crate (12 files, ~26,229 lines)                    |    64 | `${...}` DSL engine: tokenizer, AST parser, evaluator, variable substitution, ${if}, ${lookup}, 50+ transform operators, ${run}, ${dlfunc}, ${perl}, debug-trace    |
| **exim-smtp** crate (12 files, ~16,723 lines)                      |    44 | Inbound SMTP state machine (PIPELINING, CHUNKING/BDAT, PRDR, ATRN); outbound connection management, parallel delivery, STARTTLS, response parsing                   |
| **exim-deliver** crate (8 files, ~15,242 lines)                    |    40 | Per-recipient orchestrator, router-chain evaluation, transport dispatch, subprocess pool, retry scheduling + hints DB, bounce / DSN generation, journal & crash recovery |
| **exim-acl** crate (6 files, ~10,443 lines)                        |    28 | ACL evaluation engine, 7 verbs (accept/deny/defer/discard/drop/require/warn), condition evaluation, 8+ SMTP phases, ACL variable management                           |
| **exim-tls** crate (8 files, ~10,383 lines)                        |    28 | `TlsBackend` trait, `rustls` 0.23.37 backend (default), optional `openssl` 0.10.75 backend, DANE/TLSA, OCSP stapling, SNI, client-cert verify, session cache         |
| **exim-store** crate (6 files, ~4,138 lines)                       |    16 | `bumpalo::Bump` per-message arena, `Arc<Config>` frozen store, explicit-clear `HashMap` search cache, scoped `MessageStore`, `Tainted<T>` / `Clean<T>` newtypes       |
| **exim-drivers** crate (6 files, ~5,867 lines)                     |    16 | `AuthDriver` / `RouterDriver` / `TransportDriver` / `LookupDriver` trait definitions; `inventory::submit!` compile-time registration replacing `drtables.c`          |
| **exim-auths** crate (14 files, ~13,749 lines)                     |    36 | 9 auth drivers (CRAM-MD5, Cyrus SASL, Dovecot, EXTERNAL, GSASL, Heimdal GSSAPI, PLAIN/LOGIN, SPA/NTLM, TLS-cert); base64 I/O, server-condition, saslauthd helpers; CWE-208 timing-safe SPA fixed with `subtle::ConstantTimeEq` |
| **exim-routers** crate (18 files, ~19,695 lines)                   |    44 | 7 router drivers (accept, dnslookup, ipliteral, iplookup, manualroute, queryprogram, redirect); 9 shared `rf_*` helper modules                                       |
| **exim-transports** crate (8 files, ~14,344 lines)                 |    36 | 6 transport drivers (appendfile/mbox/MBX/Maildir, autoreply, LMTP, pipe, queuefile, SMTP state machine at 3,058 lines); Maildir quota / directory helper             |
| **exim-lookups** crate (27 files, ~25,453 lines)                   |    52 | 22 lookup backends (CDB, DBM, DNS, dsearch, JSON, LDAP, LMDB, lsearch, MySQL, NIS, NIS+, NMH, Oracle, passwd, PostgreSQL, PSL, readsock, Redis, SPF, SQLite, testdb, Whoson); 3 helpers |
| **exim-miscmods** crate (18 files, ~29,243 lines) — *structural scaffolding complete; crypto / DNS callbacks stubbed (see Section 1.4)* | 40 | DKIM verify/sign + PDKIM parser, ARC, SPF, DMARC + native parser, Exim-filter interpreter, Sieve filter, HAProxy PROXY v1/v2, SOCKS5, XCLIENT, PAM, RADIUS, Perl, DSCP |
| **exim-dns** crate (3 files, ~4,893 lines)                         |    16 | DNS resolver (A / AAAA / MX / SRV / TLSA / PTR) via `hickory-resolver` 0.25.0; DNSBL checking                                                                        |
| **exim-spool** crate (5 files, ~7,195 lines)                       |    20 | Spool `-H` header file read/write, `-D` data file read/write, base-62 message-ID generation, format constants                                                         |
| **exim-ffi** crate (24 files, ~16,975 lines)                       |    44 | FFI bindings (libpam, libradiusclient, libperl, libgsasl, libkrb5/Heimdal, libspf2, 4 hintsdb backends BDB/GDBM/NDBM/TDB, cyrus_sasl, NIS, NIS+, Oracle, Whoson, DMARC, LMDB); 53 `unsafe` blocks, all with SAFETY comments |
| Build-System Extension (`src/Makefile`)                            |     2 | `rust:` target invokes `cargo build --release`; `clean_rust:` invokes `cargo clean`; integrated into `distclean`                                                     |
| Benchmarking Script (`bench/run_benchmarks.sh`)                    |     8 | 1,388-line shell script measuring 4 metrics with `hyperfine`, structured JSON output, system-spec capture                                                            |
| Benchmark Report (`bench/BENCHMARK_REPORT.md`)                     |     4 | 148-line template: side-by-side tables, methodology, system specs (report is a *template* — needs real measurements to satisfy AAP §0.7.5)                            |
| Executive Presentation (`docs/executive_presentation.html`) — *structural HTML complete; slides 10 / 13 / 14 flagged for factual corrections* | 6 | Self-contained reveal.js 5.1.0 deck, 14 slides: Why, What Changed, Architecture, Performance, Security, Risk, Timeline                                              |
| Unit Test Suite                                                    |    80 | 2,898 tests across 17 crates; 100% pass; covers parsers, protocol state machines, drivers, trait implementations                                                     |
| Code-Review Fixes & Performance Optimizations                      |    28 | Multi-round fixes: CWE-208 timing fix, 4 clippy blockers, 31 clippy-all-targets cleanups, REWRITE flag bitmask bug, 5 performance directives (DnsResolver reuse, `Arc` wrapping, cached mainlog, spool-dir init, poll-based sleep) |
| Zero-Warning Build & Quality Gates                                 |     4 | `RUSTFLAGS="-D warnings"`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all --check`; all three exit 0                                                    |
| Partial API / Gate Validation                                      |     8 | `exim -bV` version output verified; `exim -bP` prints full config from `src/src/configure.default` (44 KB); CLI `--help` coverage confirmed                          |
| **Total Completed**                                                | **760** | |

### 2.2 Remaining Work Detail

| Category                                                                                                              | Hours | Priority  |
|-----------------------------------------------------------------------------------------------------------------------|------:|-----------|
| **Phase 5 P1 CRITICAL Crypto & DNS Remediation** (DKIM RSA/Ed25519 sign & verify, DKIM DNS TXT callback, DMARC FFI DNS callback, SPF DNS hook FFI trampoline, Sieve `sieve_interpret` API widening, Sieve `reject`/`ereject`/`setflag`/`addflag`/`removeflag`/`hasflag`/`mark`/`unmark` command parsers & dispatchers, Exim-filter `mail`/`vacation` enqueue wiring, Sieve `vacation`/`notify` enqueue wiring, DKIM per-transport option dispatch T2) | 120 | High      |
| **Phase 5 CRITICAL Correctness Bug Fixes** (SV3 Sieve `:count` hardcoded to 1; DN1 DMARC native `pct=` RNG sampling; DM2 DMARC FFI PSL via `psl` crate; SP2 SPF `SPF_server_set_rec_dom` FFI binding; R1 retry `senders:` filter honor; R2 retry-key IPv6 bracketing; B1 bounce DSN `Bcc:` strip) | 16 | High      |
| **Integration Test Suite Validation** (142 test-script directories, 1,205 test files executed via `test/runtest`; includes environment provisioning, iterative failure triage, fix, re-run) | 120 | High      |
| **E2E SMTP Delivery & Protocol Validation** (swaks local delivery + remote TLS relay; wire-format RFC 5321/6531/3207/8314/7672 compliance) | 16 | High      |
| **API / Interface Contract Verification** (CLI flag comparison, log format `exigrep` / `eximstats` parseability, EHLO capability advertisement, exit-code mapping) | 20 | High      |
| **Performance Benchmarking & Report** (install `hyperfine` / `swaks` / `jq`; build C-Exim reference; run 4 metrics; fill `bench/BENCHMARK_REPORT.md`; tune if any metric outside threshold) | 20 | Medium    |
| **Spool File Byte-Level Compatibility Verification** (C-Exim writes `-H`/`-D` ↔ Rust-Exim reads; Rust-Exim writes ↔ C-Exim reads; cross-version queue flush test) | 8 | Medium    |
| **Unsafe Block Reduction** (53 → < 50 in `exim-ffi`; consolidate equivalent wrappers; add a unit test exercising each boundary per AAP §0.7.2 escape clause) | 4 | Medium    |
| **Executive Presentation Factual Corrections** (slides 10 / 13 / 14 — qualify "Migration complete" to "Structural code complete"; replace "1,205 tests passing" with "2,898 unit tests passing, integration harness deferred"; replace "All metrics within target limits" with "Performance benchmarks deferred") | 2 | High      |
| **Project Guide Documentation Corrections** (PG-1 add 6 Phase 5 rows to Risk Assessment; PG-2 rename stage to "Partial Code Complete — Authentication Stack and Integration Pending"; PG-3 `exim-miscmods` ✅ → ⚠️; PG-4 promote crypto remediation to positions 1-6 of Next Steps) — **resolved by this document release** | 4 | Medium    |
| **Production Deployment Readiness** (Debian / RHEL packaging, systemd unit file, logrotate config, AppArmor / SELinux profile, migration runbook) | 14 | Medium    |
| **Security Audit** (FFI-boundary review, crypto-backend comparison, SMTP header-injection fuzzing, TLS-backend interop, taint-tracking escape analysis) | 12 | Medium    |
| **Documentation Finalization** (top-level README update, INSTALL.md, CHANGELOG.md, migration notes for v4.98 → v4.99-Rust) | 4 | Low       |
| **Total Remaining** | **360** | |

### 2.3 Hours Verification

- Section 2.1 Total (Completed): **760 hours**
- Section 2.2 Total (Remaining): **360 hours**
- Sum: 760 + 360 = **1,120 hours** = Total Project Hours in Section 1.2 ✓
- Completion: 760 / 1,120 = **67.9%** ✓

---

## 3. Test Results

All tests below originate from Blitzy's autonomous validation logs for this project (`cargo test --workspace --no-fail-fast`, captured at HEAD `bb25bb49f`). Coverage percentages are not populated because `cargo tarpaulin` / `llvm-cov` were not executed in the autonomous validation run; per-crate unit-test counts are the primary evidence of library health.

| Test Category                       | Framework              | Total Tests | Passed | Failed | Coverage % | Notes                                                                                                          |
|-------------------------------------|------------------------|-------------|--------|--------|------------|----------------------------------------------------------------------------------------------------------------|
| Unit Tests — `exim-acl`             | `cargo test`           | 137         | 137    | 0      | —          | ACL engine, 7 verbs, conditions, 8 phases, variables                                                            |
| Unit Tests — `exim-auths`           | `cargo test`           | 116         | 116    | 0      | —          | 9 auth drivers + helpers; CWE-208 SPA timing fix via `subtle::ConstantTimeEq` validated                         |
| Unit Tests — `exim-config`          | `cargo test`           | 133         | 133    | 0      | —          | Parser, option lists, macros, includes, driver init, `-bP` printing                                            |
| Unit Tests — `exim-core` (binary)   | `cargo test`           | 188         | 188    | 0      | —          | CLI, daemon, queue runner, signal, process, modes, 4 context structs                                            |
| Unit Tests — `exim-deliver`         | `cargo test`           | 111         | 111    | 0      | —          | Orchestrator, routing, transport dispatch, retry, bounce, journal                                               |
| Unit Tests — `exim-dns`             | `cargo test`           | 59          | 59     | 0      | —          | Resolver (A/AAAA/MX/SRV/TLSA/PTR), DNSBL                                                                         |
| Unit Tests — `exim-drivers`         | `cargo test`           | 134         | 134    | 0      | —          | Trait definitions, `inventory` registry                                                                         |
| Unit Tests — `exim-expand`          | `cargo test`           | 303         | 303    | 0      | —          | Tokenizer, parser, evaluator, 50+ operators, variables, conditions, lookups bridge                              |
| Unit Tests — `exim-ffi`             | `cargo test`           | 12          | 12     | 0      | —          | FFI binding validation; 39 FFI-dependent cases across the workspace are ignored when C libs are absent          |
| Unit Tests — `exim-lookups`         | `cargo test`           | 277         | 277    | 0      | —          | 22 backends + helpers                                                                                           |
| Unit Tests — `exim-miscmods`        | `cargo test`           | 213         | 213    | 0      | —          | DKIM / ARC / SPF / DMARC / filters / proxy scaffolding; crypto-stub tests return synthetic values (see §1.4)    |
| Unit Tests — `exim-routers`         | `cargo test`           | 413         | 413    | 0      | —          | 7 routers + 9 helpers                                                                                           |
| Unit Tests — `exim-smtp`            | `cargo test`           | 150         | 150    | 0      | —          | Inbound state machine, PIPELINING, CHUNKING, PRDR, ATRN; outbound connection, parallel dispatch                |
| Unit Tests — `exim-spool`           | `cargo test`           | 157         | 157    | 0      | —          | `-H` / `-D` read/write, message-ID, format                                                                      |
| Unit Tests — `exim-store`           | `cargo test`           | 119         | 119    | 0      | —          | Arena, config store, search cache, message store, taint                                                         |
| Unit Tests — `exim-tls`             | `cargo test`           | 95          | 95     | 0      | —          | `TlsBackend` trait, rustls + openssl backends, DANE, OCSP, SNI, session cache                                   |
| Unit Tests — `exim-transports`      | `cargo test`           | 187         | 187    | 0      | —          | 6 drivers + Maildir helper                                                                                      |
| Doc Tests (aggregated across 17 crates) | `cargo test` (doc)  | 133         | 94     | 0      | —          | 94 doc-tests executed; 39 intentionally ignored (FFI-library-dependent examples)                                |
| Static Analysis — clippy            | `cargo clippy --workspace -- -D warnings` | — | — | 0 | — | Zero diagnostics across 17 crates                                                                               |
| Formatter — rustfmt                 | `cargo fmt --all -- --check` | — | — | 0 | — | Zero formatting issues across 190 Rust source files                                                              |
| Release Build                       | `cargo build --release --workspace` | — | — | 0 | — | Zero-warning release build (verified on HEAD with `RUSTFLAGS="-D warnings"`)                                   |
| **Totals**                          |                        | **2,898**   | **2,898** | **0** | —      | 39 tests intentionally ignored (FFI lib dependencies); **0 failed**                                             |

**AAP-scoped integration tests NOT executed** (outside autonomous validation scope — flagged as remaining work):

| Test Category                         | Framework          | Total Tests | Passed | Failed | Coverage % | Notes                                                                                          |
|---------------------------------------|--------------------|-------------|--------|--------|------------|------------------------------------------------------------------------------------------------|
| Perl `test/runtest` Harness           | Perl TAP           | 1,205 files in 142 dirs | N/A | N/A | —  | Not executed — requires dedicated `exim` user / group, TLS certs, fake-DNS zones, C-Exim baseline |
| 14 C Test Programs in `test/src/`     | native C           | 14          | N/A    | N/A    | —          | Not executed — requires `test/` Makefile invocation                                             |
| Performance Benchmarks (4 metrics)    | `hyperfine` + custom SMTP | 4 runs | N/A | N/A | —        | Not executed — `hyperfine` / `swaks` / `jq` / C-Exim reference binary not installed             |

---

## 4. Runtime Validation & UI Verification

### Runtime Health

- ✅ Operational — `cargo build --workspace` produces `target/debug/exim` (~165 MB) with zero warnings (release profile would produce ~11 MB with LTO enabled)
- ✅ Operational — `target/debug/exim -C src/src/configure.default -bV` prints `Exim version 4.99 #0 built 21-Apr-2026 ...` with `(Rust rewrite)` tag and full feature list
- ✅ Operational — `target/debug/exim -C src/src/configure.default -bP` prints all configuration options from the 44 KB default config (acl_*, accept_8bitmime, etc.)
- ✅ Operational — `target/debug/exim --help` displays correct CLI usage with `-b*`, `-d`, `-f`, `-M*`, `-N`, `-q`, `-C`, `-t`, `-v` flag families
- ✅ Operational — Feature advertisement: `crypteq`, `IPv6`, `rustls`, `TLS_resume`, `DNSSEC`, `ESMTP_Limits`, `Event`, `OCSP`, `PIPECONNECT`, `PRDR`, `Queue_Ramp`, `SRS`
- ✅ Operational — Lookup registration: 14 lookup types registered at startup (`nwildlsearch`, `lsearch`, `wildlsearch`, `iplsearch`, `dsearch`, `testdb`, `passwd`, `dnsdb`, dbm variants, `cdb`)
- ✅ Operational — Auth driver registration: `PLAIN/LOGIN`, `CRAM-MD5` (structural; other 7 drivers gated behind features and require FFI libs)
- ✅ Operational — Router registration: 7 routers (`ipliteral`, `dnslookup`, `redirect`, `iplookup`, `accept`, `queryprogram`, `manualroute`)
- ✅ Operational — Transport registration: 5 transports (`autoreply`, `smtp`, `pipe`, `lmtp`, `appendfile/maildir`)
- ⚠ Partial — TLS support compiled in (rustls backend, OCSP, SNI, DANE all present) but not live-tested against real certificates
- ⚠ Partial — Mail-authentication (DKIM/DMARC/SPF/ARC/Sieve) structurally present but crypto / DNS callbacks stubbed; see §1.4
- ❌ Failing — Daemon mode (`exim -bd`) not tested in live environment (requires root + port 25 binding + socket accept loop under load)
- ❌ Failing — End-to-end SMTP delivery: no live mail flow through inbound → ACL → router → transport → spool → outbound chain
- ❌ Failing — 142 test-script directories via `test/runtest`: primary AAP acceptance criterion not executed

### API & Interface Contract Status

- ✅ Operational — All documented CLI flags present in `--help` output (cross-referenced against `src/src/exim.c:decode_command_line`)
- ✅ Operational — Binary exits cleanly (0) for valid operations; error exit codes mirror C Exim conventions in tested paths
- ⚠ Partial — Log format (`mainlog` / `rejectlog` / `paniclog`) implemented to match C Exim string layout but not side-by-side verified with an `exigrep` / `eximstats` round-trip
- ⚠ Partial — SMTP wire protocol EHLO capability list confirmed in code but not packet-captured on port 25
- ⚠ Partial — Spool file format (`-H` / `-D`) implemented byte-for-byte but not cross-version round-trip tested
- ❌ Failing — Cross-binary queue flush test (C writes spool, Rust reads; Rust writes spool, C reads) not executed

### UI (Executive Presentation) Verification

The `docs/executive_presentation.html` reveal.js deck was rendered and captured in three screenshots stored at `blitzy/screenshots/` (slides 01, 13, 14). **Factual discrepancies flagged by the autonomous review (Phase 6):**

- ⚠ Slide 10 — "Migration complete" claim contradicts §1.4 unresolved issues
- ⚠ Slide 13 — "1,205 tests passing" conflates unit tests (actually 2,898) with the integration harness (1,205 files, not executed)
- ⚠ Slide 14 — "All metrics within target limits" — all 4 performance thresholds were DEFERRED, not measured

The structural HTML, reveal.js integration, WCAG AA contrast, and jargon definitions were all verified; only the three factual claims on slides 10 / 13 / 14 need editorial correction.

---

## 5. Compliance & Quality Review

| AAP Requirement                                                           | Status      | Evidence                                                                                                  | Notes                                                                                       |
|---------------------------------------------------------------------------|-------------|-----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| 17-crate Rust workspace (AAP spec'd 18)                                   | ⚠ Partial   | All 17 crates listed in root `Cargo.toml`, all compile                                                    | AAP §0.4.1 listed 18 crates; delivered workspace consolidates to 17 (cosmetic deviation)     |
| Eliminate manual memory management                                        | ✅ Pass      | `exim-store`: bumpalo arena, Arc<Config>, explicit-clear HashMap                                          | Replaces all 5 C pool types from `store.c`                                                   |
| Eradicate global mutable state (714 vars)                                 | ✅ Pass      | `exim-core/src/context.rs`: 4 context structs                                                             | `ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`                         |
| Replace preprocessor conditionals (1,677)                                 | ✅ Pass      | Cargo feature flags throughout workspace; `exim-ffi` defaults to `[]`                                     | All feature-gated in driver crates                                                            |
| Compile-time taint tracking                                               | ✅ Pass      | `exim-store/src/taint.rs`: `Tainted<T>` / `Clean<T>`                                                      | Zero runtime cost newtypes                                                                    |
| Driver registration via `inventory`                                       | ✅ Pass      | `exim-drivers/src/registry.rs`                                                                            | `inventory::submit!` pattern across all driver crates                                         |
| Zero `unsafe` outside `exim-ffi`                                          | ✅ Pass      | `grep -E "^\s*unsafe\s*{" exim-*/src/` returns 0 hits outside `exim-ffi`                                  | Non-FFI crates carry `#![forbid(unsafe_code)]`                                               |
| `unsafe` block count < 50                                                 | ⚠ Partial   | 53 `unsafe` blocks in `exim-ffi`                                                                          | Exceeds AAP §0.7.2 limit by 3                                                                 |
| `RUSTFLAGS="-D warnings"` zero diagnostics                                | ✅ Pass      | Validation command `cargo build --release` exits 0                                                        | Enforced via `.cargo/config.toml`                                                             |
| `cargo clippy --workspace -- -D warnings` clean                           | ✅ Pass      | Clippy exits 0                                                                                             | 4 blocker findings from autonomous review were fixed in-place (CR bb25bb49f)                  |
| `cargo fmt --all --check` clean                                           | ✅ Pass      | `fmt` exits 0                                                                                              | Zero formatting drift                                                                         |
| Makefile extended (not replaced)                                          | ✅ Pass      | `make rust` target at `src/Makefile:100`; `clean_rust:` at `src/Makefile:122`                             | `distclean: clean_doc clean_rust` integrated                                                  |
| `tokio` scoped to lookup only                                             | ✅ Pass      | `tokio` appears only inside `exim-lookups` for `block_on` bridging                                        | Not used for daemon event loop                                                                |
| `Arc<Config>` frozen after parse                                          | ✅ Pass      | `exim-store/src/config_store.rs`                                                                           | Immutable config across threads                                                               |
| Benchmarking script delivered                                             | ✅ Pass      | `bench/run_benchmarks.sh` (1,388 lines)                                                                    | 4 metrics, hyperfine integration                                                              |
| Benchmark report delivered                                                | ⚠ Partial   | `bench/BENCHMARK_REPORT.md` (148 lines)                                                                    | Template only — real measurements deferred                                                    |
| Executive presentation delivered                                          | ⚠ Partial   | `docs/executive_presentation.html` (245 lines, 14 slides)                                                  | Slides 10 / 13 / 14 contain factual errors (Phase 6 P1 FACTUAL)                               |
| `test/` directory unmodified                                              | ✅ Pass      | 0 files changed in `test/`                                                                                 | Preservation boundary respected                                                               |
| `doc/` directory unmodified                                               | ✅ Pass      | 0 files changed in `doc/` (except `doc/index.md` deletion which is outside `doc/doc-*` scope)              | Preservation boundary respected                                                               |
| `src/src/utils/*.src` unmodified                                          | ✅ Pass      | 0 Perl utility files changed                                                                               | AAP §0.3.2 respected                                                                          |
| `src/exim_monitor/` unmodified                                            | ✅ Pass      | 0 X11 monitor files changed                                                                                | AAP §0.3.2 respected                                                                          |
| Mail-authentication crypto functional                                     | ❌ Fail      | `crypto_sign()` returns empty `Vec<u8>`; `crypto_verify()` returns `Ok(true)`; DKIM DNS callback returns `None`; DMARC FFI DNS stubbed; SPF DNS hook not wired | Phase 5 P1 CRITICAL findings S1, S2, D1, DM1, SP1                                              |
| Sieve filter complete                                                     | ❌ Fail      | `sieve_interpret` public API returns wrong type; `reject`/`ereject`/`setflag`/etc. undispatched           | Phase 5 P1 CRITICAL findings SV1, SV4                                                          |
| 142 test directories passing                                              | ❌ Fail      | Test harness not executed                                                                                  | AAP §0.7.1 primary acceptance gate                                                             |
| 14 C test programs passing                                                | ❌ Fail      | Not executed                                                                                               | AAP §0.7.1                                                                                     |
| Performance thresholds measured (4)                                       | ❌ Fail      | All 4 benchmarks DEFERRED                                                                                  | AAP §0.7.5 "Assumed parity is NOT acceptable" violated                                        |
| E2E SMTP delivery (Gate 1)                                                | ❌ Fail      | No live SMTP test                                                                                          | Requires daemon + swaks + TLS cert                                                             |
| Spool file byte-level compat                                              | ❌ Fail      | No cross-version test                                                                                      | Requires C-Exim reference binary                                                               |
| SMTP wire protocol verified                                               | ❌ Fail      | Not packet-captured                                                                                        | AAP §0.7.1 wire-protocol clause                                                                |
| CLI flags / exit codes / log format identical                             | ⚠ Partial   | Code implements parity; not side-by-side verified with C Exim                                              | Needs `exigrep` / `eximstats` round-trip                                                       |

**Autonomous fixes applied during 7-phase code review** (committed in `bb25bb49f`):

- Fixed 4 clippy blocker findings promoted to hard errors by `#![deny(clippy::all)]` (collapsible_match refactored to match guards)
- Fixed CWE-208 timing side-channel in `exim-auths/src/spa.rs` by introducing `subtle::ConstantTimeEq` for NTLM hash comparison
- Fixed 31 `cargo clippy --all-targets` warnings across 14 crates (field_reassign_with_default, default_constructed_unit_structs, clone_on_copy, single_match, unnecessary_get_then_check)
- Fixed REWRITE flag bitmask bug in `exim-config/parser.rs`, `options.rs`, `validate.rs`, `exim-core/modes.rs`, `context.rs` (sender/from/to/cc/bcc/envfrom flags were overwriting via `=` instead of OR-combining via `|=`)

---

## 6. Risk Assessment

| Risk                                                                                                             | Category     | Severity | Probability | Mitigation                                                                                                                  | Status |
|------------------------------------------------------------------------------------------------------------------|--------------|----------|-------------|-----------------------------------------------------------------------------------------------------------------------------|--------|
| DKIM `crypto_sign()` / `crypto_verify()` stubs cause outbound signature rejection and inbound `temperror`        | Technical / Security | Critical | Certain     | Implement RSA-PKCS1v1.5 / RSA-PSS / Ed25519 via `rsa` + `ed25519_dalek` crates; wire `exim_dns::resolver` into DKIM DNS TXT callback; fix S2 and D1 together to avoid fail-open downgrade | **Open** |
| DMARC FFI DNS callback stubbed → `NoPolicy` for every domain → DMARC enforcement effectively disabled            | Security     | Critical | Certain     | Replace stub with `exim_dns::resolver::Resolver::instance().txt_lookup(&format!("_dmarc.{domain}"))`; native DMARC backend (`dmarc_native.rs`) already uses `exim_dns` correctly         | **Open** |
| SPF DNS hook trampoline not wired — `libspf2` uses its own resolver, bypassing DNSSEC and test fixtures          | Security / Integration | Critical | Certain     | Extend `exim-ffi/src/spf.rs` with `SPF_server_set_dns_func` binding; write C-callable trampoline unboxing `DnsLookupFn`; ~200 lines of delicate unsafe FFI | **Open** |
| ARC signing / verification cascade-fails because of the DKIM stubs                                               | Security     | Critical | Certain     | Auto-resolved when S1 (sign) and S2 (verify) are implemented                                                                 | **Open** |
| Sieve `sieve_interpret` API doesn't expose `generated_actions` — orchestrator cannot deliver per-script intent    | Technical / Correctness | Critical | Certain     | Change return type to `Result<(SieveResult, Vec<GeneratedAction>), SieveError>` and update all callers                      | **Open** |
| Sieve `reject` / `ereject` / `setflag` / `addflag` / `removeflag` / `hasflag` / `mark` / `unmark` undispatched     | Technical / Correctness | Critical | Certain     | Implement ~500 lines across 8 commands; validate against RFC 5228 / 5429 / 6134 test vectors                                 | **Open** |
| Bounce DSN leaks `Bcc:` header (RFC 3464 §3 privacy violation)                                                    | Security / Privacy | High     | Certain     | Strip `Bcc:` from fetched headers before attaching to DSN (~5 lines in `exim-deliver/src/bounce.rs`)                         | **Open** |
| Retry `senders:` filter clause ignored — retry rules apply universally instead of sender-scoped                   | Technical    | High     | Certain     | Add sender-filter matching in rule-iteration loop (~20 lines in `exim-deliver/src/retry.rs`)                                 | **Open** |
| Retry-key IPv6 parser truncates at first `:` — IPv6 retry records misparsed                                       | Technical    | High     | Certain     | Bracket IPv6 addresses in retry-key format; parse brackets correctly on read (~30 lines)                                     | **Open** |
| Integration test failures reveal behavioral differences between C and Rust                                        | Technical    | Critical | High        | Budget 120h for test-driven debugging; prioritize SMTP protocol + config parsing tests; 7 Phase 5 correctness fixes should land first | Open   |
| Performance regression in hot paths (string expansion, SMTP I/O, DNS cache)                                       | Technical    | High     | Medium      | `bench/run_benchmarks.sh` is ready; 5 performance directives already applied (DnsResolver reuse, `Arc` wrapping, cached mainlog, spool-dir init, poll-based sleep); profile with `flamegraph` if needed | Open   |
| `unsafe` block count (53) exceeds AAP limit (50)                                                                  | Technical    | Medium   | Certain     | Consolidate FFI wrappers; all 53 already have `SAFETY:` comments; per AAP §0.7.2 escape clause each remaining block needs a unit test exercising the boundary | Open   |
| FFI library availability varies across deployment targets                                                         | Integration  | High     | Medium      | Feature-gated compilation; 39 tests already handle missing FFI deps gracefully                                               | Open   |
| Spool-format incompatibility could corrupt in-flight mail during C↔Rust migration                                 | Operational  | Critical | Low         | Byte-level format matching implemented; cross-version verification required before production                                | Open   |
| Missing SMTP edge cases (BDAT framing, PRDR multi-recipient, ATRN relay)                                          | Technical    | High     | Medium      | Code implemented but untested against real mail flow; integration tests will reveal gaps                                     | Open   |
| TLS certificate-handling differences between C OpenSSL and Rust rustls                                            | Security     | High     | Medium      | Both backends implemented; DANE / OCSP / SNI / session-cache all present; needs TLS interop testing                          | Open   |
| Log format changes break existing monitoring (`exigrep`, `eximstats`)                                             | Operational  | Medium   | Low         | Log format implemented to match C Exim; needs side-by-side comparison                                                        | Open   |
| Configuration parser rejects valid edge-case configs                                                              | Technical    | High     | Medium      | Parser handles `configure.default` (44 KB); needs testing with complex production configs                                   | Open   |
| Memory leak in arena allocator under sustained load                                                               | Technical    | Medium   | Low         | `bumpalo` arena dropped per-message; needs long-running soak test                                                            | Open   |
| Embedded Perl (`${perl}`) FFI stability under concurrent requests                                                 | Integration  | Medium   | Medium      | FFI wrapper implemented; needs stress testing with concurrent Perl eval                                                      | Open   |
| Executive-presentation factual claims (slides 10 / 13 / 14) reach C-suite before corrections are applied          | Operational  | Medium   | Low         | Do not distribute the deck until the three slides are corrected or qualified                                                 | Open   |

---

## 7. Visual Project Status

```mermaid
pie title Project Hours Breakdown
    "Completed Work" : 760
    "Remaining Work" : 360
```

**Completed Work: 760 hours (67.9%) | Remaining Work: 360 hours (32.1%)**

*(Color reference: Completed = Dark Blue `#5B39F3`; Remaining = White `#FFFFFF`.)*

### Remaining Hours by Category

| Category                                                  | Hours | Share  |
|-----------------------------------------------------------|------:|-------:|
| Phase 5 P1 CRITICAL Crypto & DNS Remediation              |   120 | 33.3%  |
| Integration Test Suite Validation (142 directories)       |   120 | 33.3%  |
| API / Interface Contract Verification                     |    20 |  5.6%  |
| Performance Benchmarking & Report                         |    20 |  5.6%  |
| Phase 5 CRITICAL Correctness Bug Fixes                    |    16 |  4.4%  |
| E2E SMTP Delivery & Protocol Validation                   |    16 |  4.4%  |
| Production Deployment Readiness                           |    14 |  3.9%  |
| Security Audit                                            |    12 |  3.3%  |
| Spool File Byte-Level Compatibility Verification          |     8 |  2.2%  |
| Unsafe Block Reduction (53 → < 50)                        |     4 |  1.1%  |
| Project Guide Documentation Corrections                   |     4 |  1.1%  |
| Documentation Finalization                                |     4 |  1.1%  |
| Executive Presentation Factual Corrections                |     2 |  0.6%  |
| **Total**                                                 | **360** | **100%** |

---

## 8. Summary & Recommendations

### Achievement Summary

The Exim C-to-Rust migration has reached **67.9% completion** (760 of 1,120 estimated total hours). Autonomous Blitzy agents delivered the full structural rewrite of all 17 Rust crates specified in the Agent Action Plan — 190 source files comprising approximately 250,769 lines of production Rust code spread across the `exim-core` / `exim-config` / `exim-expand` / `exim-smtp` / `exim-deliver` / `exim-acl` / `exim-tls` / `exim-dns` / `exim-spool` / `exim-store` / `exim-drivers` / `exim-auths` / `exim-routers` / `exim-transports` / `exim-lookups` / `exim-miscmods` / `exim-ffi` workspace. This delivery represents one of the most comprehensive C-to-Rust rewrites ever executed for production Internet infrastructure.

Quality gates that **were** satisfied: the entire workspace compiles under `RUSTFLAGS="-D warnings"`, passes `cargo clippy --workspace -- -D warnings` with zero diagnostics, passes `cargo fmt --all --check` with zero drift, and executes 2,898 unit tests with a 100% pass rate. The produced binary executes correctly for `-bV` version output, `-bP` configuration printing, and `--help` CLI discovery against the 44 KB `src/src/configure.default` reference configuration. All architectural invariants from AAP §0.4 are honored: 4 scoped context structs replace 714 globals, `bumpalo` arenas replace the 5-pool `store.c` allocator, `Cargo` features replace 1,677 preprocessor conditionals, `inventory` replaces `drtables.c`, `Tainted<T>` / `Clean<T>` newtypes enforce compile-time taint tracking, and `unsafe` blocks appear only in `exim-ffi`.

### Critical Gaps (Revised from Prior Guides)

This release includes material caveats uncovered by the autonomous 7-phase code review (`CODE_REVIEW.md`, 2,713 lines) that were not fully disclosed in earlier project-guide iterations:

1. **Mail-authentication stack is synthetic, not operational.** DKIM `crypto_sign()` returns empty `Vec<u8>`; DKIM `crypto_verify()` returns `Ok(true)`; DKIM DNS TXT callback is hardcoded to `None`; DMARC FFI DNS callback is stubbed; SPF DNS hook trampoline is not wired. ARC cascades on the DKIM stubs. Any deployment into a DMARC-enforcing environment is blocked until findings S1 / S2 / D1 / DM1 / SP1 (and cascades T1 / T2 / A1 / A2 / A3) are remediated.
2. **Sieve filter interpretation is incomplete.** `sieve_interpret` returns only `SieveResult`; `state.generated_actions` is never exposed to the delivery orchestrator. Eight Sieve commands (`reject`, `ereject`, `setflag`, `addflag`, `removeflag`, `hasflag`, `mark`, `unmark`) parse but never dispatch. Findings SV1 / SV4.
3. **Seven CRITICAL correctness bugs** exist in retry scheduling, bounce DSN privacy, Sieve `:count` matching, DMARC native `pct=` sampling, SPF macro expansion, and DMARC FFI PSL evaluation (findings SV3, DN1, DM2, SP2, R1, R2, B1). Combined remediation: ~16 hours.
4. **AAP §0.7.1 primary acceptance gate is UNMET.** The 142 test-script directories (1,205 test files) that constitute the behavioral parity contract have not been executed through `test/runtest` against the Rust binary.
5. **AAP §0.7.5 performance clause is violated.** All four performance thresholds (SMTP throughput, fork latency, peak RSS, config parse time) were DEFERRED; "Assumed parity is NOT acceptable" is stated in the AAP and is unmet.
6. **AAP §0.7.2 `unsafe` limit is exceeded by 3 blocks** (53 vs. limit of 50).

### Production-Readiness Assessment

The project is at a **"Partial Code Complete — Authentication Stack and Integration Pending"** stage. The codebase is structurally complete and unit-tested at the 2,898-test level, the binary compiles and boots, but the mail-authentication stack requires crypto / DNS remediation (~120 hours) and the 142-directory integration harness must be executed against the binary (~120 hours) before any production deployment can be contemplated. Current blockers, in descending order of severity:

1. DKIM / ARC / DMARC-FFI / SPF crypto & DNS remediation (P1 CRITICAL — 120h)
2. 142-directory integration test execution and triage (AAP §0.7.1 — 120h)
3. Phase 5 CRITICAL correctness bugs (16h)
4. Performance benchmark measurement (AAP §0.7.5 — 20h)
5. E2E SMTP wire-protocol testing (16h)
6. API / log / spool contract verification (20 + 8 = 28h)
7. `unsafe` count reduction (AAP §0.7.2 — 4h)

### Recommendations

1. **Week 1–2**: Engineering team implements findings S1, S2, D1 in `exim-miscmods/src/dkim/pdkim/signing.rs` and `exim-miscmods/src/dkim/mod.rs`. These three findings unblock the five cascades T1 / T2 / A1 / A2 / A3. Immediately after, implement DM1 (DMARC FFI DNS) and SP1 (SPF DNS hook trampoline).
2. **Week 2**: Implement the seven Phase 5 CRITICAL correctness fixes (~16h total). These are small but high-severity bugs; landing them before the integration sweep reduces triage cost.
3. **Week 2–4**: Provision the `test/runtest` environment (Perl modules, `exim` user / group, TLS test certs, fake-DNS zones) and build a C-Exim reference binary. Begin running the 142 directories in tranches; categorize failures; iteratively fix + re-run. Budget 120h.
4. **Week 3**: In parallel, install `hyperfine 1.20.0+` / `swaks` / `jq`; run `bench/run_benchmarks.sh` against both binaries; populate `bench/BENCHMARK_REPORT.md` with real measurements. Tune any metric that exceeds its threshold per AAP §0.7.5.
5. **Week 4**: Execute E2E SMTP delivery tests (swaks local + remote TLS relay), spool-file byte-compat round-trips, and log-format `exigrep` / `eximstats` parseability tests.
6. **Week 4–5**: Security audit pass (FFI boundary, crypto, SMTP header injection, TLS interop). Reduce `unsafe` block count from 53 to < 50 in `exim-ffi`.
7. **Week 5–6**: Production packaging (Debian + RHEL), systemd unit, logrotate config, AppArmor / SELinux profile, migration runbook. Finalize README, INSTALL, CHANGELOG.
8. **Before external distribution**: Correct the three factual claims on executive presentation slides 10 / 13 / 14.

Success metric: a clean `test/runtest` run against all 142 directories with zero test modifications, alongside performance thresholds published in `bench/BENCHMARK_REPORT.md` with numerical values inside AAP §0.7.5 bounds. On that basis the project moves from 67.9% complete to production-ready.

---

## 9. Development Guide

### 9.1 System Prerequisites

| Software       | Version       | Purpose                                                  |
|----------------|---------------|----------------------------------------------------------|
| Rust (stable)  | 1.80+ (pinned via `rust-toolchain.toml`; validated on 1.95.0) | Compiler + toolchain |
| Cargo          | matches Rust  | Build system and package manager                          |
| rustfmt        | stable        | Code formatting (included via `rust-toolchain.toml`)     |
| clippy         | stable        | Linting (included via `rust-toolchain.toml`)             |
| GCC or Clang   | any recent    | Required for `exim-ffi` C-library compilation             |
| `pkg-config`   | any           | FFI library discovery                                     |
| Perl 5.10+     | 5.10+         | Required for running the Exim test harness (`test/runtest`) |
| GNU Make       | 3.81+         | Driving the `make rust` target in `src/Makefile`          |

**Optional (for benchmarking and integration testing):**

| Software       | Version       | Purpose                                                  |
|----------------|---------------|----------------------------------------------------------|
| `hyperfine`    | 1.20.0+       | Binary-level benchmark timing                             |
| `swaks`        | latest        | SMTP transaction testing                                  |
| `jq`           | latest        | JSON-output processing                                    |
| C-Exim binary  | 4.99 reference| Side-by-side baseline for benchmarks & spool-compat tests |

### 9.2 Environment Setup

```bash
# 1. Clone the repository and switch to the feature branch
git clone <repository-url>
cd blitzy-exim
git checkout blitzy-990912d2-d634-423e-90f2-0cece998bd03

# 2. Install Rust toolchain (auto-pinned via rust-toolchain.toml)
#    Skip this step if rustup is already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 3. Verify the toolchain
rustc --version     # Expected: 1.80+ (1.95.0 validated)
cargo --version     # Expected: matching cargo
cargo fmt --version # Expected: rustfmt present
cargo clippy -V     # Expected: clippy present

# 4. Ensure $HOME/.cargo/bin is on PATH for interactive shells
export PATH="$HOME/.cargo/bin:$PATH"
```

### 9.3 Dependency Installation (FFI libraries)

Install only the libraries for the FFI features you intend to enable. On Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  libpcre2-dev \
  libpam0g-dev \
  libdb-dev \
  libgdbm-dev \
  libtdb-dev \
  libsasl2-dev \
  libldap2-dev \
  libperl-dev \
  libpq-dev \
  libmariadb-dev \
  libsqlite3-dev \
  libssl-dev \
  libkrb5-dev \
  libspf2-dev
```

Optional benchmarking toolchain:

```bash
cargo install hyperfine
sudo apt-get install -y swaks jq
```

### 9.4 Building the Project

```bash
# Debug build (fastest feedback)
cargo build --workspace

# Release build (LTO + codegen-units=1 + strip; produces ~11 MB binary)
cargo build --release --workspace

# Build through the extended Makefile integration
cd src && make rust && cd ..
# Invokes: cd ..; cargo build --release --target-dir target

# Type-check only (fastest incremental feedback, no linking)
cargo check --workspace
```

### 9.5 Running Tests

```bash
# Full workspace (2,898 unit tests, 94 doc-tests, 39 ignored)
CI=true cargo test --workspace --no-fail-fast

# Single crate
cargo test -p exim-expand
cargo test -p exim-smtp
cargo test -p exim-deliver

# Verbose output
cargo test --workspace -- --nocapture --test-threads=1
```

### 9.6 Quality Gates (must all exit 0 before commit)

```bash
# Gate 2a — format check
cargo fmt --all -- --check

# Gate 2b — clippy with -D warnings
cargo clippy --workspace -- -D warnings

# Gate 2c — release build with RUSTFLAGS="-D warnings"
RUSTFLAGS="-D warnings" cargo build --release --workspace

# Gate 2d — test run
CI=true cargo test --workspace --no-fail-fast
```

### 9.7 Runtime Verification

```bash
# 1. Confirm binary exists
ls -lh target/debug/exim        # ~165 MB (debug)
ls -lh target/release/exim      # ~11 MB (release) — after cargo build --release

# 2. Version + feature list
./target/debug/exim -C src/src/configure.default -bV
# Expected first line: Exim version 4.99 #0 built <date>
# Expected tag:        (Rust rewrite)

# 3. Config dump
./target/debug/exim -C src/src/configure.default -bP | head -30
# Expected: accept_8bitmime; acl_not_smtp = ; acl_smtp_*; ...

# 4. CLI help
./target/debug/exim --help
# Expected: usage summary with -b*, -d, -f, -M*, -N, -q, -C flags

# 5. Address-test and expansion-test modes
./target/debug/exim -C src/src/configure.default -bt user@example.com
./target/debug/exim -C src/src/configure.default -be '${if eq{1}{1}{yes}{no}}'
```

### 9.8 Benchmarking (after C-Exim reference is built)

```bash
# Edit bench/run_benchmarks.sh if your C-Exim binary lives elsewhere
# Default: compares target/release/exim with build-$(uname -s)-*/exim

bash bench/run_benchmarks.sh
# Outputs JSON into bench/results-<timestamp>/ and updates BENCHMARK_REPORT.md

# Run individual hyperfine comparisons
hyperfine --warmup 3 \
  'target/release/exim -C src/src/configure.default -bV' \
  'build-Linux-x86_64/exim -C src/src/configure.default -bV'
```

### 9.9 Troubleshooting

| Issue                                                        | Resolution                                                                                                                          |
|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `cargo: command not found`                                    | `export PATH="$HOME/.cargo/bin:$PATH"` or install Rust via the `rustup` one-liner in §9.2                                           |
| `configuration file not found`                                | Pass `-C <file>` (e.g. `-C src/src/configure.default`) — the default search path `/etc/exim/configure:...` is empty in a fresh checkout |
| `error[E0463]: can't find crate`                              | `cargo clean && cargo build --workspace`; incremental cache stale after branch switch                                                |
| Build fails with FFI link errors                              | Install the relevant `*-dev` package per §9.3 (e.g. `libpam0g-dev`, `libgdbm-dev`)                                                   |
| Tests report "ignored"                                        | Expected — 39 tests ignore themselves when their FFI library is absent (PAM, RADIUS, Perl, GSASL, Kerberos, SPF, BDB, GDBM, NDBM, TDB) |
| `RUSTFLAGS` warning errors                                    | This is intentional (AAP §0.7.2). Fix the warning or add `#[allow(...)]` with a comment explaining the specific technical reason     |
| `clippy` hard-errors on nested `if` in a `match` arm          | Refactor to a match guard — see examples in `exim-acl/src/conditions.rs` lines 1542 / 1548 (already landed)                          |
| NTLM hash comparison triggers CWE-208 audit                   | Use `subtle::ConstantTimeEq` — already landed in `exim-auths/src/spa.rs`                                                              |

### 9.10 Running the Perl Test Harness (142 test directories)

**This is the AAP §0.7.1 primary acceptance gate and is NOT yet operational.** Steps to enable:

```bash
# 1. Build a C-Exim reference binary (required by runtest for cross-version checks)
#    This requires authoring src/Local/Makefile — see Exim documentation.
cd src && cp OS/Makefile-Linux Local/Makefile && make && cd ..

# 2. Create the exim user and group (runtest will run as them)
sudo adduser --system --group --home /var/empty/exim exim

# 3. Configure TLS test certificates in test/aux-fixed/
#    (test/ harness documentation details which fixtures are needed)

# 4. Make the Rust binary discoverable where runtest expects it
cp target/release/exim build-$(uname -s)-$(uname -m)/exim

# 5. Invoke the harness
cd test
./runtest
#   Iterate through failures; no test files are permitted to be modified.
```

---

## 10. Appendices

### Appendix A. Command Reference

| Command                                                          | Purpose                                               |
|------------------------------------------------------------------|-------------------------------------------------------|
| `cargo build --workspace`                                        | Build all 17 crates (debug profile)                    |
| `cargo build --release --workspace`                              | Build optimized binary (~11 MB, LTO)                   |
| `cargo check --workspace`                                        | Type-check only (fastest feedback)                     |
| `cargo test --workspace --no-fail-fast`                          | Run all 2,898 unit tests + 94 doc-tests                |
| `cargo test -p <crate-name>`                                     | Run tests for a specific crate                         |
| `cargo clippy --workspace -- -D warnings`                        | Gate 2b lint check                                     |
| `cargo fmt --all -- --check`                                     | Gate 2a format check                                   |
| `cargo clean`                                                    | Remove all build artifacts                             |
| `cd src && make rust`                                            | Build via Makefile extension                           |
| `cd src && make clean_rust`                                      | Invoke `cargo clean` via Makefile                      |
| `./target/release/exim -bV`                                      | Print version + features                               |
| `./target/release/exim -bP`                                      | Print full configuration                               |
| `./target/release/exim -bt <addr>`                               | Address-test mode                                      |
| `./target/release/exim -be '<expr>'`                             | Expansion-test mode                                    |
| `./target/release/exim -bd -q30m`                                | Start daemon with 30-min queue runs                    |
| `./target/release/exim -bh <host>`                               | Host-check mode (simulate ACL against connecting host) |
| `./target/release/exim --help`                                   | CLI usage summary                                      |

### Appendix B. Port Reference

| Port | Protocol      | Purpose                              |
|------|---------------|--------------------------------------|
| 25   | SMTP          | Default MTA port (inbound / outbound) |
| 465  | SMTPS         | Implicit TLS submission               |
| 587  | Submission    | Message submission (STARTTLS)         |

### Appendix C. Key File Locations

| File / Directory                                              | Purpose                                                   |
|---------------------------------------------------------------|-----------------------------------------------------------|
| `Cargo.toml`                                                  | Root workspace manifest (17 crate members)                 |
| `Cargo.lock`                                                  | Pinned dependency versions (370 registry packages)         |
| `rust-toolchain.toml`                                         | Rust toolchain pin (`stable` + `rustfmt` + `clippy`)      |
| `.cargo/config.toml`                                          | `RUSTFLAGS="-D warnings"`, linker settings, FFI env vars   |
| `.github/workflows/ci.yml`                                    | GitHub Actions CI (fmt / clippy / test / release-build)    |
| `src/Makefile`                                                | Extended C Makefile with `rust:` and `clean_rust:` targets |
| `src/src/configure.default`                                   | Default Exim configuration (44 KB) — reference for `-bV` / `-bP` |
| `exim-core/src/main.rs`                                       | Binary entry point + mode dispatch                         |
| `exim-core/src/context.rs`                                    | 4 scoped context structs (replacing 714 globals)           |
| `exim-store/src/taint.rs`                                     | `Tainted<T>` / `Clean<T>` compile-time taint newtypes      |
| `exim-store/src/arena.rs`                                     | `bumpalo::Bump` per-message arena                          |
| `exim-drivers/src/registry.rs`                                | `inventory`-based compile-time driver registration          |
| `exim-miscmods/src/dkim/pdkim/signing.rs`                     | DKIM crypto — **stubbed (Phase 5 S1 / S2)**               |
| `exim-miscmods/src/dkim/mod.rs`                               | DKIM DNS callback — **stubbed (Phase 5 D1)**              |
| `exim-miscmods/src/dmarc.rs`                                  | DMARC FFI DNS callback — **stubbed (Phase 5 DM1)**        |
| `exim-miscmods/src/spf.rs`                                    | SPF DNS hook — **not wired (Phase 5 SP1)**                |
| `exim-miscmods/src/sieve_filter.rs`                           | Sieve interpreter — **API + commands incomplete (SV1/SV4)** |
| `exim-ffi/`                                                   | ONLY crate with `unsafe` code (53 blocks, all annotated)   |
| `bench/run_benchmarks.sh`                                     | Performance benchmarking script (1,388 lines)              |
| `bench/BENCHMARK_REPORT.md`                                   | Benchmark template (148 lines) — **needs real measurements** |
| `docs/executive_presentation.html`                            | C-suite executive presentation (14 slides)                 |
| `blitzy/screenshots/exec_presentation_slide_*.png`            | Evidence screenshots of the executive deck                 |
| `CODE_REVIEW.md`                                              | Autonomous 7-phase review (2,713 lines)                    |
| `PROJECT_GUIDE.md`                                            | Top-level index with critical caveats                      |
| `target/debug/exim`                                           | Compiled binary (debug, ~165 MB)                           |
| `target/release/exim`                                         | Compiled binary (release, ~11 MB — produced by `cargo build --release`) |
| `test/runtest`                                                | Perl TAP harness (PRESERVED; not modified)                 |
| `test/scripts/`                                               | 141 test-script directories + 142nd-category fixtures = 142 dirs total |

### Appendix D. Technology Versions

| Technology        | Version            | Purpose                                                 |
|-------------------|--------------------|---------------------------------------------------------|
| Rust              | 1.80+ (1.95.0 validated) | Primary language                                    |
| Cargo             | matches Rust       | Build system                                             |
| bumpalo           | 3.20.2             | Per-message arena allocator                              |
| inventory         | 0.3.22             | Compile-time driver registration                         |
| clap              | 4.5.60             | CLI argument parsing                                     |
| rustls            | 0.23.37            | Default TLS backend                                      |
| openssl           | 0.10.75            | Optional TLS backend (feature-gated)                     |
| hickory-resolver  | 0.25.0             | DNS resolution (A/AAAA/MX/SRV/TLSA/PTR)                  |
| tokio             | 1.50.0             | Async runtime (lookup bridging ONLY, via `block_on()`)   |
| tokio-postgres    | 0.7.16             | PostgreSQL lookup (async, bridged)                        |
| mysql_async       | 0.36.1             | MySQL / MariaDB lookup (async, bridged)                   |
| ldap3             | 0.12.1             | LDAP lookup                                               |
| rusqlite          | 0.38.0             | SQLite lookup + hintsdb                                   |
| redis             | 1.0.5              | Redis lookup                                              |
| serde             | 1.0.228            | Serialization framework                                   |
| serde_json        | 1.0.149            | JSON parsing                                              |
| regex             | 1.12.3             | Pattern matching                                          |
| pcre2             | 0.2.11             | PCRE2 compatibility                                       |
| nix               | 0.31.2             | Safe POSIX wrappers (fork / signal / socket)              |
| tracing           | 0.1.44             | Structured logging                                        |
| thiserror         | 2.0.18             | Error-type derivation                                     |
| anyhow            | 1.0.102            | Application error handling                                |
| libc              | 0.2.183            | C type definitions                                        |
| bindgen           | 0.72.1             | C-header → Rust FFI binding generation (build-dep)        |
| cc                | 1.2.56             | C compilation orchestration (build-dep)                   |
| libloading        | 0.9.0              | Dynamic library loading (`dlfunc`)                        |
| subtle            | current            | Constant-time comparisons (fixes CWE-208 in SPA)          |
| hyperfine (CLI)   | 1.20.0             | Binary-level benchmark timing                             |
| reveal.js (CDN)   | 5.1.0              | Executive presentation framework                          |

### Appendix E. Environment Variable Reference

| Variable                   | Default                                         | Purpose                                                 |
|----------------------------|-------------------------------------------------|---------------------------------------------------------|
| `RUSTFLAGS`                | `-D warnings` (set via `.cargo/config.toml`)    | Rust compiler flags                                      |
| `CARGO_TERM_COLOR`         | `always` (CI)                                   | Cargo color output                                       |
| `CI`                       | unset                                           | Set to `true` in CI environments                         |
| `EXIM_C_SRC`               | `src/src` (relative)                            | C source tree for `exim-ffi/build.rs` bindgen            |
| `EXIM_FFI_LIB_DIR`         | system default                                  | Override for all FFI library locations                   |
| `EXIM_PAM_LIB_DIR`         | system default                                  | `libpam` location override                               |
| `EXIM_PERL_LIB_DIR`        | system default                                  | `libperl` location override                              |
| `EXIM_GSASL_LIB_DIR`       | system default                                  | `libgsasl` location override                             |
| `EXIM_KRB5_LIB_DIR`        | system default                                  | `libkrb5` / Heimdal location override                    |
| `EXIM_SPF_LIB_DIR`         | system default                                  | `libspf2` location override                              |
| `EXIM_DB_LIB_DIR`          | system default                                  | Berkeley DB location override                            |
| `EXIM_GDBM_LIB_DIR`        | system default                                  | `libgdbm` location override                              |
| `EXIM_TDB_LIB_DIR`         | system default                                  | `libtdb` location override                               |
| `RUST_LOG`                 | unset                                           | `tracing` log level (e.g. `debug`, `info`, `error`)      |

### Appendix F. Developer Tools Guide

```bash
# 1. Incremental development cycle
cargo check --workspace               # Fast type-check (typically < 10s incremental)
cargo test -p <crate> <test_name>     # Run a specific test by name
cargo clippy -p <crate>               # Lint a specific crate

# 2. Feature-gated builds
cargo build --release -p exim-core \
  --features "exim-tls/tls-openssl"

cargo build --release -p exim-core \
  --features "exim-lookups/lookup-pgsql,exim-lookups/lookup-redis,exim-lookups/lookup-ldap"

# 3. Runtime debugging
RUST_LOG=debug ./target/debug/exim -C src/src/configure.default -bV
./target/release/exim -C src/src/configure.default -d+all -bt user@example.com

# 4. Profile-guided analysis (post-benchmark)
cargo build --release --workspace
# Then use `perf`, `flamegraph`, or `valgrind --tool=callgrind` against target/release/exim

# 5. Dependency analysis
cargo tree --workspace --depth 1
cargo audit       # Check for known vulnerabilities in dependencies

# 6. Binary introspection
file target/release/exim
ldd  target/release/exim         # See which FFI libs resolved at link time
./target/release/exim -bV | head # Feature advertisement from running binary
```

### Appendix G. Glossary

| Term                    | Definition                                                                                          |
|-------------------------|-----------------------------------------------------------------------------------------------------|
| **MTA**                 | Mail Transfer Agent — software that routes and delivers email between servers                       |
| **SMTP**                | Simple Mail Transfer Protocol — the standard protocol for email transmission                        |
| **Exim**                | A widely-used open-source MTA maintained by the University of Cambridge                             |
| **Crate**               | A Rust compilation unit (library or binary)                                                          |
| **Workspace**           | A Cargo feature for managing multiple related crates with shared dependencies                        |
| **Arena allocator**     | A memory-allocation strategy that frees all allocations at once (via `bumpalo::Bump::reset()`)      |
| **Taint tracking**      | A security mechanism to distinguish trusted from untrusted data (here: compile-time via newtypes)    |
| **FFI**                 | Foreign Function Interface — mechanism for calling C code from Rust                                  |
| **inventory**           | A Rust crate for compile-time plugin / driver registration (`inventory::submit!`)                    |
| **bumpalo**             | A Rust crate providing fast bump/arena allocation                                                    |
| **rustls**              | A modern, memory-safe TLS library written in Rust                                                    |
| **PCRE2**               | Perl-Compatible Regular Expressions version 2                                                         |
| **DANE**                | DNS-Based Authentication of Named Entities — TLS cert verification via DNS (RFC 6698)                |
| **DKIM**                | DomainKeys Identified Mail — email authentication via cryptographic signatures (RFC 6376)            |
| **ARC**                 | Authenticated Received Chain — email authentication for forwarded messages (RFC 8617)               |
| **SPF**                 | Sender Policy Framework — email authentication via DNS TXT records (RFC 7208)                        |
| **DMARC**               | Domain-based Message Authentication, Reporting and Conformance (RFC 7489)                            |
| **Sieve**               | RFC 5228 email filtering language                                                                     |
| **ACL**                 | Access Control List — Exim's policy-evaluation mechanism (`acl_smtp_*` runs per-phase)              |
| **Spool**               | The directory where Exim stores messages awaiting delivery (`-H` header + `-D` data files)          |
| **PRDR**                | Per-Recipient Data Response — SMTP extension (RFC 2920-flavored; Exim-specific)                     |
| **CHUNKING / BDAT**     | SMTP extension for binary-data transfer (RFC 3030)                                                    |
| **PIPELINING**          | SMTP extension allowing multiple commands in one TCP write (RFC 2920)                                |
| **XCLIENT**             | Postfix-originated SMTP extension for MTA chaining                                                    |
| **ATRN**                | Authenticated TURN — SMTP extension (RFC 2645)                                                        |
| **AAP**                 | Agent Action Plan — Blitzy's specification document (§0 in this guide's context)                    |
| **CWE-208**             | Observable Timing Discrepancy — a CVE / CWE category fixed in this PR for SPA / NTLM via `subtle`    |
