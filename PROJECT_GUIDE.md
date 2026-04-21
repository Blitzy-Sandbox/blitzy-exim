# Project Guide — Exim Rust Migration

This file is the top-level index for project-wide documents and cross-cutting references. For the authoritative delivered-state narrative (completion status, test results, runtime validation), see [`blitzy/documentation/Project Guide.md`](./blitzy/documentation/Project%20Guide.md). For the foundational specification that drove this migration (Agent Action Plan), see [`blitzy/documentation/Technical Specifications.md`](./blitzy/documentation/Technical%20Specifications.md).

## Code Reviews

- **PR #1**: [CODE_REVIEW.md](./CODE_REVIEW.md) — Complete C-to-Rust migration of the Exim MTA (219 files, 262,318 additions). Reviewed in 7 phases with graduated severity sign-offs. — **Status: APPROVED_WITH_CRITICAL_CAVEATS**

  **Caveats (must read before deployment):**
  - **Phase 5 P1 CRITICAL**: DKIM sign/verify crypto stubbed; DMARC FFI DNS callback stubbed; SPF DNS hook not wired; ARC inherits DKIM stubs; Sieve `sieve_interpret` API missing; Sieve `reject`/`setflag` undispatched. Mail-authentication verdicts are currently synthetic — do not deploy to any DMARC-enforcing or DKIM-rejecting environment without remediation.
  - **Phase 6 P1 FACTUAL**: Executive presentation (`docs/executive_presentation.html`) slides 10/13/14 contain factual claims that contradict the delivered state (premature "Migration complete", unverified "1,205 tests passing", unsupported "All metrics within target limits"). Edit before distribution.
  - **Phase 7 P1 FACTUAL (Project Guide)**: `blitzy/documentation/Project Guide.md` §6 Risk Assessment omits 6 Phase 5 P1 CRITICAL items; §8 "Code Complete, Integration Pending" narrative contradicts Phase 5 findings; §1.3 Key Accomplishments overstates exim-miscmods completion; §1.6 Next Steps omits crypto remediation. Four editorial fixes required before external distribution.
  - **Phase 7 P1 GAP (AAP)**: AAP §0.7.1 (142 test directories) not executed; AAP §0.7.5 ("Assumed parity is NOT acceptable" — all 4 performance thresholds DEFERRED) violated; AAP §0.7.2 (unsafe count 53 > 50 limit) exceeded. Engineering remediation required to reach AAP compliance.

  See [`CODE_REVIEW.md`](./CODE_REVIEW.md) → YAML `final_verdict_summary` and `## Summary` section for full detail.
