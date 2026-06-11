# Feature Verification: F-010 Trust-Ledger Allowlisting

**PRD:** `tasks/prd-trust-ledger-allowlisting.md` (approved 2026-06-11)
**Date:** 2026-06-11
**Stories:** 3/3 DONE (0 blocked)
**Result:** PASS

## Acceptance Criteria

| # | Criterion | Evidence | Status |
|---|-----------|----------|--------|
| 1 | Digest-matched approved content suppressed from score/verdict, LowRisk verdict | `cargo test suppression` → 7 passed (note: tests named `suppression_*`, not the PRD's `ledger_suppress` filter); e2e scenario 3: score 0, LOW RISK, exit 0 | PASS |
| 2 | Drifted content never suppressed; RUGPULL-001 unaffected | `cargo test rugpull` → 4 passed; `suppression_skipped_for_drifted_content`, `suppression_never_swallows_rugpull_findings`; e2e scenarios 6-7 (drift → CRITICAL + re-quarantine) | PASS |
| 3 | `--ignore-ledger` restores unsuppressed behavior | `suppression_skipped_when_ignored`; e2e scenario 4 (findings back, exit 1) | PASS |
| 4 | Suppressed findings visible in JSON, no schema break | Result-level `suppressed_findings`/`suppressed_by` (documented deviation: all-or-nothing semantics make per-finding field redundant — US-H2 evidence); `scanresult_without_suppression_fields_deserializes` proves old caches parse; e2e scenario 3 shows suppressed finding in JSON output | PASS (deviation documented) |
| 5 | Eval re-measure: warm pass, recall byte-identical, warm FP@High 0%, honest disclosure | Full 351+20 run exit 0: warm FP 0% all thresholds, `recall_delta: 0` (per-sample identical), cold FP unchanged 70% @High, TRUE-BY-CONSTRUCTION disclosure in report (US-H3 evidence). Warm metrics nest under `ledger_warm` JSON key (documented deviation) | PASS (deviation documented) |
| 6 | Full test suite green | `cargo test` → 129 passed; 0 failed (fresh run, 2026-06-11) | PASS |

## Test results (final fresh run)
```
test result: ok. 129 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Eval re-measure (real data; disclosure per CLAUDE.md)
```
Data Source: Real — Datadog malicious-software-packages-dataset (605a7318) + 20 public-registry packages
Sample Size: 351 malicious / 20 clean control
Limitations: warm FP 0% is true by construction (workflow metric, not detector precision);
             cold FP@High 70% remains the headline detector metric; GuardDog selection bias
```
- Recall (cold == warm, per-sample): any 96.87% / High 90.31% / Critical 59.54%
- Control FP cold → warm: 85→0% (any), 80→0% (Medium), 70→0% (High), 20→0% (Critical)

## Security/safety properties verified
- Rejection revokes suppression immediately (`ledger::remove` in `cmd_reject`, e2e 8-10)
- Cached results re-evaluated against current ledger on every load (revocation beats cache, e2e 11)
- Empty-pin guard (digest-of-nothing can't become a universal allowlist key)
- RUGPULL-001 presence vetoes suppression (drift outranks content match)

## Commits
- `568df63` docs(plan): PRD + stories
- `c18bf5a` feat(cli): [US-H1] digest-keyed ledger match + revocation API
- `dfc968e` feat(cli): [US-H2] scan suppression + --ignore-ledger + reject revocation
- `a3595b7` feat(eval): [US-H3] ledger-warm FP re-measure

## Carried-forward observations (not blocking)
- Stale Homebrew `sigil` 1.0.4 at `/opt/homebrew/bin/sigil` shadows the repo build on PATH — eval now prefers the repo build, but the operator may want to `brew upgrade`/unlink it.
- `/tmp/sigil-ush2-e2e` scratch dir left in place (rm denied by permission mode); harmless, /tmp.
