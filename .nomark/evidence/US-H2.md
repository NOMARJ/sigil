# Evidence — US-H2: Scan-time ledger suppression + `--ignore-ledger` (F-010)

**Date:** 2026-06-11
**Files:** `cli/src/ledger.rs`, `cli/src/scanner/mod.rs`, `cli/src/main.rs`, `cli/src/output.rs`

## Design deviation (documented)
Suppression is all-or-nothing per artifact (exact-digest approval), so attribution lives at **result level** (`ScanResult.suppressed_findings: Vec<Finding>` + `ScanResult.suppressed_by: Option<String>`), not as a per-`Finding` field as the PRD sketch suggested — a per-finding field would be redundant data and touch 22 `Finding` construction sites. PRD AC#4 intent preserved: suppressed findings stay visible in JSON output, attributed; old caches deserialize (serde defaults, unit-tested).

## What was built
- `ledger::apply_suppression_in/apply_suppression` — restores any previously-suppressed findings (cache re-evaluation), then suppresses when content digest-matches an approved pin. Vetoes: `--ignore-ledger`, presence of RUGPULL-001. Score/verdict recomputed via existing scoring fns.
- `cmd_scan`: applies suppression on both the cached and fresh paths; shared `print_scan_output` emits the suppression object AFTER the findings array in JSON (keeps `run_eval.py`'s first-array parser correct); human format prints one attribution line.
- `--ignore-ledger` flag on `sigil scan`.
- `cmd_reject` revokes the ledger pin (`ledger::remove`) — rejected artifacts stop suppressing immediately.
- `print_scan_summary` JSON gains scalar `suppressed_count` (object kept array-free by design).

## Verification

Unit (fresh runs): `cargo test ledger::tests` → 20 passed; full `cargo test` → **129 passed; 0 failed** (was 123 before US-H2).

New tests: `suppression_moves_findings_and_rewrites_verdict`, `suppression_skipped_when_ignored`, `suppression_skipped_for_drifted_content`, `suppression_never_swallows_rugpull_findings`, `cached_suppressed_result_is_reevaluated_against_current_ledger`, `scanresult_without_suppression_fields_deserializes`. TDD: all confirmed failing (E0425/E0560/E0609) before implementation.

End-to-end (debug binary, hermetic `HOME=/tmp/sigil-ush2-e2e`):
| # | Scenario | Result |
|---|----------|--------|
| 1 | Cold scan, pending entry | 1 High finding (CODE-001), exit 1 |
| 2-3 | `sigil approve` → rescan identical content | `findings_count: 0, suppressed_count: 1`, LOW RISK, exit 0, `suppressed_by: ledger:testpkg@1.0.0#q1 approved 2026-06-11`, suppressed finding present in JSON |
| 4 | `--ignore-ledger` | findings back, exit 1 |
| 5 | Human output | `[*] 1 finding suppressed by ledger approval (…)` |
| 6 | Drifted copy of approved content | no suppression, exit 1 |
| 7 | Drift on approved quarantine path | CODE-001 + RUGPULL-001, CRITICAL RISK, exit 1, re-quarantined |
| 8-10 | `sigil reject` | "ledger pin revoked"; same content rescanned → no suppression, exit 1 |
| 11 | Cache written pre-approval, approve, cached rescan | cache hit + `suppressed_count: 1`, exit 0 |
