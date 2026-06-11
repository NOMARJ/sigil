# PRD — Trust-Ledger Allowlisting (F-010)

- **Status:** approved — ready_for_execution (operator approval 2026-06-11)
- **Author:** autopilot decompose phase, 2026-06-11
- **Depends on:** F-008 (trust ledger + rug-pull detection, eval harness) — merged at `7457e01`
- **SOLUTION.md entry:** F-010 · Trust-Ledger Allowlisting (EP-003)

## Problem

`sigil approve <id>` records a content-pinned `LedgerRecord` (`cli/src/ledger.rs:52`) and rug-pull detection fires on drift, but approval has no effect on subsequent scans: a package the operator already reviewed and approved is re-flagged with the same findings every scan. This is workflow noise — the dominant complaint behind the 70% FP@High on clean control packages (`evaluation_results/honest_detection_eval.json`, 2026-06-11).

## Solution

When a scan target's content exactly matches an approved ledger pin (`artifact_digest` equality), suppress its findings from score and verdict — the operator already accepted this exact content. Drifted content is never suppressed (rug-pull detection continues to fire). Suppression is visible, auditable, and bypassable.

### Semantics (fixed)

1. **Match key is content, not name.** Suppression requires `ContentPin.artifact_digest` of the scanned directory to equal an approved `LedgerRecord.pin.artifact_digest`. Name/version are metadata only.
2. **Drift kills suppression.** Any digest mismatch → full findings + existing RUGPULL-001 path. No partial suppression of drifted packages.
3. **No silent drops.** Suppressed findings stay in the scan result marked `suppressed_by: "ledger:<source>#<id>"`; they are excluded from score/verdict. Human output prints one line: `N findings suppressed by ledger approval (<source>, approved <date>)`.
4. **Escape hatch.** `sigil scan --ignore-ledger` disables suppression entirely.
5. **Rejected/pending entries never suppress.** Only `Approved` ledger records participate.

## Acceptance Criteria

| # | Criterion | Verification command |
|---|-----------|---------------------|
| 1 | Scanning content that digest-matches an approved ledger record suppresses all pack/phase findings from score and verdict (verdict becomes LowRisk for clean-by-approval content) | `cd cli && cargo test ledger_suppress` (new tests) |
| 2 | Drifted content (any file changed/added/removed vs pin) is NOT suppressed and RUGPULL-001 still fires | `cd cli && cargo test rugpull` (existing tests stay green + new drift-no-suppress test) |
| 3 | `--ignore-ledger` restores unsuppressed behavior | `cd cli && cargo test ignore_ledger_flag` |
| 4 | Suppressed findings remain in `--format json` output with `suppressed_by` set; non-suppressed runs serialize without the field (no schema break) | `cargo test` serde tests + manual: `sigil scan <approved-dir> --format json \| jq '.findings[].suppressed_by'` |
| 5 | Eval re-measure: `scripts/run_eval.py --ledger-warm` runs a cold pass and a warm pass (control set approved into a hermetic `HOME` ledger); recall is byte-identical cold vs warm; warm control FP@High = 0% for digest-matched packages; report carries the mandatory disclosure block and states the warm number measures workflow suppression, not detector precision | `python3 scripts/run_eval.py --dataset datadog --dataset-path /tmp/evalset/samples --control-path /tmp/control2 --out evaluation_results/ --ledger-warm` then read `evaluation_results/honest_detection_eval.json` |
| 6 | Full test suite green | `cd cli && cargo test` |

## Honest-measurement note (CLAUDE.md integrity)

A warm-ledger FP of 0% on approved packages is true by construction (exact-digest suppression), not evidence of a smarter detector. The eval exists to prove (a) recall is untouched by the ledger path, (b) drift is never suppressed, and (c) the end-to-end operator workflow stops re-flagging approved content. The report MUST state this; cold FP rates remain the headline detector metric.

## Stories

### US-H1: Digest-keyed ledger match API [moderate]
- **Goal:** `ledger::match_approved(path: &Path) -> Option<LedgerMatch>` exists — computes the pin of `path`, returns the approved record on exact digest match, distinguishes `Match` vs `Drifted` vs no record.
- **Done when:** `cd cli && cargo test ledger::tests` green including new tests: digest match returns record; drifted returns drift signal; rejected/pending records never match.
- **Files:** `cli/src/ledger.rs`
- **Dependencies:** none

### US-H2: Scan-time suppression + CLI flag [complex]
- **Goal:** `cmd_scan` consults the ledger post-scan; on exact match, marks findings `suppressed_by`, recalculates score/verdict over unsuppressed findings, prints the suppression line; `--ignore-ledger` bypasses; drift path unchanged.
- **Done when:** `cd cli && cargo test` green including: suppressed scan yields LowRisk verdict + populated `suppressed_by`; drifted scan yields original findings + RUGPULL-001; `--ignore-ledger` yields original findings; JSON serde round-trip.
- **Files:** `cli/src/scanner/mod.rs` (Finding field), `cli/src/main.rs` (cmd_scan hook + flag), `cli/src/ledger.rs` (suppress helper), `cli/src/scanner/scoring.rs` (recalc over unsuppressed)
- **Dependencies:** US-H1

### US-H3: Eval ledger-warm mode + FP re-measure [moderate]
- **Goal:** `run_eval.py --ledger-warm` approves the control set into a temp-`HOME` ledger via the real `sigil` binary, re-scans control warm, reports cold AND warm FP per threshold plus recall-delta assertion; honest disclosure included.
- **Done when:** Eval run completes against `/tmp/evalset/samples` + `/tmp/control2`; JSON contains `control_flagged_cold`, `control_flagged_warm`, `recall_delta: 0`; disclosure note present; results committed to `evaluation_results/`.
- **Files:** `scripts/run_eval.py`, `evaluation_results/honest_detection_eval.{json,md}`
- **Dependencies:** US-H2

## Out of scope

- Name/version-based (non-content) allowlisting — weaker than digest pinning, invites typosquat suppression
- Partial/per-file suppression of drifted packages
- API/bash scanner parity (Rust engine is the F-008 path; bash delegates already)
- Ledger sync/sharing across machines

## Risks

- `HOME` override hermeticity in eval: `dirs::home_dir()` respects `$HOME` on unix — verify in US-H3 before trusting warm-pass isolation.
- Score recalc must reuse `calculate_score`/verdict logic, not duplicate it (one source of truth).
