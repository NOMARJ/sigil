# Autopilot Plan: Trust-Ledger Allowlisting (F-010)

- **PRD:** `tasks/prd-trust-ledger-allowlisting.md` (status: approved — Gate 1 passed 2026-06-11)
- **Date:** 2026-06-11
- **Stories:** 3 (0 trivial / 2 moderate / 1 complex)
- **Estimated exchanges:** ~25
- **Parallel candidates:** none — strict chain US-H1 → US-H2 → US-H3

## Dependency DAG

```
US-H1 (ledger match API) ──> US-H2 (scan suppression + flag) ──> US-H3 (eval re-measure)
```

## Key integration facts (from codebase exploration, 2026-06-11)

- Product trust ledger exists: `cli/src/ledger.rs` — `LedgerRecord` (line 52), `ContentPin` (line 32), `record_approval` (line 235), `detect_rugpull` (line 255). Written on `sigil approve` at `cli/src/main.rs:1401`.
- Suppression hook point: post-scan in `cmd_scan` (`cli/src/main.rs:880-1060`), after `run_scan` returns — all phases aggregated, before verdict/output/cache.
- `Finding` struct: `cli/src/scanner/mod.rs:72-90`. Add `suppressed_by: Option<String>` with `skip_serializing_if`.
- Score/verdict: `cli/src/scanner/scoring.rs:44-78` — recalc over unsuppressed findings only; reuse existing functions.
- Eval harness: `scripts/run_eval.py`; datasets live at `/tmp/evalset/samples` (Datadog, commit 605a7318) and `/tmp/control2` (20 clean packages, fetched by `/tmp/fetch_control.py`). Current cold metrics: FP@High 70%, recall@High 90.31% (`evaluation_results/honest_detection_eval.json`).
- Hermetic warm ledger: no `SIGIL_HOME` override exists; `dirs::home_dir()` respects `$HOME` — eval warm pass sets `HOME=<tempdir>` when invoking the binary.

## Risk flags

- FP "improvement" from allowlisting is true-by-construction; report must not present warm FP as detector precision (CLAUDE.md no-fake-data rules). Cold FP stays headline.
- Recall must be byte-identical cold vs warm — any delta means suppression leaked to non-approved content (release blocker).
- Drift must never suppress — covered by existing rug-pull tests plus a new drift-no-suppress test.

## Escalation boundaries

- None expected: no auth, no DB schema, no CI config, no new dependencies.
- If US-H3 reveals `$HOME` override is insufficient for hermetic isolation, a small `SIGIL_HOME` env-var story will be proposed (scope addition → operator approval).

## Preconditions outstanding (Gate 1 blockers)

1. PRD status flip to `approved` / `ready_for_execution` (operator)
2. SOLUTION.md Feature entry (F-009) linking this PRD (operator — autopilot may not modify SOLUTION.md)
3. Clean working tree — `.nomark/*` telemetry, `progress.md`, and `sigil-skill/*` modifications from prior sessions are uncommitted

## Resume command

```
/autopilot tasks/prd-trust-ledger-allowlisting.md --skip-plan
```
