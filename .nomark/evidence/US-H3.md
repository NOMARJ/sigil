# Evidence — US-H3: Eval ledger-warm mode + honest FP re-measure (F-010)

**Date:** 2026-06-11
**Files:** `scripts/run_eval.py`, `evaluation_results/honest_detection_eval.{json,md}`

## Disclosure (per CLAUDE.md)
```
Data Source: Real — Datadog malicious-software-packages-dataset (commit 605a7318) + 20 extracted
             legitimate npm/PyPI packages (/tmp/control2, fetched from public registries).
Sample Size: 351 malicious samples (110/bucket, deterministic selection); 20 clean control packages.
Limitations: Warm FP of 0% is TRUE BY CONSTRUCTION (exact-digest suppression of operator-approved
             content) — it measures the F-010 allowlisting workflow, not detector precision. Cold FP
             (70% @High) remains the headline detector metric. Dataset has GuardDog selection bias.
```

## What was built
- `run_eval.py --ledger-warm`: after the cold passes, approves every control package into a hermetic temp-`HOME` trust ledger via the REAL `sigil approve` (production pinning path, no synthetic pins), then re-scans BOTH sets warm. Reports `control_flagged_cold`/`control_flagged_warm`, `recall_delta` with per-sample drift list, `control_outcome_changes`.
- `resolve_binary()` now prefers the repo build over PATH — the smoke run exposed a stale Homebrew sigil 1.0.4 (pre-ledger) silently being measured. SIGIL_BIN still overrides.

## Verification (full run, exit 0, fresh 2026-06-11)

Command:
```
SIGIL_BIN=cli/target/release/sigil python3 scripts/run_eval.py --dataset datadog \
  --dataset-path /tmp/evalset --control-path /tmp/control2 --out evaluation_results/ \
  --limit 110 --ledger-warm
```

Results (`evaluation_results/honest_detection_eval.json`):
- 351 malicious scanned, 0 extract failures, 0 scan errors
- **Recall unchanged vs pre-F-010 baseline**: any 96.87%, Medium 96.58%, High 90.31%, Critical 59.54% — byte-identical to the 2026-06-11 07:00 cold baseline
- **Cold FP unchanged**: any 85%, Medium 80%, High 70%, Critical 20% (headline detector metric)
- **Warm FP (20/20 control packages ledger-approved)**: 0% at every threshold; `control_outcome_changes: 17` (exactly the 17 cold-flagged packages)
- **`recall_delta: 0`**, `recall_drift_samples: []` — per-sample (max_severity, finding_count) identical cold→warm across all 351 malicious samples; suppression did not leak

AC#5 deltas from PRD: report JSON nests `control_flagged_cold`/`control_flagged_warm`/`recall_delta` under a `ledger_warm` key (keeps top-level schema stable for consumers of the existing report).
