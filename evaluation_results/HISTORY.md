# Sigil measurement history

Every detection measurement Sigil has published, in one table, so a reader can
see how the numbers moved instead of only seeing the latest one.

```
Data Source: Transcribed from measurements already committed to this repository —
             evaluation_results/honest_detection_eval.{md,json} and their git
             history, plus the README "Detection Accuracy" table's history. Those
             runs used the Datadog malicious-software-packages-dataset (real,
             human-triaged malicious npm/PyPI packages) and a clean control set of
             popular packages fetched from the live registries.
Sample Size: 3 published measurement runs (351, 844 and 844 malicious samples;
             20 clean control packages each) and 3 README publications of them.
Limitations: This file is a transcription, not a measurement. Every value is
             copied verbatim from the source row's linked artifact, with no
             rounding, no recomputation and no interpolation. The per-run
             limitations (dataset selection bias, offline-only phases, small
             control set) are stated in each run's own report — read them there,
             not here. Rows are not directly comparable to each other: the sample
             size, the dataset revision and the scanner all changed between runs.
```

## Measurement runs

Recall is `detected / scanned`; clean-set FP is `flagged / 20 control packages`.
Both are read at four thresholds: any severity / ≥ Medium / ≥ High / ≥ Critical.

| Date (generated) | Commit | Binary | Dataset commit | Dataset fingerprint | Samples | Recall any / Med / High / Crit | Clean FP any / Med / High / Crit | Notes |
|---|---|---|---|---|---|---|---|---|
| 2026-06-11 | [`f1e194d`](https://github.com/NOMARJ/sigil/commit/f1e194d) | not recorded | `605a7318822117b3b29466747e65db1d582f290c` | `5f7ebb09543449f01fff5216fe610f545a7abb78dba4b1eb3080ad6599a050bb` | 351 malicious (110/bucket), 20 clean | 340/351 96.87% · 339/351 96.58% · 317/351 90.31% · 209/351 59.54% | 17/20 85.00% · 16/20 80.00% · 14/20 70.00% · 4/20 20.00% | Extract failures 0, scan errors 0. Includes a ledger-warm pass: 20 control packages approved into a hermetic trust ledger, warm FP 0.00% at all four thresholds, `recall_delta = 0`. |
| 2026-09-03 | [`c7771d2`](https://github.com/NOMARJ/sigil/commit/c7771d2) | not recorded | `unknown` (recorded literally as `unknown`) | `587e09d2a8bb6ab0bba65f086fb1b5f342dd24357725cdd22104c4fe60aebd0b` | 844 malicious (204/bucket, incl. the AI-skills bucket), 20 clean | 750/844 88.86% · 744/844 88.15% · 672/844 79.62% · 540/844 63.98% | 18/20 90.00% · 17/20 85.00% · 15/20 75.00% · 5/20 25.00% | Extract failures 0, scan errors 0. **No ledger-warm pass** — `ledger_warm` is `{}` in the JSON. |
| 2026-09-03 | [`da316a5`](https://github.com/NOMARJ/sigil/commit/da316a5) | not recorded | `unknown` | `587e09d2a8bb6ab0bba65f086fb1b5f342dd24357725cdd22104c4fe60aebd0b` | 844 malicious (204/bucket, incl. the AI-skills bucket), 20 clean | 772/844 91.47% · 764/844 90.52% · 718/844 85.07% · 553/844 65.52% | 17/20 85.00% · 17/20 85.00% · 13/20 65.00% · 5/20 25.00% | Extract failures 0, scan errors 0. No ledger-warm pass. Same dataset fingerprint as the row above, so the two are directly comparable. The clean-set columns count a package containing a finding at that severity; by *verdict* this run returns CRITICAL RISK on 0 of 20 and HIGH RISK or worse on 16 of 20, against 6 and 18 for the row above. |

All three runs used the same offline, deterministic phase set:
`install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection`.
OSV and provenance network feeds are excluded from the measurement so a re-run on
the same dataset revision reproduces the same numbers.

### Which rows compare, and which do not

**Rows 1 and 2 do not compare.** The sample set changed from 351 to 844 and
gained the dataset's AI-skills bucket, and the fingerprints differ. The
README's disclosure for row 2 states the AI-skills bucket is the weakest
("65% detected at any severity on a 60-sample subset") and pulls the averages
below the earlier run. Two runs over different sample sets are two
measurements, not a trend.

**Rows 2 and 3 do compare.** Same 844 samples, same dataset fingerprint
(`587e09d2…`), same phase set, same 20 control packages — only the scanner
changed. Recall rose at all four thresholds and the clean-set flag rate fell at
two, which is the shape a precision change is supposed to have; a threshold
move alone would have traded one for the other.

One caution on reading row 3's AI-skills improvement, because part of it is a
correction rather than a gain. `SKILL-003` matched bare substrings, so it
scored English prose — a markdown heading `### Code Execution`, a DirectX API
name `ID3D12CommandQueue::ExecuteCommandLists` — as a Critical finding. Across
the 41 samples that lost their High rating when the rule was narrowed, all 128
of its findings matched prose and none matched a manifest value. Row 2's
AI-skills figures were inflated by that; the rules added in row 3 are what
recover and exceed them honestly.

### Fields the reports do not record

- **Scanner version.** The JSON reports store the path to the binary that was
  run, not a version string, so no run can be tied to a released version from
  the artifact alone. (Local build paths are deliberately not reproduced here;
  row 3's report replaces the path with a description for the same reason.)
  Recording `sigil --version` in the report would close this gap.
- **Dataset commit for the second run.** It is recorded literally as `unknown`;
  only the reproducibility fingerprint identifies that sample set.

## README publications of those runs

The README's "Detection Accuracy — Measured, Not Marketed" table is a
publication of the runs above, not a separate measurement. Its history:

| Date | Commit | Sample size stated | Recall any / ≥High / ≥Crit | FP ≥High, first scan | FP after ledger approval | FP ≥High with Pro AI adjudication |
|---|---|---|---|---|---|---|
| 2026-08-28 | [`61306ae`](https://github.com/NOMARJ/sigil/commit/61306ae) | 351 malicious; 20 clean | 96.87% · 90.31% · (not shown) | 70% | 0% | 30% |
| 2026-09-03 | [`c7771d2`](https://github.com/NOMARJ/sigil/commit/c7771d2) | 844 malicious (204/bucket); 20 clean | 88.86% · 79.62% · 63.98% | **75%** (15 of 20) | 0% | 30% |

Two rows in that table come from outside `evaluation_results/`, and a reader
should know which:

- **"FP after trust-ledger approval: 0%"** is the ledger-warm result of the
  **2026-06-11** run. The 2026-09-03 run recorded no ledger-warm pass, so the
  0% published alongside its numbers is carried over from the earlier run.
- **"FP ≥High with Pro AI adjudication: 30%"** comes from
  [`evidence/F-009/fp-adjudication-eval.md`](../evidence/F-009/fp-adjudication-eval.md)
  (14/20 → 6/20 on the 20-package control set). Its stated 70% "before"
  baseline is the **2026-06-11** FP rate, not the 75% published next to it in
  the 2026-09-03 table. That file also states the 30% residual is a per-target
  finding-cap artifact, not a verdict failure.

## Not a measurement

`archive/production_d1_d4_scorecard_80k_scans.json` claimed ~80k scans and 99%+
detection. It was never reproducible and reused the fabricated 82,415 figure from
the March 14 2026 fake-evaluation incident. It is retained under `archive/` with
a provenance note for audit history only and appears in no row above. See the
"Supersedes" section of
[`honest_detection_eval.md`](honest_detection_eval.md) and `CLAUDE.md`.

## How to add a row

1. Run the benchmark: `make benchmark SIGIL_EVAL_DATASET=… SIGIL_EVAL_CONTROL=…`
   (see [`docs/benchmarks.md`](../docs/benchmarks.md) for the method and
   [`docs/RELEASING.md`](../docs/RELEASING.md) for when in the release it runs).
2. Commit the regenerated `honest_detection_eval.{json,md}`.
3. Transcribe that report's numbers into a new row here, verbatim, and link the
   commit. If a value is absent from the report, write what the report says
   (`unknown`, `not recorded`) rather than filling it in from elsewhere.
