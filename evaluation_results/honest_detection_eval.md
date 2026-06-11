# Sigil Detection Evaluation — Honest Measurement

_Generated: 2026-06-11T07:00:16.155537+00:00_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm/PyPI packages) + caller-provided clean control set.
Sample Size: 351 malicious samples selected (110 per ecosystem/category bucket); 20 clean control packages.
Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's own disclaimer). Detection uses offline static phases only (install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection); OSV/provenance network feeds are excluded for reproducibility. Recall denominator excludes samples that failed to extract.
```

- Dataset commit: `605a7318822117b3b29466747e65db1d582f290c`
- Reproducibility fingerprint: `5f7ebb09543449f01fff5216fe610f545a7abb78dba4b1eb3080ad6599a050bb`
- Scanner: `/Users/reecefrazier/CascadeProjects/sigil/cli/target/release/sigil`
- Extract failures: 0 | scan errors: 0

## Recall (malicious samples detected)

| Threshold | Detected | Scanned | Recall |
|-----------|----------|---------|--------|
| >= any | 340 | 351 | 96.87% |
| >= Medium | 339 | 351 | 96.58% |
| >= High | 317 | 351 | 90.31% |
| >= Critical | 209 | 351 | 59.54% |

## False-positive rate (clean control flagged) & precision

| Threshold | Flagged | Control | FP rate | Precision |
|-----------|---------|---------|---------|-----------|
| >= any | 17 | 20 | 85.00% | 95.24% |
| >= Medium | 16 | 20 | 80.00% | 95.49% |
| >= High | 14 | 20 | 70.00% | 95.77% |
| >= Critical | 4 | 20 | 20.00% | 98.12% |

## Notes

- PRECISION IS IMBALANCE-DISTORTED: it was computed on 351 malicious vs 20 clean samples. With far more malicious than clean inputs, precision looks high even when most clean packages are flagged. Read the FP-rate column, not precision, as the real-world false-positive signal.
- HIGH FALSE-POSITIVE RATE: 80% of clean control packages (popular, legitimate npm/PyPI) are flagged at Medium/High. The static phases over-trigger on benign idioms (network calls, base64, env reads, minified code). Recall is strong but the rule set needs FP-narrowing before these severities can gate real-world installs without noise.

## Supersedes

This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to `archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures that could not be reproduced and shared the fabricated 82,415 figure from the March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.
