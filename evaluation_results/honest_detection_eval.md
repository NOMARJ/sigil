# Sigil Detection Evaluation — Honest Measurement

_Generated: 2026-09-27T08:40:07.793813+00:00_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm/PyPI packages) + caller-provided clean control set.
Sample Size: 844 malicious samples selected (204 per ecosystem/category bucket); 20 clean control packages.
Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's own disclaimer). Detection uses offline static phases only (install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection); OSV/provenance network feeds are excluded for reproducibility. Recall denominator excludes samples that failed to extract.
```

- Dataset commit: `1dbcfc517277f3e3d32434f8f6a82e6e9fb75580`
- Reproducibility fingerprint: `63fcde5babebf27dfb47833749a0a987c24e2bffd0228a412dd4910ebda73ade`
- Scanner: `release build of v1.3.7 (cli/ identical to 0b5a121)`
- Extract failures: 0 | scan errors: 0

## Recall (malicious samples detected)

| Threshold | Detected | Scanned | Recall |
|-----------|----------|---------|--------|
| >= any | 785 | 844 | 93.01% |
| >= Medium | 761 | 844 | 90.17% |
| >= High | 752 | 844 | 89.10% |
| >= Critical | 560 | 844 | 66.35% |

## False-positive rate (clean control flagged) & precision

| Threshold | Flagged | Control | FP rate | Precision |
|-----------|---------|---------|---------|-----------|
| >= any | 17 | 20 | 85.00% | 97.88% |
| >= Medium | 15 | 20 | 75.00% | 98.07% |
| >= High | 11 | 20 | 55.00% | 98.56% |
| >= Critical | 6 | 20 | 30.00% | 98.94% |

## Notes

- PRECISION IS IMBALANCE-DISTORTED: it was computed on 844 malicious vs 20 clean samples. With far more malicious than clean inputs, precision looks high even when most clean packages are flagged. Read the FP-rate column, not precision, as the real-world false-positive signal.
- HIGH FALSE-POSITIVE RATE: 75% of clean control packages (popular, legitimate npm/PyPI) are flagged at Medium/High. The static phases over-trigger on benign idioms (network calls, base64, env reads, minified code). Recall is strong but the rule set needs FP-narrowing before these severities can gate real-world installs without noise.

## Supersedes

This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to `archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures that could not be reproduced and shared the fabricated 82,415 figure from the March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.
