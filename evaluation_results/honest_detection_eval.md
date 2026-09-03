# Sigil Detection Evaluation — Honest Measurement

_Generated: 2026-09-03T00:47:33.357661+00:00_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm/PyPI packages) + caller-provided clean control set.
Sample Size: 844 malicious samples selected (204 per ecosystem/category bucket); 20 clean control packages.
Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's own disclaimer). Detection uses offline static phases only (install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection); OSV/provenance network feeds are excluded for reproducibility. Recall denominator excludes samples that failed to extract.
```

- Dataset commit: `unknown`
- Reproducibility fingerprint: `587e09d2a8bb6ab0bba65f086fb1b5f342dd24357725cdd22104c4fe60aebd0b`
- Scanner: `/tmp/claude-0/-home-user-sigil/a564528b-cc52-54e2-877a-4ee2e50aa976/scratchpad/bin/sigil-final`
- Extract failures: 0 | scan errors: 0

## Recall (malicious samples detected)

| Threshold | Detected | Scanned | Recall |
|-----------|----------|---------|--------|
| >= any | 750 | 844 | 88.86% |
| >= Medium | 744 | 844 | 88.15% |
| >= High | 672 | 844 | 79.62% |
| >= Critical | 540 | 844 | 63.98% |

## False-positive rate (clean control flagged) & precision

| Threshold | Flagged | Control | FP rate | Precision |
|-----------|---------|---------|---------|-----------|
| >= any | 18 | 20 | 90.00% | 97.66% |
| >= Medium | 17 | 20 | 85.00% | 97.77% |
| >= High | 15 | 20 | 75.00% | 97.82% |
| >= Critical | 5 | 20 | 25.00% | 99.08% |

## Notes

- PRECISION IS IMBALANCE-DISTORTED: it was computed on 844 malicious vs 20 clean samples. With far more malicious than clean inputs, precision looks high even when most clean packages are flagged. Read the FP-rate column, not precision, as the real-world false-positive signal.
- HIGH FALSE-POSITIVE RATE: 85% of clean control packages (popular, legitimate npm/PyPI) are flagged at Medium/High. The static phases over-trigger on benign idioms (network calls, base64, env reads, minified code). Recall is strong but the rule set needs FP-narrowing before these severities can gate real-world installs without noise.

## Supersedes

This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to `archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures that could not be reproduced and shared the fabricated 82,415 figure from the March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.
