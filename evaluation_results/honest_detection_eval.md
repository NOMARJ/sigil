# Sigil Detection Evaluation — Honest Measurement

_Generated: 2026-09-03T16:07:08.321581+00:00_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm/PyPI packages) + caller-provided clean control set.
Sample Size: 844 malicious samples selected (204 per ecosystem/category bucket); 20 clean control packages.
Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's own disclaimer). Detection uses offline static phases only (install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection); OSV/provenance network feeds are excluded for reproducibility. Recall denominator excludes samples that failed to extract.
```

- Dataset commit: `unknown`
- Reproducibility fingerprint: `587e09d2a8bb6ab0bba65f086fb1b5f342dd24357725cdd22104c4fe60aebd0b`
- Scanner: `release build of this branch`
- Extract failures: 0 | scan errors: 0

## Recall (malicious samples detected)

| Threshold | Detected | Scanned | Recall |
|-----------|----------|---------|--------|
| >= any | 772 | 844 | 91.47% |
| >= Medium | 764 | 844 | 90.52% |
| >= High | 718 | 844 | 85.07% |
| >= Critical | 553 | 844 | 65.52% |

## False-positive rate (clean control flagged) & precision

| Threshold | Flagged | Control | FP rate | Precision |
|-----------|---------|---------|---------|-----------|
| >= any | 17 | 20 | 85.00% | 97.85% |
| >= Medium | 17 | 20 | 85.00% | 97.82% |
| >= High | 13 | 20 | 65.00% | 98.22% |
| >= Critical | 5 | 20 | 25.00% | 99.10% |

## Notes

- PRECISION IS IMBALANCE-DISTORTED: it was computed on 844 malicious vs 20 clean samples. With far more malicious than clean inputs, precision looks high even when most clean packages are flagged. Read the FP-rate column, not precision, as the real-world false-positive signal.
- HIGH FALSE-POSITIVE RATE: 85% of clean control packages (popular, legitimate npm/PyPI) are flagged at Medium/High. The static phases over-trigger on benign idioms (network calls, base64, env reads, minified code). Recall is strong but the rule set needs FP-narrowing before these severities can gate real-world installs without noise.

## Supersedes

This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to `archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures that could not be reproduced and shared the fabricated 82,415 figure from the March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.

## Verdicts on the clean control set

The `>= Critical` row above counts control packages containing a Critical-severity
*finding*. The verdict is a separate question, and it is the one a CI gate reads:

| | c7771d2 (main) | this branch |
|---|---:|---:|
| clean packages returning CRITICAL RISK | 6 of 20 | **0 of 20** |
| clean packages returning HIGH RISK or worse | 18 of 20 | 16 of 20 |

`CRED-006`, `CRED-030` and `INSTALL-001` are marked as corroborating evidence, so a
single one of them no longer drives a CRITICAL RISK verdict. They keep their severity
and their full score contribution.

Measured with `sigil scan <package> --no-cache` on the same 20 control packages, all
phases, isolated HOME.
