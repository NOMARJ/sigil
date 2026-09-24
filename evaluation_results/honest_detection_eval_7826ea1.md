# Sigil Detection Evaluation — Honest Measurement

_Generated: 2026-09-24T09:37:36.743877+00:00_

## Disclosure (mandatory, per CLAUDE.md)

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm/PyPI packages) + caller-provided clean control set.
Sample Size: 844 malicious samples selected (204 per ecosystem/category bucket); 0 clean control packages.
Limitations: Dataset has selection bias (mostly GuardDog-identified, per Datadog's own disclaimer). Detection uses offline static phases only (install_hooks,code_patterns,network_exfil,credentials,obfuscation,prompt_injection); OSV/provenance network feeds are excluded for reproducibility. Recall denominator excludes samples that failed to extract.
```

- Dataset commit: `1dbcfc517277f3e3d32434f8f6a82e6e9fb75580`
- Reproducibility fingerprint: `63fcde5babebf27dfb47833749a0a987c24e2bffd0228a412dd4910ebda73ade`
- Scanner: `release build of 7826ea1`
- Extract failures: 0 | scan errors: 0

## Recall (malicious samples detected)

| Threshold | Detected | Scanned | Recall |
|-----------|----------|---------|--------|
| >= any | 785 | 844 | 93.01% |
| >= Medium | 761 | 844 | 90.17% |
| >= High | 752 | 844 | 89.10% |
| >= Critical | 561 | 844 | 66.47% |

## Notes

- No --control-path supplied: precision / false-positive rate NOT measured. Recall is reported alone; do not infer precision.

## Supersedes

This report replaces `production_d1_d4_scorecard_80k_scans.json` (moved to `archive/` with a provenance note). That artifact claimed 80k-scan / 99%+ figures that could not be reproduced and shared the fabricated 82,415 figure from the March 14 2026 fake-eval incident. Whatever the numbers above are, they are real.
