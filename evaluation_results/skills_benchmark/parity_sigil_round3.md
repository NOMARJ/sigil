# SkillSpector parity: main 35c0155 against ws/lifecycle-shadow ad57eff

```
Data Source: SkillSpector's own test suite, every finding its tests construct, de-duplicated
             (the parity corpus).
Sample Size: 1,796 examples, each scanned once per build (35c0155, and 34eaa0b, whose
             figures carry to the final build ad57eff — see the note below).
Limitations: Includes findings SkillSpector's later stages filter as false positives and test-only
             markers; measures agreement with SkillSpector's examples, not recall on malware.
             The branch column was measured on 34eaa0b, not re-run on ad57eff: the parity
             corpus needs a SkillSpector checkout. It still describes ad57eff, because
             parity counts whether a finding is present (flagged) or reaches High, the
             lifecycle classifier only relabels findings (never removes one), and ad57eff
             rewrites a strict subset of 34eaa0b's (every fail-closed condition only prevents
             a rewrite). main (no classifier) and 34eaa0b both flag 626 / 385, so the final
             build, whose severities sit between them, also flags 626 / 385.
```

| Build | Examples | Flagged at any severity | Flagged at High or above | Chains |
|---|---:|---:|---:|---|
| main | 1796 | 626 | 385 | {'EXFIL-CHAIN-001': 9} |
| branch | 1796 | 626 | 385 | {'EXFIL-CHAIN-001': 9} |

Examples whose highest severity or rule set differs: 0 (0 higher, 0 lower, 0 same severity with other rules). Per-rule breakdowns of each build are the two runs' own reports; every example is in the JSON.
