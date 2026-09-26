# SkillSpector parity: main 35c0155 against ws/exfil-port 8f8fd64

```
Data Source: SkillSpector's own test suite, every finding its tests construct, de-duplicated
             (the parity corpus).
Sample Size: 1,796 examples, each scanned once per build (35c0155, 8f8fd64).
Limitations: Includes findings SkillSpector's later stages filter as false positives and test-only
             markers; measures agreement with SkillSpector's examples, not recall on malware.
```

| Build | Examples | Flagged at any severity | Flagged at High or above | Chains |
|---|---:|---:|---:|---|
| main | 1796 | 626 | 385 | {'EXFIL-CHAIN-001': 9} |
| branch | 1796 | 626 | 385 | {'EXFIL-CHAIN-001': 9} |

Examples whose highest severity or rule set differs: 0 (0 higher, 0 lower, 0 same severity with other rules). Per-rule breakdowns of each build are the two runs' own reports; every example is in the JSON.
