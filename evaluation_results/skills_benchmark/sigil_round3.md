# Skills (204 malicious, 455 clean): main 35c0155 against ws/exfil-port 8f8fd64

_Composed from two runs of `scripts/benchmark_skills.py --tools sigil --workers 2`, one per build._

```
Data Source: Real samples: DataDog malicious-software-packages-dataset ai-skills bucket (malicious);
             anthropics, NVIDIA, openai and vercel-labs skill catalogs (clean).
Sample Size: 204 malicious, 455 clean, each scanned once per build (35c0155, 8f8fd64).
Limitations: Real samples, static analysis only. 'Clean' means published, not audited.
             One run per build on a 4-core machine (--workers 2); the per-file time
             budget makes large files load-sensitive (PROV-BUDGET-001 is listed below).
             main 35c0155 predates the whole branch (the MCP false-positive pass, #169,
             #170 and this port), so main-vs-branch differences are not all this port's.
```

| Build | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Malicious any | Clean blocked | Clean warned | Clean any | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| main | 173/204 | 184/204 | 190/204 | 7/455 | 71/455 | 224/455 | 0 |
| branch | 173/204 | 184/204 | 190/204 | 7/455 | 71/455 | 224/455 | 0 |

Chains (samples each fires on): main {'AGENTSC-CHAIN-002': 4, 'EXFIL-CHAIN-001': 4, 'TLS-CHAIN-001': 1}; branch {'AGENTSC-CHAIN-002': 4, 'EXFIL-CHAIN-001': 4, 'TLS-CHAIN-001': 1}.

## Level changes (0)

None.

## Correlation-chain changes (0)

None.

Samples whose rule set or finding count changed at the same level: 2 (listed in the JSON). Samples where either build hit the per-file time budget (PROV-BUDGET-001): 0.
