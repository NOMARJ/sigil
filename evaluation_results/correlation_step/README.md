# Correlation chains: names as values, and one propagation step

Raw material for [docs/detection/correlation-names.md](../../docs/detection/correlation-names.md),
which has the method, the tables and the decision.

```
Data Source: Real samples, static scans only. Datadog malicious-software-packages-dataset at
             1dbcfc517277f3e3d32434f8f6a82e6e9fb75580 (run_eval.py selection, --limit 204,
             fingerprint 63fcde5b...); 204 malicious + 455 clean skills; 169 clean MCP servers
             (mcp_clean_manifest.json); 154 MCP servers re-derived from the holdout's criteria
             (mcp_holdout_rederived_manifest.json, not the original holdout).
Sample Size: 844 Datadog packages, 659 skills, 323 MCP servers.
Limitations: The clean corpora contain few source/sink pairs (37 in 18 of 778 samples), so they
             cannot show the step's false positives well; the constructed probes in the doc do.
```

| File | What it is |
|---|---|
| `datadog.json` | `scripts/datadog_diff.py` over head (ef0b95f), `name_uses` (fa601b8), B and C, and a second run of `name_uses` against the shipped build (Python braces read as values): recall per build, and every max-severity, verdict and chain change between the builds compared. A change on a sample that hit the 30 s per-file budget is marked `budget_expired`; the two such changes in the first run are timing (see `budget_check`) |
| `benchmarks.json` | `scripts/benchmark_skills.py --tools sigil` outcomes: head's for every sample, then every sample whose level, rule set or finding count changed from one build to the next (none did) |
| `follow_assignment.patch` | B, the propagation step as measured (a per-rule `follow_assignment`, on for EXFIL-, AGENTSC- and DESER-CHAIN) |
| `follow_assignment_bare.patch` | C, on top of B: a derived name links only where it is used bare |

Neither patch is part of the shipped code. They apply to fa601b8, the tree
they were measured on (`git apply`); with B applied, `exfil_chain_does_not_follow_a_two_hop_flow`
and `a_value_derived_from_a_credential_does_not_link` fail by design, because
those tests pin what the step would change.
