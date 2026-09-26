# Correlation chains: names as values, and one propagation step

Raw material for [docs/detection/correlation-names.md](../../docs/detection/correlation-names.md),
which has the method, the tables and the decision.

```
Data Source: Real samples, static scans only. Datadog malicious-software-packages-dataset at
             1dbcfc517277f3e3d32434f8f6a82e6e9fb75580 (run_eval.py selection, --limit 204,
             fingerprint 63fcde5b...); 204 malicious + 455 clean skills; 169 clean MCP servers
             (mcp_clean_manifest.json); 157 MCP servers from the reconstructed out-of-sample holdout
             (mcp_holdout_manifest.json, not the original holdout).
Sample Size: 844 Datadog packages, 659 skills, 326 MCP servers.
Limitations: The clean corpora contain few source/sink pairs (37 in 18 of 781 samples), so they
             cannot show the step's false positives well; the constructed probes in the doc do.
```

| File | What it is |
|---|---|
| `datadog.json` | `scripts/datadog_diff.py` over head (ef0b95f), `name_uses` (fa601b8), B and C; a second run of `name_uses` against the Python-braces fix; a third of the merged base (09d9fae) against the shipped tree: recall per build, and every max-severity, verdict and chain change between the builds compared. A change on a sample that hit the 30 s per-file budget is marked `budget_expired`; the two such changes in the first run are timing (see `budget_check`) |
| `benchmarks.json` | `scripts/benchmark_skills.py --tools sigil` outcomes: head's for every sample, then, for each pair of builds compared, every sample whose level, rule set or finding count changed (none did, apart from #170's own two holdout chains between head and the merged base) |
| `follow_assignment.patch` | B, the propagation step as measured (a per-rule `follow_assignment`, on for EXFIL-, AGENTSC- and DESER-CHAIN) |
| `follow_assignment_bare.patch` | C, on top of B: a derived name links only where it is used bare |
| `narrow_hop.patch` | The exfilchain lane's narrow one-hop follow with its tests, as measured in `hop.json`, against the port's final `cli/` (34eaa0b) |
| `hop.json` | The exfilchain lane's narrow one-hop follow (a derived name followed where the word reading's window names the bound one), measured against the port without it (34eaa0b): per-probe verdicts and chains for 37 hand-written probes (names and verdicts only; the doc describes each in words) with nine builds, including B and C rebuilt on 37c3140; the lane's 286 probes per build; the Datadog recall and every per-sample change (datadog_diff.py, empty HOME) and run_eval.py's aggregate; the skills, clean-MCP, unseen-MCP and parity comparisons. Real scans; the probes are synthetic |

None of the patches is part of the shipped code. B and C apply to fa601b8,
the tree they were measured on, and to #169's tree, 37c3140 (`git apply`);
with B applied, `exfil_chain_does_not_follow_a_two_hop_flow`
and `a_value_derived_from_a_credential_does_not_link` fail by design, because
those tests pin what the step would change. `narrow_hop.patch` applies to the
port's tree and replaces the first of those tests with the lane's
`exfil_chain_follows_a_two_hop_flow_the_word_reading_linked`.
