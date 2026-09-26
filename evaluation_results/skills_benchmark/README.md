# Skill and MCP-server benchmark runs

Raw per-sample outcomes behind [docs/comparison/skillspector.md](../../docs/comparison/skillspector.md).
Every file was produced by `scripts/benchmark_skills.py` running the scanners
on real samples. Nothing is simulated. Corpus paths are shortened to
`corpora/…`.

```
Data Source: Real samples. Malicious: DataDog malicious-software-packages-dataset, ai-skills bucket.
             Clean skills: anthropics/skills, NVIDIA/skills, openai/skills, vercel-labs/agent-skills.
             Clean MCP servers: evaluation_results/corpora/mcp_clean_manifest.json.
Sample Size: 204 malicious skills, 455 clean skills, 169 clean MCP servers.
Limitations: Static analysis only (SkillSpector --no-llm). "Clean" is published, not audited.
```

| File | Scanner | Samples | Date |
|---|---|---|---|
| `sigil_7826ea1.{json,md}` | Sigil, final build of this change | 204 malicious + 455 clean skills | 2026-09-24 |
| `sigil_dc82a94.{json,md}` | Sigil before this change | 204 malicious + 455 clean skills | 2026-09-23 |
| `baseline_2026-09-23_sigil-dc82a94_skillspector-2.11.2.{json,md}` | Sigil before this change and SkillSpector 2.11.2, same run | 204 malicious + 411 clean skills (openai/skills was missed by discovery at the time: its skills sit under a hidden `.curated/` directory) | 2026-09-23 |
| `skillspector-2.11.2_openai-skills_2026-09-23.{json,md}` | SkillSpector 2.11.2 | the 44 openai/skills skills the baseline missed | 2026-09-23 |
| `mcp_sigil_7826ea1.{json,md}` | Sigil, final build of this change | 169 clean MCP servers | 2026-09-24 |
| `mcp_skillspector-2.11.2.{json,md}` | SkillSpector 2.11.2, `--timeout 600` | 169 clean MCP servers (156 finished, 13 timed out) | 2026-09-24 |
| `parity_sigil_7826ea1.{json,md}` | Sigil, final build of this change, on `scripts/skillspector_parity.py run` | 1,796 examples from SkillSpector's own test suite | 2026-09-24 |
| `sigil_tls.{json,md}`, `mcp_sigil_tls.{json,md}`, `parity_sigil_tls.{json,md}` | Sigil with the insecure-transport pack (TLS-*), final build after the second adversarial review, [docs/detection/insecure-transport.md](../../docs/detection/insecure-transport.md). The runs of the two earlier builds (the pack's first commit and the first review) are in the commits that published them; the verdict level of every sample, and the result of every parity example, is the same in all three | the same skills, MCP servers and parity examples | 2026-09-25 |
| `sigil_exfilchain.{json,md}`, `mcp_sigil_exfilchain.{json,md}`, `mcp_holdout_sigil_exfilchain.{json,md}`, `parity_sigil_exfilchain.{json,md}`, `datadog_exfilchain_diff.json`, [`../honest_detection_eval_exfilchain.{md,json}`](../honest_detection_eval_exfilchain.md) | **The exfilchain lane's own build (`ws/exfilchain-v` d89c600), with its one-hop follow on; not the build this branch ships**, which leaves that follow out and has not been re-measured on these corpora yet (the next measurement replaces these files). Sigil with every correlation chain reading names as sent values (`name_uses`: code only, the sink's own call, and in this build one hop followed where the old reading linked), final build after the attack review, [docs/detection/correlation-chains.md](../../docs/detection/correlation-chains.md). Compared sample by sample, both directions, with the release build of cff3fa2: no verdict level or highest-severity change in any corpus; the only finding that moved is DROPPER-CHAIN-001 on two one-line `.js.map` source maps of the unseen MCP servers (removed, both servers stay CRITICAL); Datadog has the same rules, finding count and chain findings on every package (the file lists every sample). The two MCP files are the second run of the final build: the first had two files truncated by the per-file budget under load (see the docs page) | the same skills, MCP servers and parity examples; 146 unseen MCP servers; 844 Datadog packages (`run_eval.py --limit 204`) | 2026-09-26 |

SkillSpector's 455-skill figures are the sum of the baseline run (411) and the
openai run (44).
