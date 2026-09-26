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
| `sigil_round3.{json,md}`, `mcp_sigil_round3.{json,md}`, `mcp_holdout_sigil_round3.{json,md}`, `parity_sigil_round3.{json,md}`, `datadog_round3_diff.json`, [`../honest_detection_eval_round3.{md,json}`](../honest_detection_eval_round3.md) | Sigil main (35c0155) against this branch's final build (`ws/exfil-port` 34eaa0b: the third MCP false-positive pass, #169, #170 and the port of the value reading with both verifications' fixes, one-hop follow off), sample by sample in both directions; the 169 MCP servers and the Datadog packages also with e45efc5 (the branch before the port). MCP 169: 39 → 24 blocked, 125 → 76 warned, 62 servers down and none up, all from the false-positive pass (e45efc5 and 34eaa0b identical on every server). Holdout 146 ([`mcp_holdout146_manifest.json`](../corpora/mcp_holdout146_manifest.json)): 80 → 66 blocked, 135 → 114 warned, 34 down, none up; DROPPER-CHAIN-001 leaves two one-line source maps (#170). Skills and parity: no level change (parity 626 / 385). Datadog: EXFIL-CHAIN-001 leaves 21 `artifact-lab-3-package` versions (17 already with e45efc5, 4 with the port), one of which drops from CRITICAL to HIGH RISK, so recall at Critical is 560 (561 on main); 785 / 761 / 752 at any / Medium / High unchanged. See [docs/detection/correlation-chains.md](../../docs/detection/correlation-chains.md#measurements) | the same skills, MCP servers and parity examples; 146 unseen MCP servers; 844 Datadog packages (`run_eval.py --limit 204`) | 2026-09-26 |

SkillSpector's 455-skill figures are the sum of the baseline run (411) and the
openai run (44).
