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
| `sigil_tls.{json,md}`, `mcp_sigil_tls.{json,md}`, `parity_sigil_tls.{json,md}` | Sigil with the insecure-transport pack (TLS-*), final build after the adversarial review, [docs/detection/insecure-transport.md](../../docs/detection/insecure-transport.md). The first build's runs are in the commit that added the pack; re-run with that build, they reproduced sample for sample | the same skills, MCP servers and parity examples | 2026-09-25 |

SkillSpector's 455-skill figures are the sum of the baseline run (411) and the
openai run (44).
