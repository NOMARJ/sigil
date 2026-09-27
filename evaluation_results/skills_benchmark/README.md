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
| `sigil_round3.{json,md}`, `mcp_sigil_round3.{json,md}`, `mcp_holdout_sigil_round3.{json,md}`, `parity_sigil_round3.{json,md}`, `datadog_round3_diff.json`, [`../honest_detection_eval_round3.{md,json}`](../honest_detection_eval_round3.md) | Sigil main (35c0155) against this branch's final build (`ws/lifecycle-shadow` ad57eff: the third MCP false-positive pass, #169, #170, the value-reading port, and the lifecycle rewrites made to fail closed on runners, dependencies, `directories.bin` and install-config side channels), sample by sample in both directions. MCP 169: 39 → 28 blocked, 125 → 89 warned, 46 servers down and none up. Holdout 146 ([`mcp_holdout146_manifest.json`](../corpora/mcp_holdout146_manifest.json)): 80 → 69 blocked, 135 → 115 warned, 30 down, none up. Skills and parity: no level change (parity 626 / 385). Datadog: recall 785 / 761 / 752 / 560 at any / Medium / High / Critical (561 at Critical on main — EXFIL-CHAIN-001 on one `artifact-lab-3-package` version). The final build was re-measured against `34eaa0b` (the branch before the fail-closed rewrites) on the 844 Datadog packages and shows 0 verdict, severity or chain changes, so the against-main figures are unchanged from that build. See [docs/detection/correlation-chains.md](../../docs/detection/correlation-chains.md#measurements) | the same skills, MCP servers and parity examples; 146 unseen MCP servers; 844 Datadog packages (`run_eval.py --limit 204`) | 2026-09-26 |

| `mcp_sigil_e34f017.{json,md}`, `mcp_holdout_sigil_e34f017.{json,md}`, `skills_e34f017.{json,md}`, `datadog_codex2v_diff.json` | Sigil against the final build of the adversarial verification of Codex's second #172 review (`ws/codex2` e34f017: six fail-closed fixes — H1 CODE-016 name/version validation, H2 SUPPLY-016 unbounded ctypes span, H3 SUPPLY-008 child_process-gated template→exec, H4 correlation shadowing by reference, H5 CODE-017 in-memory loader, INFER-CHAIN-001 hardcoded-key-to-non-vendor-endpoint, and the line-terminator-aware eval/exec method context). Clean MCP 169: 29 blocked, 95 warned (main 35c0155: 39, 125). Unseen 146: 70 blocked, 115 warned (main: 80, 135). Skills: 173 blocked, 184 warned of 204 malicious; 7 blocked, 71 warned of 455 clean. All clean-corpus figures are identical to `68a9d30` (the review's head before this verification): the seven clean-MCP and one holdout level-ups against base `955a469` are the credential-exemption removals from the review itself, not these fixes. Datadog (base `955a469` vs e34f017, `--limit 204`, 844 packages): 0 verdict, 0 highest-severity and 0 chain changes; recall 785 / 761 / 752 / 560 at any / Medium / High / Critical on both builds. The fixes catch crafted single-line and dispatch shapes not present in the real corpus. | 169 + 146 MCP servers, 204 malicious + 455 clean skills, 844 Datadog packages | 2026-09-27 |

SkillSpector's 455-skill figures are the sum of the baseline run (411) and the
openai run (44).
