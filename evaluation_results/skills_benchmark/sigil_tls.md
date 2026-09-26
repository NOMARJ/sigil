# Skill scanner head-to-head

_Generated 2026-09-25T14:16:36+00:00 by `scripts/benchmark_skills.py`._

```
Data Source: Real samples. Malicious: mal_skills
             Clean: anthropics_skills, NVIDIA_skills, openai_skills, vercel-labs_agent-skills
Sample Size: 204 malicious, 455 clean (per-corpus counts below)
Limitations: Static analysis only for every tool (SkillSpector --no-llm, Sigil offline
             phases). 'Clean' means published by a reputable vendor catalog, not audited;
             a vendor skill that legitimately shells out or reads credentials can be a
             correct finding, so the FP column is an upper bound on true false positives.
```

| Corpus | Samples |
|---|---:|
| malicious:mal_skills | 204 |
| clean:anthropics_skills | 20 |
| clean:NVIDIA_skills | 382 |
| clean:openai_skills | 44 |
| clean:vercel-labs_agent-skills | 9 |

## Results

| Tool | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked (FP) | Clean warned (FP) | Errors | Scan time |
|---|---:|---:|---:|---:|---:|---:|
| sigil | 173/204 (84.8%) | 184/204 (90.2%) | 7/455 (1.5%) | 71/455 (15.6%) | 0 | 644s |

## Clean samples blocked

- sigil: `corpora/NVIDIA_skills/skills/doca-upgrade` — HIGH ['MANIP-004'] (High/Critical: ['MANIP-004'])
- sigil: `corpora/NVIDIA_skills/skills/tao-run-on-brev` — HIGH ['NET-012', 'NET-RCE-001', 'PROMPT-017', 'SKILL-008'] (High/Critical: ['NET-RCE-001'])
- sigil: `corpora/NVIDIA_skills/skills/tao-setup` — HIGH ['AGENTSC-030', 'INSTR-014', 'SKILL-008'] (High/Critical: ['INSTR-014'])
- sigil: `corpora/openai_skills/skills/.curated/figma` — HIGH ['PERSIST-004', 'PROMPT-014'] (High/Critical: ['PROMPT-014'])
- sigil: `corpora/openai_skills/skills/.curated/migrate-to-codex` — HIGH ['PROMPT-014', 'PROMPT-015', 'PROMPT-017'] (High/Critical: ['PROMPT-014', 'PROMPT-015'])
- sigil: `corpora/openai_skills/skills/.curated/playwright-interactive` — HIGH ['PROMPT-015'] (High/Critical: ['PROMPT-015'])
- sigil: `corpora/vercel-labs_agent-skills/skills/vercel-optimize` — HIGH ['CODE-002', 'CODE-007', 'OBFUSC-003', 'PROMPT-017'] (High/Critical: ['CODE-002'])
