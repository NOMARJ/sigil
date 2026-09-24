# Skill scanner head-to-head

_Generated 2026-09-23T19:25:35+00:00 by `scripts/benchmark_skills.py`._

```
Data Source: Real samples. Malicious: 
             Clean: openai_skills
Sample Size: 0 malicious, 44 clean (per-corpus counts below)
Limitations: Static analysis only for every tool (SkillSpector --no-llm, Sigil offline
             phases). 'Clean' means published by a reputable vendor catalog, not audited;
             a vendor skill that legitimately shells out or reads credentials can be a
             correct finding, so the FP column is an upper bound on true false positives.
```

| Corpus | Samples |
|---|---:|
| clean:openai_skills | 44 |

## Results

| Tool | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked (FP) | Clean warned (FP) | Errors | Scan time |
|---|---:|---:|---:|---:|---:|---:|
| skillspector | 0/0 (n/a) | 0/0 (n/a) | 13/44 (29.5%) | 29/44 (65.9%) | 0 | 337s |

## Clean samples blocked

- skillspector: `corpora/openai_skills/skills/.curated/chatgpt-apps` — HIGH ['AE1', 'LP3', 'P1']
- skillspector: `corpora/openai_skills/skills/.curated/cloudflare-deploy` — CRITICAL ['AE4', 'E1', 'E3', 'E4', 'EA2', 'EA4', 'P2', 'PE1']
- skillspector: `corpora/openai_skills/skills/.curated/figma-use` — CRITICAL ['AE1', 'AR3', 'E1', 'EA1', 'P3', 'P9', 'YR4']
- skillspector: `corpora/openai_skills/skills/.curated/migrate-to-codex` — CRITICAL ['AS1', 'AS2', 'AST7', 'EA2', 'LP3', 'RA1', 'RA2']
- skillspector: `corpora/openai_skills/skills/.curated/notion-knowledge-capture` — HIGH ['E4', 'EA2', 'EA3', 'PE2']
- skillspector: `corpora/openai_skills/skills/.curated/openai-docs` — HIGH ['AE1', 'LP3', 'P6']
- skillspector: `corpora/openai_skills/skills/.curated/security-best-practices` — CRITICAL ['AR2', 'E1', 'EA1', 'EA2', 'EA4', 'OH1', 'OH3', 'P1']
- skillspector: `corpora/openai_skills/skills/.curated/security-ownership-map` — HIGH ['AST4', 'LP3', 'P6', 'TM3']
- skillspector: `corpora/openai_skills/skills/.curated/speech` — CRITICAL ['AS1', 'AST7', 'EA2', 'LP3', 'P6', 'TM1']
- skillspector: `corpora/openai_skills/skills/.curated/winui-app` — HIGH ['EA2', 'P1', 'P9', 'RA1']
- skillspector: `corpora/openai_skills/skills/.system/imagegen` — CRITICAL ['AS1', 'AST7', 'EA2', 'LP3', 'P6', 'TM1']
- skillspector: `corpora/openai_skills/skills/.system/openai-docs` — HIGH ['AE1', 'LP3', 'P6']
- skillspector: `corpora/openai_skills/skills/.system/plugin-creator` — HIGH ['AE1', 'LP3', 'RA1', 'RA2']
