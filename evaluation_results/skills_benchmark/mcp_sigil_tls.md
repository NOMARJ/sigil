# Skill scanner head-to-head

_Generated 2026-09-25T09:06:26+00:00 by `scripts/benchmark_skills.py`._

```
Data Source: Real samples. Malicious: 
             Clean: mcp_clean
Sample Size: 0 malicious, 169 clean (per-corpus counts below)
Limitations: Static analysis only for every tool (SkillSpector --no-llm, Sigil offline
             phases). 'Clean' means published by a reputable vendor catalog, not audited;
             a vendor skill that legitimately shells out or reads credentials can be a
             correct finding, so the FP column is an upper bound on true false positives.
```

| Corpus | Samples |
|---|---:|
| clean:mcp_clean | 169 |

## Results

| Tool | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked (FP) | Clean warned (FP) | Errors | Scan time |
|---|---:|---:|---:|---:|---:|---:|
| sigil | 0/0 (n/a) | 0/0 (n/a) | 39/169 (23.1%) | 125/169 (74.0%) | 0 | 505s |

## Clean samples blocked

- sigil: `corpora/mcp_clean/ai.autoblocks__ctxl` — HIGH ['CRED-006', 'HYGIENE-005'] (High/Critical: ['CRED-006'])
- sigil: `corpora/mcp_clean/ai.dimensions__analytics-mcp` — CRITICAL ['CODE-007', 'CODE-MCP-001', 'CRED-002', 'CRED-007', 'CRED-ENV-001', 'HYGIENE-001', 'INFER-002', 'INFER-007'] (High/Critical: ['CRED-007', 'INFER-007', 'NET-RCE-001'])
- sigil: `corpora/mcp_clean/com.aave__mcp` — HIGH ['INSTALL-004', 'NET-012', 'OBFUSC-002', 'PROMPT-003'] (High/Critical: ['PROMPT-003'])
- sigil: `corpora/mcp_clean/com.altmetric.mcp__altmetric-mcp` — HIGH ['CRED-001', 'CRED-002', 'NET-012', 'NET-RCE-001', 'PROMPT-007'] (High/Critical: ['NET-RCE-001', 'PROMPT-007'])
- sigil: `corpora/mcp_clean/com.apideck__mcp` — HIGH ['CODE-002', 'CODE-003', 'CODE-006', 'CODE-007', 'CODE-012', 'CODE-MCP-001', 'CRED-002', 'CRED-007'] (High/Critical: ['CODE-002', 'CRED-007', 'CRED-008', 'OBFUSC-006', 'OBFUSC-CHAIN-006', 'SUPPLY-007', 'SUPPLY-008'])
- sigil: `corpora/mcp_clean/com.audioeye__testing-sdk-mcp` — HIGH ['CODE-008', 'CODE-009', 'CODE-012', 'CRED-002', 'INFER-010', 'INFER-011', 'PROMPT-014'] (High/Critical: ['CODE-008', 'CODE-009', 'PROMPT-014'])
- sigil: `corpora/mcp_clean/com.automox__automox-mcp` — CRITICAL ['CODE-011', 'CODE-014', 'CODE-MCP-001', 'CRED-001', 'CRED-007', 'NET-010', 'NET-013', 'NET-MCP-001'] (High/Critical: ['CODE-014', 'CRED-007', 'NET-013', 'OBFUSC-CHAIN-006', 'PROMPT-001', 'PROMPT-002', 'PROMPT-004'])
- sigil: `corpora/mcp_clean/com.browser-use__browser-use` — CRITICAL ['CODE-002', 'CODE-004', 'CODE-011', 'CODE-013', 'CODE-MCP-001', 'CRED-001', 'CRED-007', 'CRED-040'] (High/Critical: ['CODE-002', 'CRED-007', 'CRED-040', 'NET-008', 'NET-RCE-001', 'PROMPT-003'])
- sigil: `corpora/mcp_clean/com.gitkraken__gk-cli` — CRITICAL ['CODE-007', 'INSTALL-003', 'SKILL-006'] (High/Critical: ['INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/com.keboola__mcp` — CRITICAL ['CODE-MCP-001', 'CRED-001', 'NET-007', 'NET-012', 'OBFUSC-001', 'OBFUSC-011', 'SKILL-012'] (High/Critical: ['NET-007', 'SKILL-012'])
- sigil: `corpora/mcp_clean/com.microsoft__azure` — CRITICAL ['CODE-007', 'CODE-012', 'CODE-014', 'CODE-MCP-001', 'INSTALL-003', 'SKILL-006'] (High/Critical: ['CODE-014', 'INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/com.microsoft__microsoft-fabric` — CRITICAL ['CODE-007', 'CODE-012', 'CODE-014', 'CODE-MCP-001', 'INSTALL-003', 'SKILL-006', 'SKILL-015'] (High/Critical: ['CODE-014', 'INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/com.microsoft__template-server-name` — CRITICAL ['CODE-007', 'CODE-012', 'CODE-014', 'CODE-MCP-001', 'INSTALL-003', 'SKILL-006', 'SKILL-015'] (High/Critical: ['CODE-014', 'INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/com.postman__postman-mcp-server` — CRITICAL ['INFER-002', 'INSTALL-003', 'SKILL-006'] (High/Critical: ['INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/com.tracklution__server-side-tracking` — HIGH ['CODE-007', 'CRED-011', 'NET-MCP-002'] (High/Critical: ['CRED-011'])
- sigil: `corpora/mcp_clean/dev.rivet__mcp` — HIGH ['CODE-003', 'CODE-008', 'CODE-009', 'HYGIENE-001', 'NET-018', 'NET-MCP-002', 'OBFUSC-002', 'OBFUSC-003'] (High/Critical: ['CODE-008', 'CODE-009', 'NET-018', 'OBFUSC-006', 'OBFUSC-012', 'SUPPLY-013', 'SUPPLY-014'])
- sigil: `corpora/mcp_clean/dev.svelte__mcp` — CRITICAL ['CODE-003', 'CODE-012', 'HYGIENE-001', 'NET-018', 'NET-MCP-002', 'OBFUSC-002', 'OBFUSC-003', 'OBFUSC-004'] (High/Critical: ['NET-018', 'SUPPLY-001', 'SUPPLY-007', 'SUPPLY-011', 'SUPPLY-013', 'SUPPLY-016'])
- sigil: `corpora/mcp_clean/io.frase__mcp-server` — HIGH ['CODE-003', 'CODE-007', 'CODE-014', 'CODE-MCP-001', 'CRED-002', 'HYGIENE-001', 'INSTALL-004', 'OBFUSC-002'] (High/Critical: ['CODE-014'])
- sigil: `corpora/mcp_clean/io.fusionauth__mcp-api` — HIGH ['CODE-001', 'HYGIENE-001'] (High/Critical: ['CODE-001'])
- sigil: `corpora/mcp_clean/io.github.Azure__containerization-assist` — HIGH ['CODE-001', 'CODE-006', 'CODE-007', 'CODE-MCP-001', 'CRED-002', 'CRED-ENV-001', 'HYGIENE-001', 'INSTALL-004'] (High/Critical: ['CODE-001', 'MANIP-004', 'NET-RCE-001', 'PERSIST-001'])
- sigil: `corpora/mcp_clean/io.github.ChromeDevTools__chrome-devtools-mcp` — CRITICAL ['CODE-001', 'CODE-002', 'CODE-003', 'CODE-007', 'CODE-008', 'CODE-009', 'CODE-012', 'CODE-014'] (High/Critical: ['CODE-001', 'CODE-002', 'CODE-008', 'CODE-009', 'CODE-014', 'CRED-007', 'CRED-018', 'OBFUSC-CHAIN-010', 'OBFUSC-CHAIN-011', 'SUPPLY-008', 'SUPPLY-014'])
- sigil: `corpora/mcp_clean/io.github.NVIDIA__elements` — HIGH ['CODE-003', 'CODE-006', 'CODE-007', 'CODE-008', 'CODE-009', 'CODE-014', 'CODE-RUNFILE-001', 'CRED-008'] (High/Critical: ['CODE-008', 'CODE-009', 'CODE-014', 'CRED-008', 'NET-RCE-001', 'OBFUSC-CHAIN-006', 'PROMPT-004', 'SUPPLY-008'])
- sigil: `corpora/mcp_clean/io.github.SAP-samples__hana-cli` — CRITICAL ['ARTIFACT-007', 'ARTIFACT-008', 'ARTIFACT-011', 'CODE-001', 'CODE-002', 'CODE-003', 'CODE-007', 'CODE-008'] (High/Critical: ['ARTIFACT-011', 'CODE-001', 'CODE-002', 'CODE-008', 'CODE-009', 'CODE-014', 'CRED-008', 'CRED-011', 'CRED-033', 'DEPSRC-005', 'GHSA-28wg-ghj8-5hjv', 'GHSA-2v37-7h3g-55p8', 'GHSA-4r6h-8v6p-xvw6', 'GHSA-5pgg-2g8v-p4x9', 'GHSA-8r6m-32jq-jx6q', 'GHSA-r28c-9q8g-f849', 'INSTALL-003', 'MANIP-004', 'NET-RCE-001', 'OBFUSC-006', 'OBFUSC-CHAIN-006', 'OBFUSC-CHAIN-010', 'PERSIST-005', 'PROMPT-004', 'PROMPT-014', 'SKILL-006', 'SUPPLY-001', 'SUPPLY-007', 'SUPPLY-008', 'SUPPLY-014'])
- sigil: `corpora/mcp_clean/io.github.SAP__fiori-mcp-server` — HIGH ['CODE-003', 'CODE-008', 'CODE-009', 'CODE-012', 'CRED-ENV-001', 'INFER-010', 'INFER-011', 'NET-012'] (High/Critical: ['CODE-008', 'CODE-009', 'NET-013', 'OBFUSC-CHAIN-015', 'PERSIST-005', 'SUPPLY-008', 'SUPPLY-014'])
- sigil: `corpora/mcp_clean/io.github.awslabs__mcp-server-for-oscal` — CRITICAL ['ARTIFACT-007', 'CODE-010', 'CODE-011', 'CODE-013', 'CODE-MCP-001', 'CRED-001', 'CRED-ENV-001', 'GHSA-4q5v-7g7x-j79w'] (High/Critical: ['GHSA-4q5v-7g7x-j79w', 'GHSA-537c-gmf6-5ccf', 'GHSA-5rvq-cxj2-64vf', 'GHSA-82r6-8w77-94w6', 'GHSA-82w8-qh3p-5jfq', 'GHSA-g3vg-vx23-3858', 'GHSA-g6cj-pr64-35w5', 'GHSA-gg2g-p7xc-qqmm', 'GHSA-h47f-gmjp-m7rr', 'GHSA-hvrp-rf83-w775', 'GHSA-jpw9-pfvf-9f58', 'GHSA-jw39-3688-r4rx', 'GHSA-jwv3-5hgf-82ww', 'GHSA-mf9v-mfxr-j63j', 'GHSA-mr95-65j8-9mxp', 'GHSA-pp6c-gr5w-3c5g', 'GHSA-qccp-gfcp-xxvc', 'GHSA-r4vp-3vw6-r2x5', 'GHSA-vj7q-gjh5-988w', 'GHSA-wqp7-x3pw-xc5r', 'GHSA-xgmm-8j9v-c9wx', 'OBFUSC-CHAIN-017', 'PYSEC-2026-142', 'PYSEC-2026-161', 'PYSEC-2026-179', 'PYSEC-2026-2132', 'PYSEC-2026-2281', 'PYSEC-2026-2423', 'PYSEC-2026-2424', 'PYSEC-2026-2425', 'PYSEC-2026-2426', 'PYSEC-2026-249', 'PYSEC-2026-3036', 'PYSEC-2026-3039', 'PYSEC-2026-3481', 'PYSEC-2026-3482', 'PYSEC-2026-3483', 'PYSEC-2026-3552', 'PYSEC-2026-3553', 'PYSEC-2026-3554', 'PYSEC-2026-36', 'PYSEC-2026-3659', 'PYSEC-2026-3817'])
- sigil: `corpora/mcp_clean/io.github.cloudinary__asset-management-mcp` — HIGH ['CODE-003', 'CODE-012', 'CODE-MCP-001', 'CRED-002', 'CRED-007', 'HYGIENE-001', 'INFER-011', 'INSTALL-004'] (High/Critical: ['CRED-007', 'OBFUSC-006', 'OBFUSC-CHAIN-006', 'SUPPLY-007', 'SUPPLY-008'])
- sigil: `corpora/mcp_clean/io.github.dynatrace-oss__Dynatrace-mcp` — HIGH ['CODE-001', 'CODE-003', 'CODE-007', 'CODE-012', 'CODE-MCP-001', 'CRED-002', 'NET-012', 'OBFUSC-002'] (High/Critical: ['CODE-001', 'PERSIST-001'])
- sigil: `corpora/mcp_clean/io.github.firebase__firebase-mcp` — HIGH ['CODE-003', 'CODE-007', 'CODE-012', 'CRED-002', 'CRED-008', 'CRED-018', 'CRED-ENV-001', 'INSTALL-MCP-002'] (High/Critical: ['CRED-008', 'CRED-018', 'NET-RCE-001', 'SUPPLY-007', 'TYPOSQUAT-001'])
- sigil: `corpora/mcp_clean/io.github.localstack__localstack-mcp-server` — HIGH ['CODE-001', 'CODE-002', 'CODE-003', 'CODE-007', 'CODE-012', 'CRED-002', 'CRED-ENV-001', 'INFER-002'] (High/Critical: ['CODE-001', 'CODE-002', 'INFER-004', 'INFER-005'])
- sigil: `corpora/mcp_clean/io.github.mapbox__mcp-devkit-server` — CRITICAL ['CRED-002', 'HYGIENE-001', 'INSTALL-003', 'INSTR-019', 'OBFUSC-003', 'OBFUSC-008', 'PROMPT-017', 'SKILL-006'] (High/Critical: ['INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/io.github.mapbox__mcp-server` — CRITICAL ['CODE-007', 'CRED-002', 'HYGIENE-001', 'INSTALL-003', 'INSTALL-004', 'SKILL-006'] (High/Critical: ['INSTALL-003', 'SKILL-006'])
- sigil: `corpora/mcp_clean/io.github.mongodb-js__mongodb-mcp-server` — HIGH ['CODE-002', 'CODE-003', 'CODE-007', 'CODE-012', 'HYGIENE-001', 'INFER-010', 'INFER-011', 'MANIP-008'] (High/Critical: ['CODE-002'])
- sigil: `corpora/mcp_clean/io.github.mozilla__firefox-devtools-mcp` — HIGH ['CODE-003', 'CODE-007', 'CODE-014', 'CRED-002', 'INSTALL-004', 'OBFUSC-002', 'OBFUSC-003', 'OBFUSC-004'] (High/Critical: ['CODE-014'])
- sigil: `corpora/mcp_clean/io.github.vercel__next-devtools-mcp` — HIGH ['AGENTSC-030', 'CODE-007', 'CRED-002', 'INSTR-014', 'NET-004', 'PERSIST-004', 'TLS-004'] (High/Critical: ['INSTR-014'])
- sigil: `corpora/mcp_clean/io.qase__mcp-server` — HIGH ['CODE-002', 'CRED-002', 'HYGIENE-001', 'INSTALL-004', 'MANIP-008', 'NET-012', 'NET-MCP-002', 'OBFUSC-003'] (High/Critical: ['CODE-002', 'PROMPT-014'])
- sigil: `corpora/mcp_clean/io.scrapfly.mcp__mcp` — HIGH ['GHSA-5cv4-jp36-h3mw', 'GHSA-89xv-2j6f-qhc8', 'GHSA-q382-vc8q-7jhj', 'GHSA-wvj2-96wp-fq3f', 'GHSA-xw59-hvm2-8pj6', 'GO-2026-4569', 'GO-2026-4770', 'GO-2026-4773'] (High/Critical: ['GHSA-89xv-2j6f-qhc8', 'GHSA-q382-vc8q-7jhj', 'GHSA-wvj2-96wp-fq3f', 'GHSA-xw59-hvm2-8pj6', 'GO-2026-4569', 'GO-2026-4770', 'GO-2026-4773', 'GO-2026-4918', 'GO-2026-5025', 'GO-2026-5026', 'GO-2026-5027', 'GO-2026-5028', 'GO-2026-5029', 'GO-2026-5030', 'GO-2026-5771', 'GO-2026-5942'])
- sigil: `corpora/mcp_clean/io.slingdata__sling-cli` — HIGH ['CODE-006', 'CODE-013', 'CODE-015', 'CRED-033', 'CRED-ENV-001', 'INSTALL-001', 'NET-002', 'TLS-002'] (High/Critical: ['CRED-033', 'INSTALL-001'])
- sigil: `corpora/mcp_clean/io.snyk__mcp` — CRITICAL ['CODE-001', 'CODE-002', 'CODE-003', 'CODE-007', 'CODE-008', 'CODE-009', 'CODE-012', 'CRED-002'] (High/Critical: ['CODE-001', 'CODE-002', 'CODE-008', 'CODE-009', 'CRED-008', 'INSTALL-003', 'NET-018', 'OBFUSC-006', 'OBFUSC-007', 'OBFUSC-012', 'OBFUSC-CHAIN-006', 'PROMPT-004', 'SKILL-006', 'SKILL-022', 'SUPPLY-001', 'SUPPLY-006', 'SUPPLY-007', 'SUPPLY-008', 'SUPPLY-009', 'SUPPLY-011', 'SUPPLY-012', 'SUPPLY-014'])
- sigil: `corpora/mcp_clean/ly.img__codesign` — CRITICAL ['ARTIFACT-007', 'CODE-007', 'CODE-012', 'CODE-RUNFILE-001', 'CRED-002', 'CRED-007', 'DEPSRC-006', 'HYGIENE-001'] (High/Critical: ['CRED-007', 'MANIP-007', 'NET-018', 'OBFUSC-007', 'OBFUSC-CHAIN-006', 'PROMPT-004', 'SKILL-018', 'SUPPLY-001', 'SUPPLY-007'])
