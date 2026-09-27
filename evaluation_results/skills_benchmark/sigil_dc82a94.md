# Skill scanner head-to-head

_Generated 2026-09-23T20:19:07+00:00 by `scripts/benchmark_skills.py`._

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
| sigil | 142/204 (69.6%) | 149/204 (73.0%) | 108/455 (23.7%) | 226/455 (49.7%) | 0 | 422s |

## Clean samples blocked

- sigil: `corpora/anthropics_skills/skills/claude-api` — CRITICAL ['CODE-001', 'CRED-001', 'CRED-002', 'CRED-009', 'MANIP-006', 'NET-006', 'NET-011', 'NET-012']
- sigil: `corpora/anthropics_skills/skills/mcp-builder` — HIGH ['CODE-MCP-002', 'CRED-002', 'NET-001', 'NET-005']
- sigil: `corpora/anthropics_skills/skills/skill-creator` — HIGH ['CODE-013', 'CODE-MCP-002', 'CRED-033', 'OBFUSC-002', 'SUPPLY-008']
- sigil: `corpora/anthropics_skills/skills/webapp-testing` — HIGH ['CODE-013', 'CODE-015']
- sigil: `corpora/NVIDIA_skills/skills/aiq-research` — HIGH ['CRED-MCP-001', 'NET-002', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-add-cmim-pretrain` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-continue-pretrain` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-embed` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-finetune` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-infer` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-kermt-pretrain-scratch` — HIGH ['CODE-004', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-msa-structure-prediction-pipeline` — HIGH ['CRED-001', 'NET-001', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/bionemo-openfold2-nim` — HIGH ['CRED-001', 'NET-001', 'NET-012', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/cuopt-install` — HIGH ['CODE-003', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/cuopt-server-api-python` — HIGH ['NET-001', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/deepstream-dev` — HIGH ['CRED-001', 'NET-001', 'NET-012', 'OBFUSC-010']
- sigil: `corpora/NVIDIA_skills/skills/deepstream-import-vision-model` — HIGH ['CODE-001', 'CODE-011', 'CODE-013', 'NET-011', 'OBFUSC-001', 'PROMPT-007', 'PROMPT-017']
- sigil: `corpora/NVIDIA_skills/skills/deepstream-sop` — HIGH ['CODE-001', 'CODE-013', 'MANIP-006', 'NET-001', 'NET-008', 'NET-009', 'NET-011', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/digital-health-clinical-asr-build` — HIGH ['NET-001', 'OBFUSC-CHAIN-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-bare-metal-deployment` — CRITICAL ['CRED-005', 'PERSIST-006']
- sigil: `corpora/NVIDIA_skills/skills/doca-caps` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-comm-channel-admin` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-flow-grpc-server` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-flow-tune` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-gpunetio-ib-write-bw` — HIGH ['MANIP-008', 'PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-gpunetio-ib-write-lat` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/doca-setup` — HIGH ['MANIP-007']
- sigil: `corpora/NVIDIA_skills/skills/doca-telemetry-exporter` — HIGH ['MANIP-007']
- sigil: `corpora/NVIDIA_skills/skills/doca-upgrade` — HIGH ['MANIP-004']
- sigil: `corpora/NVIDIA_skills/skills/earth2studio-create-diagnostic` — CRITICAL ['CODE-001', 'PERSIST-004', 'PERSIST-012', 'SKILL-003']
- sigil: `corpora/NVIDIA_skills/skills/earth2studio-create-prognostic` — CRITICAL ['CODE-001', 'PERSIST-004', 'PERSIST-012', 'SKILL-003']
- sigil: `corpora/NVIDIA_skills/skills/holoscan-install-conda` — HIGH ['NET-012', 'PERSIST-004']
- sigil: `corpora/NVIDIA_skills/skills/hsb-app` — HIGH ['MANIP-008', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/hsb-setup` — CRITICAL ['CRED-005', 'CRED-031', 'MANIP-008', 'PERSIST-003', 'PERSIST-004', 'PERSIST-006', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/hsb-test` — HIGH ['MANIP-008', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/isaac-mission-control-showcase` — HIGH ['CODE-013', 'INFER-003', 'NET-002', 'NET-003']
- sigil: `corpora/NVIDIA_skills/skills/jetson-headless-mode` — HIGH ['PERSIST-003']
- sigil: `corpora/NVIDIA_skills/skills/jetson-init-source` — HIGH ['MANIP-008']
- sigil: `corpora/NVIDIA_skills/skills/jetson-validate-image` — CRITICAL ['CODE-002', 'CODE-013', 'OBFUSC-001', 'PERSIST-007', 'SKILL-003']
- sigil: `corpora/NVIDIA_skills/skills/jetson-video-pipeline` — HIGH ['CODE-010', 'CODE-011', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/jetson-video-setup` — HIGH ['CODE-011', 'CODE-013']
- sigil: `corpora/NVIDIA_skills/skills/launch-nemo-rl` — CRITICAL ['CRED-005', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/nemotron-speech` — HIGH ['CRED-001', 'NET-012', 'PERSIST-004', 'PERSIST-005']
- sigil: `corpora/NVIDIA_skills/skills/nv-generate-mr-brain-finetune` — HIGH ['CODE-013', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/nv-generate-vae-finetune` — HIGH ['CODE-001', 'CODE-013', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/nv-reason-cxr` — HIGH ['CODE-001', 'CODE-010', 'CODE-013', 'CRED-001', 'NET-002', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/nv-segment-ct-finetune` — HIGH ['CODE-013', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/nv-segment-ctmr` — HIGH ['CODE-013', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/nvflare-convert-lightning` — HIGH ['CODE-001']
- sigil: `corpora/NVIDIA_skills/skills/nvflare-convert-pytorch` — HIGH ['CODE-001', 'MANIP-006', 'MANIP-008', 'SUPPLY-003']
- sigil: `corpora/NVIDIA_skills/skills/omniverse-cad-to-simready` — HIGH ['CODE-013', 'CRED-033', 'NET-002', 'NET-011', 'NET-012', 'OBFUSC-001', 'OBFUSC-005']
- sigil: `corpora/NVIDIA_skills/skills/omniverse-usd-performance-tuning` — HIGH ['CODE-011', 'CODE-013', 'MANIP-006', 'MANIP-007', 'MANIP-008', 'PROMPT-017', 'PROV-003']
- sigil: `corpora/NVIDIA_skills/skills/paidf-orchestration-setup` — HIGH ['CODE-013', 'CRED-001', 'CRED-031', 'MANIP-008', 'NET-012', 'PERSIST-009']
- sigil: `corpora/NVIDIA_skills/skills/paidf-orchestration-write-dag` — HIGH ['MANIP-008']
- sigil: `corpora/NVIDIA_skills/skills/physical-ai-event-video-generation` — HIGH ['CRED-001', 'MANIP-006', 'NET-012', 'PROV-003']
- sigil: `corpora/NVIDIA_skills/skills/physical-ai-image-attribute-augmentation` — HIGH ['CRED-001', 'MANIP-006', 'NET-002', 'NET-012', 'PROV-003']
- sigil: `corpora/NVIDIA_skills/skills/physical-ai-infrastructure-setup-and-resilient-scaling` — HIGH ['CRED-008', 'CRED-031', 'MANIP-006', 'MANIP-007', 'MANIP-008', 'NET-012', 'PERSIST-004']
- sigil: `corpora/NVIDIA_skills/skills/rag-blueprint` — CRITICAL ['CRED-031', 'MANIP-004', 'MANIP-006', 'NET-012', 'PROMPT-006', 'SKILL-010']
- sigil: `corpora/NVIDIA_skills/skills/rag-eval` — CRITICAL ['CODE-001', 'SKILL-003', 'SKILL-010']
- sigil: `corpora/NVIDIA_skills/skills/rtx-remix-modding` — HIGH ['PROMPT-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-analyze-detection-kpi` — HIGH ['CRED-031', 'SKILL-004', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-data-io` — CRITICAL ['CRED-001', 'CRED-003', 'CRED-031', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-finetune-cosmos-reason` — HIGH ['CODE-007', 'CODE-011', 'CODE-013', 'MANIP-006', 'NET-002', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-finetune-huggingface-model` — CRITICAL ['CODE-001', 'CRED-001', 'MANIP-006', 'SKILL-003']
- sigil: `corpora/NVIDIA_skills/skills/tao-finetune-video-clip` — CRITICAL ['CODE-001', 'CRED-003', 'CRED-031', 'SKILL-003', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-launch-workflow` — CRITICAL ['CRED-005', 'CRED-031', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-port-huggingface-model` — HIGH ['CODE-001', 'CODE-015', 'CRED-001', 'MANIP-006', 'SKILL-011']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-automl` — CRITICAL ['CODE-001', 'CODE-010', 'CODE-013', 'CRED-001', 'CRED-003', 'CRED-031', 'OBFUSC-CHAIN-017']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-deft-aoi` — HIGH ['CODE-001', 'CODE-013', 'CRED-001', 'CRED-031', 'CRED-033', 'MANIP-006', 'MANIP-008', 'PROV-001']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-deft-aoi-cosmos3` — HIGH ['CODE-001', 'CODE-013', 'CRED-031', 'CRED-033', 'MANIP-006']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-on-brev` — HIGH ['CRED-031', 'NET-012', 'PROMPT-017', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-on-kubernetes` — HIGH ['CRED-031', 'NET-012', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-on-slurm` — CRITICAL ['CRED-005', 'PERSIST-006', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-run-on-virtualenv` — HIGH ['CODE-013', 'CRED-001', 'CRED-033', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-setup` — HIGH ['CRED-031', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-setup-nvidia-gpu-host` — HIGH ['NET-012', 'PERSIST-003', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-train-dinov3` — HIGH ['SKILL-008', 'SUPPLY-008']
- sigil: `corpora/NVIDIA_skills/skills/tao-train-visual-changenet` — CRITICAL ['CODE-001', 'CODE-013', 'CRED-001', 'CRED-003', 'SKILL-008']
- sigil: `corpora/NVIDIA_skills/skills/vss-ask-video` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-deploy-dense-captioning` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-deploy-detection-tracking-3d` — HIGH ['NET-012', 'SKILL-011']
- sigil: `corpora/NVIDIA_skills/skills/vss-deploy-profile` — HIGH ['MANIP-004', 'MANIP-006', 'MANIP-008', 'NET-012', 'NET-013', 'NET-MCP-002', 'PERSIST-003', 'PERSIST-004']
- sigil: `corpora/NVIDIA_skills/skills/vss-deploy-video-embedding` — HIGH ['NET-012', 'PERSIST-007']
- sigil: `corpora/NVIDIA_skills/skills/vss-generate-video-calibration` — HIGH ['MANIP-008', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-generate-video-report` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-manage-alerts` — CRITICAL ['CRED-001', 'CRED-013', 'MANIP-004', 'MANIP-008', 'NET-006', 'NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-manage-video-io-storage` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-query-analytics` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-search-archive` — HIGH ['NET-012']
- sigil: `corpora/NVIDIA_skills/skills/vss-setup-video-analytics-api` — HIGH ['NET-012', 'PERSIST-004']
- sigil: `corpora/NVIDIA_skills/skills/vss-summarize-video` — HIGH ['MANIP-008', 'NET-012']
- sigil: `corpora/openai_skills/skills/.curated/cloudflare-deploy` — CRITICAL ['CODE-002', 'CODE-007', 'CRED-001', 'CRED-002', 'CRED-007', 'MANIP-008', 'NET-004', 'NET-006']
- sigil: `corpora/openai_skills/skills/.curated/figma` — HIGH ['PERSIST-004', 'PROMPT-014']
- sigil: `corpora/openai_skills/skills/.curated/figma-use` — HIGH ['NET-006', 'OBFUSC-CHAIN-006']
- sigil: `corpora/openai_skills/skills/.curated/gh-fix-ci` — HIGH ['CODE-013']
- sigil: `corpora/openai_skills/skills/.curated/migrate-to-codex` — HIGH ['PROMPT-007', 'PROMPT-014', 'PROMPT-015', 'PROMPT-017']
- sigil: `corpora/openai_skills/skills/.curated/netlify-deploy` — HIGH ['CRED-002', 'MANIP-004']
- sigil: `corpora/openai_skills/skills/.curated/playwright` — HIGH ['PROMPT-017']
- sigil: `corpora/openai_skills/skills/.curated/playwright-interactive` — HIGH ['PROMPT-015']
- sigil: `corpora/openai_skills/skills/.curated/screenshot` — HIGH ['CODE-013', 'OBFUSC-006']
- sigil: `corpora/openai_skills/skills/.curated/security-best-practices` — HIGH ['CODE-001', 'CODE-002', 'CODE-003', 'CODE-007', 'CODE-008', 'CODE-009', 'CODE-014', 'CODE-015']
- sigil: `corpora/openai_skills/skills/.curated/security-ownership-map` — HIGH ['CODE-013']
- sigil: `corpora/openai_skills/skills/.curated/transcribe` — HIGH ['CRED-001', 'MANIP-006', 'PROMPT-017']
- sigil: `corpora/openai_skills/skills/.system/imagegen` — HIGH ['CRED-001', 'MANIP-006', 'OBFUSC-001']
- sigil: `corpora/openai_skills/skills/.system/skill-installer` — HIGH ['CODE-013', 'CRED-001', 'NET-002', 'PROMPT-017']
- sigil: `corpora/vercel-labs_agent-skills/skills/deploy-to-vercel` — HIGH ['MANIP-008']
- sigil: `corpora/vercel-labs_agent-skills/skills/vercel-cli-with-tokens` — HIGH ['MANIP-006', 'MANIP-008']
- sigil: `corpora/vercel-labs_agent-skills/skills/vercel-optimize` — HIGH ['CODE-002', 'CODE-007', 'OBFUSC-003', 'PROMPT-017', 'PROV-003']
