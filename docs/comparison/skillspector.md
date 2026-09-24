# Sigil vs NVIDIA SkillSpector

This page measures Sigil against [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
on the job both tools claim: deciding, before an AI agent loads it, whether a
skill is safe. Both tools were run on the same real samples.
Nothing here is simulated or estimated, and the results that do not favour
Sigil are listed too.

```
Data Source: Real samples.
             Malicious skills: the ai-skills bucket of DataDog/malicious-software-packages-dataset
             (204 skills published with malicious intent).
             Clean skills: every skill directory (a SKILL.md) in anthropics/skills, NVIDIA/skills,
             openai/skills and vercel-labs/agent-skills (455 skills).
Sample Size: 204 malicious skills, 455 clean skills.
Limitations: Static analysis on both sides: SkillSpector 2.11.2 with --no-llm, Sigil's offline
             phases. SkillSpector's optional LLM stage was not measured (no provider credentials
             in the measurement environment), and it may move SkillSpector's numbers either way.
             "Clean" means published in a vendor catalog, not audited, so the
             false-positive columns are upper bounds.
             Sigil's newer rules were written after reading these corpora, so its figures on them
             are in-sample. SkillSpector was measured as released.
             SkillSpector's skill figures come from a run on 2026-09-23 (SkillSpector has not
             changed since); Sigil's come from the final build of this change, 2026-09-24.
```

## Skills

| | Malicious blocked (≥ HIGH) | Malicious warned (≥ MEDIUM) | Clean blocked | Clean warned |
|---|---:|---:|---:|---:|
| **Sigil, this change** | **173/204 (84.8%)** | **184/204 (90.2%)** | **7/455 (1.5%)** | **71/455 (15.6%)** |
| Sigil before this change (`dc82a94`) | 142/204 (69.6%) | 149/204 (73.0%) | 108/455 (23.7%) | 226/455 (49.7%) |
| SkillSpector 2.11.2 (static) | 45/203 (22.2%) | 97/203 (47.8%) | 118/455 (25.9%) | 282/455 (62.0%) |

"Blocked" is the verdict an install gate refuses: Sigil HIGH or CRITICAL RISK,
SkillSpector `DO_NOT_INSTALL`. "Warned" adds Sigil MEDIUM RISK and SkillSpector
`CAUTION`. SkillSpector failed on one of the 204 malicious samples, so its
denominator is 203.

- **Per sample:** both tools block 43 malicious skills. Sigil alone blocks
  130, and SkillSpector alone blocks 2 (see [Where Sigil loses](#where-sigil-loses)).
- **No clean skill is CRITICAL** in Sigil (18 were before this change).
- **Speed:** median 1.48 s per skill for Sigil, measured in the final run. In
  the baseline run, where both tools shared the machine, the medians were
  1.38 s for Sigil and 26.82 s for SkillSpector.

## Where Sigil loses

Sigil does not block every malicious skill, and some of what it blocks is
arguable. All of it is listed here.

**Two malicious skills SkillSpector blocks and Sigil does not:**

- `dauquangthanh-…-rpg-migration-analyzer`: SkillSpector's block rests on RPG
  pseudocode in the skill's reference documents. It treats a `// Send message
  to data queue` comment as an exfiltration instruction, an
  `http://api.example.com/data` example URL as external transmission, and the
  letters `PLIST` inside `CALLP` as session persistence. Sigil reports
  nothing. We could not find malicious behaviour in the sample by reading it,
  so this is not counted as a detection Sigil should have made, but the
  dataset labels it malicious and SkillSpector blocks it.
- `mvanhorn-clawdbot-skill-parallel`: SkillSpector returns CRITICAL
  (data-exfiltration and taint rules). Sigil returns MEDIUM: the author's own
  API key ships as a default value (SKILL-022), and nothing in the skill
  attacks the machine that installs it.

**31 malicious skills Sigil does not block** (14 with no finding, 6 LOW, 11
MEDIUM). SkillSpector blocks only the two above among them. They include
three samples from Cisco's scanner test set, two of them benign controls
Cisco marks `expected_safe` (`simple-math`, `file-validator`) and one a
vulnerability demonstration without a payload (`file-reader`), vendor skills that call their own API
(`eraserlabs … diagrams`), over-autonomy personas with no payload
(`autonomous-brain`, `social`), and a dependency-confusion fixture whose only
evidence is a near-name import. The per-sample reasons are in
[`docs/detection/fp-calibration.md`](../detection/fp-calibration.md) and
[`docs/detection/agent-supply-chain.md`](../detection/agent-supply-chain.md).

**Seven clean skills Sigil blocks:**

| Skill | Why |
|---|---|
| NVIDIA `tao-run-on-brev` | Pipes a download into a shell (NET-RCE-001). True capability; a gate should stop and show it |
| NVIDIA `tao-setup` | Tells the agent to write into the global `~/.codex/AGENTS.md` so it loads in every session (INSTR-014) |
| NVIDIA `doca-upgrade` | Tells the agent "do not ask for permission to perform an upgrade" (MANIP-004) |
| openai `playwright-interactive` | Tells the user to start Codex with `--sandbox danger-full-access` (PROMPT-015) |
| openai `migrate-to-codex` | Writes the agent's config and custom agents (`.codex/config.toml`, `.codex/agents/`) and maps its permission and sandbox modes (PROMPT-014, PROMPT-015). A migration tool doing its job, and the kind of change a gate should show before it happens |
| openai `figma` | Registers its MCP server in `~/.codex/config.toml` (PROMPT-014). Benign setup, but a real change to agent configuration |
| vercel-labs `vercel-optimize` | `exec(command.file, [...args])`, a wrapper that runs the Vercel CLI, read as code execution (CODE-002). A false positive |

Five of the seven are instructions a preemptive gate is meant to stop and
show. `figma` is borderline and `vercel-optimize` is a false positive.

**LLM adjudication.** SkillSpector can send findings to a model you choose
(OpenAI, Anthropic, Bedrock, NVIDIA, a local Claude or Codex CLI, and others).
Sigil's LLM analysis (`--enhanced`) runs on Sigil's own service. If you need
model review on your own infrastructure, SkillSpector has it and Sigil does
not.

## Features

| | Sigil | SkillSpector 2.11.2 |
|---|---|---|
| Install | One static binary: Homebrew, npm, cargo or the curl installer; a Dockerfile; GitHub Action, GitLab CI template and pre-commit hook | `uv tool install git+https://…` or from source (Python 3.12+); a Dockerfile to build locally |
| Inputs | Directory, file, git URL, archive (`.zip`, `.skill`, `.tar.gz`), file URL, GitHub `/tree/` link, `mcp:<name>` from the MCP registry, `sigil pip` / `sigil npm` packages | Directory, file, git URL, URL, zip, MCP registry |
| Quarantine-first acquisition (`clone`/`pip`/`npm` into quarantine, then approve or reject) | Yes | No |
| Blocks risky agent actions before they run | Claude Code PreToolUse hook on `Bash`, `Write`, `Edit`, `MultiEdit` | No |
| Posture scan of the skills, MCP servers and hooks already installed | `sigil skills scan` | No |
| Scans what a skill tells you to download, without running it | `--follow-refs` (SSRF-guarded, two hops) | `--transitive` |
| Fails closed on incomplete coverage | `--fail-on-incomplete`, lockable in an organisation policy | `--fail-on-incomplete` |
| Output formats | text, JSON, SARIF 2.1.0, HTML, Markdown, JUnit | terminal, JSON, Markdown, SARIF |
| Baseline of accepted findings | Content fingerprints plus glob rules; stale entries reported | Glob rules or fingerprints |
| Custom rules | JSON/YAML packs and a YARA subset (fail-closed on unsupported constructs), Ed25519-signed; `sigil rules validate/test/sign` | A YARA rules directory (full YARA via yara-python) |
| Organisation policy (file pushed by MDM, locked keys, tighten-only project files) | `SIGIL_POLICY_FILE` | No |
| Built-in MCP server | `sigil mcp` (`scan`, `scan_package`, `check_command`) | `skillspector mcp` |
| IDE and agent integrations | Claude Code plugin, VS Code / Cursor / Windsurf, JetBrains | OpenCode and Pi extensions |
| LLM adjudication with your own model | No | Yes |

SkillSpector runs full YARA through libyara, including modules; Sigil's YARA
support is a documented subset that refuses anything outside it rather than
skipping it.

## Reproducing

```bash
make cli-build
python3 scripts/benchmark_skills.py --tools sigil,skillspector \
    --malicious /path/to/mal_skills --sample-depth 2 \
    --clean /path/to/anthropics_skills --clean /path/to/NVIDIA_skills \
    --clean /path/to/openai_skills --clean /path/to/vercel-labs_agent-skills \
    --out evaluation_results/skills_benchmark/run

```

`SIGIL_BIN` and `SKILLSPECTOR_BIN` select the binaries. The raw per-sample
outcomes of the runs on this page are in
[`evaluation_results/skills_benchmark/`](../../evaluation_results/skills_benchmark/).
