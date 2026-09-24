# Sigil vs NVIDIA SkillSpector

This page measures Sigil against [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
on the job both tools claim: deciding, before an AI agent loads it, whether a
skill or an MCP server is safe. Both tools were run on the same real samples.
Nothing here is simulated or estimated, and the results that do not favour
Sigil are listed too.

```
Data Source: Real samples.
             Malicious skills: the ai-skills bucket of DataDog/malicious-software-packages-dataset
             (204 skills published with malicious intent).
             Clean skills: every skill directory (a SKILL.md) in anthropics/skills, NVIDIA/skills,
             openai/skills and vercel-labs/agent-skills (455 skills).
             Clean MCP servers: 169 servers from the official MCP registry (npm or PyPI package,
             pinned by SHA-256 in evaluation_results/corpora/mcp_clean_manifest.json).
Sample Size: 204 malicious skills, 455 clean skills, 169 clean MCP servers.
Limitations: Static analysis on both sides: SkillSpector 2.11.2 with --no-llm, Sigil's offline
             phases. SkillSpector's optional LLM stage was not measured (no provider credentials
             in the measurement environment), and it may move SkillSpector's numbers either way.
             "Clean" means published in a vendor catalog or the registry, not audited, so the
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

## MCP servers

Both tools on the same 169 clean MCP servers from the official registry, one
unpacked package per server. There is no malicious MCP-server corpus of
comparable size, so this measures false positives only.

| | Scanned | Blocked | Warned | CRITICAL | Median scan time |
|---|---:|---:|---:|---:|---:|
| **Sigil** | 169 (0 errors) | **39 (23.1%)** | **125 (74.0%)** | 17 | **2.5 s** |
| SkillSpector 2.11.2 | 156 (13 timed out at 10 min) | 100 (64.1%) | 127 (81.4%) | 78 | 19.3 s |
| Sigil, on the 156 SkillSpector finished | 156 | 28 (17.9%) | 112 (71.8%) | 12 | |

Sigil blocks 6 servers SkillSpector does not; SkillSpector blocks 78 Sigil does
not.

This is Sigil's weakest false-positive result. MCP servers ship as complete
packages, often with minified bundles, and most of Sigil's blocks come from
code-execution and obfuscation rules firing inside bundled JavaScript, or from
an npm lifecycle script (INSTALL-003 is Critical for any install-time script).
The 13 servers SkillSpector timed out on are large bundles, and Sigil blocks 11
of them, so the like-for-like row above flatters Sigil somewhat. The
calibration and the remaining false positives, server by server, are in
[`docs/detection/mcp-server-calibration.md`](../detection/mcp-server-calibration.md).

## Rule-level parity

SkillSpector's own test suite is the most complete public statement of what
each of its rules is meant to catch. `scripts/skillspector_parity.py` collects
every example those tests construct (1,796 unique samples across 80 rule ids)
and asks whether Sigil flags each one.

```
Data Source: SkillSpector's own test suite, every finding its tests construct, de-duplicated.
Sample Size: 1,796 samples across 80 SkillSpector rule ids.
Limitations: The rows include findings SkillSpector's later stages filter out as false
             positives and test-only markers. A row measures agreement with SkillSpector's
             examples, not recall on malicious code.
```

| | Sigil flags (any severity) | Sigil ≥ High |
|---|---:|---:|
| Sigil before this change (`dc82a94`) | 416/1,796 (23.2%) | 275 (15.3%) |
| **Sigil, this change** | **623/1,796 (34.7%)** | **385 (21.4%)** |

Agreement is high where the examples are attacks: SkillSpector's agent-rogue
(AR, 81%), taint-tracking (TT, 88%), supply-chain (SC, 61%) and code-AST
(AST, 58%) families. It is low in the two largest families, tool misuse (TM,
9% of 406) and privilege escalation (PE, 15% of 277):

- **Destructive commands** (`rm -rf` of the root or the home directory and
  their variants) make up most of the tool-misuse rows. Sigil has no rule for
  them. This is a real gap, listed under [Where Sigil loses](#where-sigil-loses).
- **Credential words** (`keyring`, "Access tokens") make up most of the
  privilege-escalation rows. Sigil reports a credential path only when
  something reads or sends it; a bare mention is not flagged. That choice is a
  large part of why Sigil blocks 1.5% of clean skills and SkillSpector 25.9%.
- **Container privileges** (`--privileged`, `hostNetwork`, the Docker socket)
  and disabled TLS verification are not covered by Sigil either.

The per-rule table is in
[`evaluation_results/skills_benchmark/parity_sigil_7826ea1.md`](../../evaluation_results/skills_benchmark/parity_sigil_7826ea1.md).

## Malicious npm and PyPI packages

Sigil also gates package installs (`sigil pip`, `sigil npm`), so it is measured
on the full Datadog dataset selection as well. SkillSpector was not run here:
it is a skill scanner, and these are packages.

```
Data Source: Datadog malicious-software-packages-dataset, 844 samples (204 per ecosystem/category
             bucket, including the AI-skills bucket), selected deterministically by scripts/run_eval.py.
Sample Size: 844 malicious packages; no clean control set in this run.
Limitations: GuardDog selection bias (Datadog's disclaimer). Offline static phases only.
```

| Threshold | Sigil before this change | Sigil, this change |
|---|---:|---:|
| any severity | 772 (91.47%) | 785 (93.01%) |
| ≥ Medium | 764 (90.52%) | 761 (90.17%) |
| ≥ High | 718 (85.07%) | 752 (89.10%) |
| ≥ Critical | 553 (65.52%) | 561 (66.47%) |

Recall fell by 3 samples at ≥ Medium. Report:
[`evaluation_results/honest_detection_eval_7826ea1.md`](../../evaluation_results/honest_detection_eval_7826ea1.md).

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

**Not covered.** Sigil has no rule for recursive deletion of the root or home
directory, or for disk wipes beyond `dd` to a device and the classic fork bomb
(SKILL-012 catches those two). It has none for container-privilege settings or
disabled TLS verification either. SkillSpector covers all three.

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

# MCP servers: rebuild the corpus from the manifest, then one package per directory
python3 evaluation_results/corpora/fetch_mcp_clean.py --out /path/to/mcp_clean \
    --from-manifest evaluation_results/corpora/mcp_clean_manifest.json
python3 scripts/benchmark_skills.py --tools sigil,skillspector --timeout 600 \
    --clean /path/to/mcp_clean --clean-sample-depth 1 --out evaluation_results/skills_benchmark/mcp

```

`SIGIL_BIN` and `SKILLSPECTOR_BIN` select the binaries. The raw per-sample
outcomes of the runs on this page are in
[`evaluation_results/skills_benchmark/`](../../evaluation_results/skills_benchmark/).
