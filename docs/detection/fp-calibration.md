# False-positive calibration: verdict and rule severities

This note records a calibration pass over Sigil's verdict and its core packs,
measured against 455 skills published by four reputable vendors and 204
malicious skills. It says what changed, why, and what it cost. Every number
below comes from a real run; the commands are at the end.

```
Data Source: Real samples.
             Clean: anthropics/skills (20), NVIDIA/skills (382), openai/skills (44),
                    vercel-labs/agent-skills (9) — vendor catalogs, not audited.
             Malicious: Datadog malicious-software-packages-dataset, ai-skills
                    bucket (204 skills); npm and pypi buckets for recall (844
                    packages, 204 per bucket).
             Fixtures: SkillSpector's own test fixtures (26).
Sample Size: 455 clean + 204 malicious skills; 844 malicious packages; 26 fixtures.
Limitations: Static analysis only (offline phases). "Clean" means published by a
             vendor, not audited: a vendor skill that pipes an installer into bash
             is a correct finding, so the clean-blocked figure is an upper bound on
             false positives. The rules were tuned while looking at these same
             clean skills, so the clean figures are in-sample. The malicious
             skills and the Datadog set were used to check for loss, and four
             changes were written after reading samples there (SKILL-024,
             CODE-014, NET-007, the CODE-001/002 '$' fix), so those gains are
             in-sample too.
```

## Results

Skills benchmark (`scripts/benchmark_skills.py`, Sigil only, 204 malicious / 455 clean):

| | Before (dc82a94) | After | Change |
|---|---:|---:|---:|
| Malicious blocked (≥ HIGH) | 142/204 (69.6%) | 152/204 (74.5%) | +10 |
| Malicious warned (≥ MEDIUM) | 149/204 (73.0%) | 165/204 (80.9%) | +16 |
| Clean blocked (≥ HIGH) | 108/455 (23.7%) | 7/455 (1.5%) | −101 |
| Clean warned (≥ MEDIUM) | 226/455 (49.7%) | 71/455 (15.6%) | −155 |
| Clean at CRITICAL | 18 | 0 | −18 |
| Malicious at CRITICAL | 33 | 28 | −5 |

Verdict distribution after: malicious 28 CRITICAL / 124 HIGH / 13 MEDIUM / 12 LOW / 27 NONE;
clean 0 / 7 / 64 / 147 / 237. The 147 clean LOW skills carry only Low observations
(a subprocess call, an HTTP client, an API key read from the environment).

The malicious block rate did not drop: 16 malicious skills lost their block and
26 gained one. Every loss is listed and explained below.

## What changed in the verdict

`cli/src/scanner/scoring.rs`, `cli/src/scanner/context.rs`.

**Low is an observation, not evidence.** Findings at Low severity still appear
in the report and in the score shown to the user, but the verdict reads a
*signal score* that counts Medium and above only. A skill made of routine
capabilities is LOW however many of them it has. Measured alone, excluding Low
from the verdict moved 6 clean skills and 3 malicious ones out of HIGH.

**HIGH needs attack evidence.** HIGH now requires at least one High or Critical
finding in first-party code (not tests, docs, vendored trees, `evals/`, or code
examples in reference documentation). Without one, no pile of Medium findings
reaches HIGH: a lone Medium can never be HIGH. Given attack evidence, the
existing share terms decide whether it is a real part of the package:

- first-party signal score ≥ 200, or
- ≥ 3.5 first-party points per scanned file (density), or
- **new:** at least one scanned file in eight carries the High/Critical
  evidence (concentration — a one-file dropper in a three-file skill), or
- first-party signal ≥ 50 together with an action behaviour
  (`install_time_execution`, `exfiltration_endpoint`, `installs_persistence`,
  `dynamic_execution`) — now from a Medium-or-above first-party finding only.

**MEDIUM** is any Medium-or-above first-party finding, or a signal score ≥ 10
overall. **CRITICAL** is unchanged: one `standalone` Critical, or two different
`corroborate` Criticals.

**Documentation examples are secondary.** A Code, Network, Credentials or
Obfuscation finding in a reference document (`.md`, `.mdx`, `.markdown`,
`.rst`) is treated like a test file for the verdict. Agent instruction files
(`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `copilot-instructions.md`,
`.cursorrules`, `.windsurfrules`, `.clinerules`) never qualify, and only those
four phases do: a prompt-injection, agent-manipulation or skill-manifest
finding in a reference file the agent is sent to read is still an instruction.
Neither is a code-phase rule whose match is an action the reader carries out
(`INSTRUCTION_SHAPED_RULES` in `context.rs`: NET-RCE-001, SKILL-011, SKILL-016,
SKILL-017, SKILL-018, SKILL-020, SKILL-021), so a skill cannot take
`curl … | bash` out of the HIGH gate by moving it from `SKILL.md` into
`references/install.md` (see "Verification" below).
The finding is still reported at its own severity; only the HIGH gate stops
counting it, and a High or Critical finding anywhere keeps the verdict at
MEDIUM or above. The context is derived from the finding's own path, phase
and rule id, so the ledger, enforcement and `sigil diff` recompute the same
verdict.

The concentration ratio was chosen by replaying saved findings from an
intermediate pack set (not the final one): 1 in 4 blocked 143 malicious / 10
clean; 1 in 8 blocked 151 / 14; 1 in 12 blocked 152 / 17. Without the
documentation context, 1 in 8 blocked 21 clean.

## Severity policy and rule changes

Routine capability is at most Low. Medium means suspicious in context. High and
Critical mean the line has the shape of an attack.

**Re-graded to Low** (capability observations): CODE-007 (`child_process`
import), CODE-010/011/012 (dynamic import), CODE-013 (`subprocess` call),
CODE-015 (`shell=True`), CODE-MCP-002 (`execute_tool(`), CRED-001/002
(environment and API-key reads), CRED-MCP-001, NET-001…005 (HTTP clients),
NET-012 (remote download), SKILL-008 (wildcard tool permissions).

**Re-graded to Medium**: MANIP-008 (act without confirmation — now suppressed on
negations), PERSIST-003 (`systemctl enable`), PERSIST-007, NET-006 (webhook URL;
also narrowed to URL assignments and localhost/example hosts suppressed).

**Narrowed** (the pattern matched prose or a benign idiom):

| Rule | Was matching | Now requires |
|---|---|---|
| CODE-001 / CODE-002 | `eval (key`, `$eval(`, "No eval() or exec()" in prose | a call shape: `eval(` with an argument, not a method or `$eval` |
| CRED-005 / CRED-003 / CRED-031 | any mention of `~/.ssh/id_rsa`, `.aws/credentials`, `.pub`, `authorized_keys` | a read verb (`cat`, `cp`, `scp`, `open(`, `read`, `upload`, `curl -d @`, …) on the private file |
| CRED-033 | `os.environ.copy()` for a subprocess | dumps/harvests the environment; the copy idiom is the new CRED-ENV-001 (Low) |
| CRED-008 / CRED-009 / CRED-013 | templated placeholders, `"type": "service_account"` alone, `xoxb-` in docs | literal values; a service-account key with a private key; a Slack token shape |
| NET-011 | any base64 near a request | base64 of `getenv`/`environ` data |
| PROMPT-006 / 007 / 008 | the word "jailbreak"; `---` delimiters; "send the report" | jailbreak phrasing; chat-template tokens; send/upload/exfiltrate secrets |
| SKILL-003 / 004 / 011 | `eval()` named in a checklist; "private"; any `rm` | a code-execution reference with an argument; secret scopes; `rm` on script-like targets |
| MANIP-004 / 007, PERSIST-005 / 006, NET-008 | CLI flag docs, "tell the user to", `remote-ssh`, `AF_UNIX` | the manipulation or persistence shape itself |
| SUPPLY-008, INFER-003, OBFUSC-CHAIN-017, PROV-003, SKILL-001 / 006 | `${…}` template text, any model name, `copy`, `payload.md`, `tool_calls` | `${eval(…)}`, secret names, dangerous modules, attack filenames, the key position |

**New rules** (each with remediation, references, tags, and positive and
negative tests in `cli/src/corpus/engine.rs::fp_calibration`, checked against
all 455 clean skills):

- **NET-RCE-001** (High, network_exfil): a download piped straight into an
  interpreter (`curl … | bash`, `wget -O - | sudo sh`, `irm … | iex`,
  `IEX (New-Object Net.WebClient).DownloadString(…)`). Split out of NET-012,
  which is now a Low observation for downloads in general. The best-known vendor
  installers (rustup, uv, Docker, NodeSource, Poetry, get-pip, Ollama, Bun,
  Deno, Homebrew, Helm, Sentry CLI) are allow-listed. Fires on 5 clean and 10
  malicious skills. It keeps NET-012's behaviour (`downloads_remote_content`).
- **CRED-ENV-001** (Low, credentials): the whole environment copied
  (`os.environ.copy()`, `{**os.environ}`, `{...process.env}`), the standard idiom
  for a child process's `env=`. Fires on 13 clean and 1 malicious skill.

**Extended** (to keep or raise malicious recall):

- SKILL-024: the ClawHavoc fake-prerequisite delivery (extract a
  password-protected archive, run a named `.exe`, download from a free file
  host). 28 → 67 malicious skills, 0 clean.
- PROMPT-010: secret or hidden instructions addressed to the agent. 0 → 5
  malicious, 0 clean.
- MANIP-004: "do not ask the user — just run/install".
- SKILL-022: a long literal assigned to a secret-named variable.
- CODE-014: `execSync("…")` with a literal command line and `spawn('sh'|'bash',
  ['-c'|'-i'])` — the shell forms of `child_process`, which stay High while
  importing `child_process` is Low. 4 → 8 malicious, 1 → 1 clean.
- NET-007: `oastify.com` (Burp Collaborator); placeholder URLs suppressed.

Per-rule sample counts (skills with at least one finding of the rule):

| Rule | Severity before → after | Clean before → after | Malicious before → after |
|---|---|---:|---:|
| CODE-001 | High → High | 22 → 6 | 10 → 4 |
| CODE-002 | High → High | 5 → 4 | 13 → 8 |
| CODE-014 | High → High | 1 → 1 | 4 → 8 |
| CRED-005 | Critical → Critical | 5 → 0 | 3 → 3 |
| CRED-031 | High → High | 20 → 2 | 0 → 0 |
| CRED-033 | High → High | 12 → 0 | 2 → 1 |
| MANIP-007 | High → High | 6 → 1 | 6 → 6 |
| MANIP-008 | High → Medium | 24 → 17 | 4 → 4 |
| NET-006 | High → Medium | 4 → 0 | 4 → 0 |
| NET-RCE-001 | — → High | 0 → 5 | 0 → 10 |
| PROMPT-008 | High → High | 8 → 0 | 0 → 0 |
| SKILL-003 | Critical → Critical | 6 → 0 | 10 → 5 |
| SKILL-008 | High → Low | 81 → 81 | 1 → 1 |
| SKILL-024 | High → High | 0 → 0 | 28 → 67 |
| NET-012 | Medium → Low | 58 → 58 | 46 → 46 |
| CODE-013 | Medium → Low | 58 → 58 | 7 → 7 |

Every malicious finding the narrowing removed (CODE-001, CODE-002, SKILL-003,
CRED-033, NET-006, PROMPT-006, PROMPT-007) was checked by hand: they are
comments ("# CRITICAL: Uses eval() on user input"), expected-result JSON, a
security-review checklist naming `eval()`, Puppeteer's `page.$eval(`,
`.join('\n---\n')`, and OAuth callbacks on localhost. The samples that carried
them keep their block through the real call or a new rule: Cisco's
eval-execution and exfiltrator samples are unchanged (HIGH, CRITICAL), and the
four security-review skills go from CRITICAL (SKILL-003 on the checklist) to
HIGH (PROMPT-010, NET-RCE-001).

## Why the 108 clean skills were blocked

Each baseline HIGH/CRITICAL clean skill, classified by why it no longer blocks
(first matching reason per first-party High/Critical finding):

| Reason | Skills |
|---|---:|
| Verdict math — no first-party High/Critical at all; Medium/Low volume or density | 26 |
| Pattern — the line no longer matches (prose, idiom, placeholder) | 22 |
| Severity — a routine capability re-graded to Medium/Low | 19 |
| Pattern + severity | 15 |
| Context + pattern (+ severity) — documentation example | 11 |
| Other combinations (a High finding still present but diluted) | 8 |
| Still blocked | 7 |

Rules behind the most baseline clean blocks, counted in first-party
High/Critical lines on those 108 skills: CODE-001 (69: 58 prose or method calls,
11 documentation examples), CRED-005 (37, mentions of key paths), CRED-031 (32),
SKILL-008 (23), MANIP-008 (23), CRED-033 (15), CODE-015 (15), CODE-007 (15),
PERSIST-003 (12), PROMPT-008 (10).

"Other" is a High finding that is still present and first-party but no longer
reaches HIGH because the rest of the skill's evidence was Low or removed
(screenshot OBFUSC-006, imagegen OBFUSC-001, figma-use OBFUSC-CHAIN-006, and five
more). Those skills are MEDIUM now.

### The 7 clean skills still blocked

| Skill | Finding | Classification |
|---|---|---|
| NVIDIA tao-run-on-brev | NET-RCE-001: `curl -fsSL https://raw.githubusercontent.com/brevdev/…/main/…sh \| bash` | True risk: an unpinned script from a branch head, executed |
| openai playwright-interactive | PROMPT-015: requires `--sandbox danger-full-access` | True risk: the skill asks for the sandbox to be disabled |
| openai migrate-to-codex | PROMPT-014/015: writes `.codex/config.toml`, agents, permission modes | True capability: rewriting agent configuration is the skill's purpose |
| openai figma | PROMPT-014: register an MCP server in `~/.codex/config.toml` with bearer auth | True capability, in a reference doc; prompt-phase findings are never documentation-secondary by design |
| NVIDIA doca-upgrade | MANIP-004: "do not ask for permission to perform an upgrade" | True risk by the rule's definition: an instruction to skip user confirmation for a privileged operation |
| NVIDIA jetson-validate-image | OBFUSC-001: `base64.b64decode` of data read over UART, written to a file | Residual FP by pattern: statically this is also the dropper shape |
| vercel-optimize | CODE-002 on a promisified `execFile` aliased `exec`; OBFUSC-003 `Buffer.from(body, 'base64')` | Residual FP by pattern |

## Malicious skills that lost their block (16)

None lost a block because an attack line stopped matching. They fall into two
groups.

**The baseline block had no attack content** (the verdict was right for the
wrong reason, or the sample is not an attack):

| Sample | Before | After | Why |
|---|---|---|---|
| cisco simple-math | CRITICAL | NONE | The only findings were "No eval() or exec()" in its SKILL.md — a benign control sample in Cisco's scanner eval set |
| dreamineering meme-pumper | HIGH | NONE | PROMPT-007 on `.join('\n---\n')` |
| galz10 load-pickle-persona | HIGH | LOW | Density of Low MANIP-006 persona text |
| mindverse secondme-reference | HIGH | LOW | One API-key read (CRED-002) in a small skill |
| riba2534 feishu-cli-create | HIGH | LOW | SKILL-008 wildcard permission only |
| zhangyanxs repo2skill | HIGH | LOW | NET-012 GitHub API and mirror downloads |
| plurigrid aqua-voice-malleability | HIGH | LOW | NET-012 to a localhost DevTools port |
| eraserlabs azure-diagrams, terraform-diagrams | HIGH | MEDIUM | `allowed-tools: Bash(curl:*)` (SKILL-010, Medium) and a `curl -X POST` to the vendor's own render API |
| ralph-wren omni-recall | HIGH | MEDIUM | Fernet cipher use (OBFUSC-010, Medium) plus env and HTTP reads now at Low |

**Medium-only evidence** (the skill is suspicious, the verdict is still a
warning, but nothing in it has an attack shape a static rule can see):
Charpup credential-harvester (SKILL-023), Charpup dependency-confusion
(SKILL-015), boomsystel autonomous-brain (MANIP-008, PROMPT-017), cisco
file-reader (SKILL-013), senturysh social (MANIP-008) — all MEDIUM now.

**Diluted High:** mvanhorn parallel — SKILL-022 (a hard-coded API key as an
`os.environ.get` default) in one of nine files, below the concentration and
density terms. MEDIUM now.

## Malicious skills that gained a block (26)

23 ClawHavoc fake-prerequisite skills through the extended SKILL-024 (most were
NONE before); boomsystel financial-market-analysis (NET-MCP-002), sebastiaanwouters
e2e-tester (SKILL-001), tmdgusya subway (CODE-014 `execSync`).

## SkillSpector fixtures

SkillSpector's 26 test fixtures, scanned with Sigil (verdicts):

| Fixture | Expected | Before | After |
|---|---|---|---|
| mcp_clean_skill | clean | HIGH (CODE-013 Medium) | LOW |
| sqp2_clean | clean | HIGH (CODE-013, CODE-015) | LOW |
| sdi_clean | clean | LOW | LOW |
| safe_skill, sqp1_clean, sqp3_clean, ssd_clean, pe3_bare_keyring, as3_self_reference | clean | NONE | NONE |
| malicious_skill | positive | HIGH | HIGH |
| mcp_poisoned_tool | positive | CRITICAL | CRITICAL |
| mcp_mismatched_skill | positive | LOW | HIGH (CRED-033, concentration) |
| mcp_underdeclared_skill | positive | HIGH | LOW |
| sdi2_inappropriate | positive | HIGH | LOW |
| tp4_markdown_fenced_code | positive | HIGH | LOW |
| 11 other positives (mcp_overprivileged, sdi1/3/4, sqp ×3, ssd ×4) | positive | NONE (sdi1 LOW) | unchanged |

Every clean fixture is now LOW or NONE. Three positives lost HIGH: each was HIGH
only from routine-capability Mediums identical to what made `mcp_clean_skill`
HIGH (a `subprocess.run` list call, a `requests.post` in a fenced block). They
are SkillSpector's declaration-mismatch cases — "uses the network but declares
no permissions" — which a line pattern cannot judge; Sigil reports the
capabilities at Low.

## SkillSpector rule parity

SkillSpector's positive examples (1,796 deduplicated sources across its rules),
scanned by Sigil: detected at any severity 413 → 411 (23.0% → 22.9%), at High or
above 275 → 279 (15.3% → 15.5%). Gains: 39 SC2 (download-and-execute) rows
through NET-RCE-001. Deliberate losses at High+: the re-graded subprocess and
`child_process` idioms (TM1, OH1, TT3, TT5), `os.environ.copy()` (E2),
"Delete the files without confirmation" (EA2, MANIP-008 now Medium),
`systemctl enable` (RA2), `payload.md` filenames (MP2, SC8), an educational
"to jailbreak the model" (AR1), and `ssh -i ~/.ssh/id_ed25519` (BH1, a key used,
not read).

## Datadog recall

`scripts/run_eval.py --dataset datadog --limit 204` (844 malicious packages;
run_eval's offline phases, which leave out `skill_security`; a sample counts at
the highest severity of any finding, not the verdict):

| Threshold | Before (dc82a94) | After | Change |
|---|---:|---:|---:|
| ≥ any | 772 (91.47%) | 769 (91.11%) | −3 |
| ≥ Medium | 764 (90.52%) | 736 (87.20%) | −28 |
| ≥ High | 718 (85.07%) | 710 (84.12%) | −8 |
| ≥ Critical | 553 (65.52%) | 554 (65.64%) | +1 |

By bucket at ≥ High: ai-skills 113 → 109, npm compromised 203 → 203, npm
malicious 201 → 201, pypi compromised 22 → 21, pypi malicious 179 → 176.

**This is a real loss and it is reported as one.** 11 samples lost ≥ High and 3
gained it (two cloudrouter skills through MANIP-004, zackkorman pdf-helper
through NET-RCE-001 and PROMPT-010). Of the 11:

- 7 are skills that also appear in the skills benchmark above: cisco
  simple-math (a benign control), meme-pumper (`.join('\n---\n')`), mitsuhiko
  google-workspace ×2 (a `require('node:child_process')` and a localhost OAuth
  callback), bear-notes (a localhost callback), and boomsystel autonomous-brain
  and senturysh social (MANIP-008, now Medium). The mitsuhiko pair and
  bear-notes are still HIGH in the skills benchmark — through advisories on
  their dependencies and through SKILL-024 — which run_eval's phase set leaves
  out.
- 4 are real malicious packages that the baseline caught **through the wrong
  line**, and whose actual payload no rule covers:
  - `ai-labs-snippets-sdk` 0.1.0 / 1.1.0 / 1.2.0: the only High was CODE-001 on
    PyTorch's `model.eval()`. The payload is the line before it,
    `torch.load(model_path, weights_only=False)` on a model bundled in the
    package, at import time — a pickle-deserialization dropper.
  - `guardrails-ai` 0.10.1 (compromised release): the only High was CRED-033 on
    `env = dict(os.environ)` in an unrelated CLI helper. The payload is in
    `guardrails/__init__.py`: at import it downloads a `.pyz` from a
    look-alike domain into `/tmp` and runs it with `python3`. Those lines now
    report at Low (NET-002, CODE-013); the download→write→execute flow spans
    three lines through a `with … as` binding, which neither a line rule nor
    the existing correlation linker (assignment-based) connects.

Both payload shapes are recall work, recorded under Known gaps.

The ≥ Medium drop (30 lost, 2 gained) is the Low re-grade: samples whose only
findings were an HTTP client call or a `subprocess.run([...])` list call now
report those calls at Low. 23 of the 30 are ai-skills samples, measured here
without the skill-security phase. The other 7 are PyPI packages, and they are
real: dependency-confusion beacons that POST host, user and CI details with
`urllib` (airio and azure-eventhub-checkpointstoretable 9.9.9 from `setup.py`,
anduril-sdk ×2 at import, to a raw IP), and three droppers that pass a
`curl.exe … .exe` download and a `Start-Process` through
`subprocess.run(["powershell", "-Command", var])` (antibyfron, artindex,
automsg). None of the 7 was at ≥ High before either.

One pattern regression was found by this measurement and fixed: the
CODE-001/CODE-002 argument shape did not allow `$` in an identifier, so
obfuscator output (`eval(tgZa$q_T[…])`, npm `1imit` ×2) stopped matching.

## Self-scan

`sigil scan . --no-cache --fail-on high` from the repository root exits 0
before and after. The verdict moves from HIGH RISK (score 342; 67 findings, 47
Medium and 20 Low, none High — HIGH by Medium density alone) to MEDIUM RISK
(score 182; 48 findings, 10 Medium and 38 Low; 491 files).
`cli/src/hook.rs` and `cli/src/residue/checks.rs` were added to `.sigilignore`:
their unit tests feed `curl … | sh` to Sigil's own guards, which NET-RCE-001 now
reports.

## Known gaps

- The two residual clean false positives (jetson-validate-image,
  vercel-optimize) need data-flow, not patterns: a base64 decode written to a
  file and an `exec` alias for `execFile` look the same as their malicious
  twins line by line.
- Medium-only malicious skills (5 above) now warn instead of block. A
  "several independent Medium behaviours" path to HIGH was considered; on these
  samples it would recover at most one (boomsystel autonomous-brain), so it was
  not added.
- Clean figures are in-sample. A held-out vendor catalog would give an honest
  out-of-sample FP rate.
- Datadog ≥ High recall is 0.95 points lower (710 vs 718 of 844). The four
  real packages behind most of that need rules this pass did not add:
  import-time `torch.load(…, weights_only=False)` of a bundled model, and a
  download written to a file and then executed (a correlation from NET-00x to
  CODE-013 through a shared path identifier, which needs the correlation linker
  to accept a `with … as` / `open(PATH, 'wb')` binding, not only assignments).
- An HTTP call from `setup.py`, or at import to a raw-IP URL, reports at Low
  like any other HTTP call. Install-time and import-time context would justify
  Medium (a context rule on the install-hook file set, or an install-hooks pack
  rule scoped to `setup.py`); it was not added here.
- A download of a Windows executable passed to PowerShell through a variable
  (`subprocess.run(["powershell", "-Command", cmd])`) is Low; NET-RCE-001 only
  sees the one-line pipe and `IEX` cradle forms.
- SkillSpector's declaration-mismatch fixtures (underdeclared permissions,
  inappropriate capability for the description) are not judged by any Sigil
  rule; they were HIGH before only by capability volume.

## Reproducing

`scripts/benchmark_skills.py` is added by the skill-scanner benchmark branch
(`claude/sigil-skillspector-comparison-jz4v68`, commit 31c0228); it is not on
this branch's base. `scripts/run_eval.py` is on main.

```bash
export CARGO_TARGET_DIR=/path/to/target CARGO_INCREMENTAL=0
(cd cli && cargo build --release)

# Skills benchmark (Sigil only)
SIGIL_BIN=$CARGO_TARGET_DIR/release/sigil python3 scripts/benchmark_skills.py \
    --tools sigil --malicious <datadog ai-skills, extracted> --sample-depth 2 \
    --clean <anthropics/skills> --clean <NVIDIA/skills> \
    --clean <openai/skills> --clean <vercel-labs/agent-skills> \
    --workers 3 --out <out>

# Datadog recall
SIGIL_BIN=$CARGO_TARGET_DIR/release/sigil python3 scripts/run_eval.py \
    --dataset datadog --dataset-path <malicious-software-packages-dataset> \
    --out <out> --limit 204
```

The "before" column is the same commands with a binary built from `dc82a94`.
