# Structural checks

Most of Sigil's detection is declarative: regex rules in `cli/packs/core/v1/*.json`,
matched line by line. Some attacks cannot be expressed that way, because the evidence is
not a line of text:

- a `.pyc` whose embedded source hash does not match the `.py` next to it;
- a file called `logo.png` whose first four bytes are `\x7fELF`;
- a payload inside `bundle.zip`, which a line matcher never opens;
- an `.npmrc` whose registry host is `registry.npmjs.org.attacker.example` (a substring
  allow-list says "npmjs.org, fine");
- two hundred blank lines between a harmless description and an instruction;
- a `SKILL.md` that declares `allowed-tools: Read` while its script posts to the network.

These checks live in the scanner engine (`cli/src/scanner/bytecode.rs`, `artifacts.rs`,
`depsrc.rs`, `padding.rs`, `lpriv.rs`). Their rule metadata — title, remediation,
references, tags — lives in packs like every other rule, in a new `engine_rules` section
(`cli/packs/core/v1/structural.json` and `supply_chain.json`), so JSON, SARIF and HTML
output explain them exactly like regex findings, and `sigil diff` can tell a finding from
a newly added rule apart from a change in the code. A unit test pins each rule's documented
phase, severity and evidence to what the engine emits.

## Rules

| Rule | Phase | Severity | What it means |
|---|---|---|---|
| `ARTIFACT-001` | Provenance | High | Python bytecode (`.pyc`/`.pyo`/`__pycache__`) shipped. One finding per directory. |
| `ARTIFACT-002` | Obfuscation | Critical (standalone) | Bytecode Python runs *instead of* the reviewed source: an unchecked hash-based pyc whose hash does not match the shipped `.py`, or a sourceless `.pyc` at an importable location. |
| `ARTIFACT-003` | Obfuscation | Critical (corroborate) | Bytecode compiled from different source than shipped: a recorded source size no line-ending conversion explains, a checked-hash mismatch, a `__pycache__` entry with no source, or URL constants the source never mentions. One finding per directory. |
| `ARTIFACT-004` | Obfuscation | Critical (corroborate) | ELF / PE / Mach-O / Java class / WASM / DEX / Lua bytecode under a document, text or image name. |
| `ARTIFACT-005` | Obfuscation | High | Archive (zip, gzip, tar, 7z, rar, bzip2, xz) or `#!` script under a document, text or image name. |
| `ARTIFACT-006` | Obfuscation | High | Native executable inside a hidden file or directory. |
| `ARTIFACT-007` | Provenance | Low | Archive shipped in the tree. Observation; its contents were scanned. |
| `ARTIFACT-008` | Provenance | Medium | Archive not fully inspected (corrupt, unsupported format, nesting deeper than two, caps). |
| `ARTIFACT-009` | Obfuscation | High | Password-protected archive member. |
| `ARTIFACT-010` | Provenance | High | Archive member path or link target escapes the extraction root (zip-slip). |
| `ARTIFACT-011` | Obfuscation | High | Executable or bytecode inside an archive; any script, program or VBA project inside an Office/ODF document. |
| `DEPSRC-001` | Network/Exfil | High | A config file replaces the default registry or index with an unrecognised host. |
| `DEPSRC-002` | Network/Exfil | High | A config file adds an extra index, find-links source or supplemental source on an unrecognised host (dependency confusion). |
| `DEPSRC-003` | Network/Exfil | Medium | A config file routes one scope (npm `@scope:registry`, yarn `npmScopes`, bunfig scopes, Cargo alternative registries, uv/poetry explicit indexes) to an unrecognised host. |
| `DEPSRC-004` | Network/Exfil | Medium | A config file disables TLS verification for package downloads. |
| `DEPSRC-005` | Network/Exfil | High | A dependency is fetched directly from a URL on an unrecognised host. |
| `DEPSRC-006` | Network/Exfil | Medium | An install command in instructions or a script points pip / uv / npm / yarn / poetry / mvn / cargo at an unrecognised index. |
| `DEPSRC-007` | Network/Exfil | High | A package source over plaintext `http://` to a non-local host. |
| `PAD-001` | Prompt Injection | High | A padding run followed by instruction-like text. |
| `PAD-002` | Prompt Injection | Medium | A padding run followed by other text. |
| `PAD-003` | Prompt Injection | Low | A large padding run with nothing after it. |
| `LPRIV-001` | Skill Security | Medium | The skill's scripts use a capability its `allowed-tools` / `permissions` declaration does not cover. |
| `LPRIV-002` | Skill Security | Low | Wildcard grant that `SKILL-008` did not already report. |
| `LPRIV-003` | Skill Security | Low | An explicit `permissions` entry (shell, network, env) nothing in the skill appears to use. |

`SUPPLY-005` is narrowed by this change: it now reads only `package.json`
`publishConfig` (where the *author* publishes) at Low. Install-time redirection in
`.npmrc` and `pyproject.toml`, which it used to match with a substring allow-list, is
reported by `DEPSRC-*` with real host parsing, so the two no longer double-report.

## Shipped bytecode (`ARTIFACT-001` .. `003`)

The main file walker skips `__pycache__/` for content scanning — in a working tree it is
build output. The bytecode check walks for `.pyc`/`.pyo` on its own, so that skip can no
longer hide anything:

- It honours `.sigilignore` always, and `.gitignore` only inside a git checkout whose
  index tracks no bytecode. A developer's local `__pycache__` is ignored; a repository
  that force-added `.pyc` files past its own `.gitignore` is not. The index is read as
  bytes (`.pyc\0` in `.git/index`); no git process runs.
- For each file it parses the CPython header (3.0 through 3.14 layouts, Python 2) and
  finds the source (`__pycache__/mod.cpython-311.pyc` → `../mod.py`; legacy `mod.pyc` →
  `mod.py`).
- **Hash-based pycs (PEP 552)** carry a SipHash of the source keyed with the magic
  number. Sigil recomputes it — SipHash-1-3, checked against CPython 3.11's own
  `_imp.source_hash`, and SipHash-2-4, the variant CPython used before 3.11 (not checked
  against a 3.7–3.10 interpreter here); either match counts — over the shipped source and
  its CRLF/LF variants. An *unchecked* pyc that
  does not match is `ARTIFACT-002`: Python loads it without looking at the source. This
  is exactly the `tjade273-agent-skills-*` samples in the Datadog `ai-skills` set, where
  `formatter.cpython-311.pyc` matches `formatter.py` and both `utils.cpython-31x.pyc`
  files do not.
- **Timestamp pycs** record the source size. A size that disagrees is re-checked against
  CRLF↔LF conversion before it counts: every one of the 39 size mismatches in
  `luoluoluo22-jianying-editor-skill` equals the file's line count (compiled on Windows,
  shipped with LF), and none of them is reported. The mtime field is not compared, because
  git checkouts and most extractors rewrite mtimes.
- A pyc whose header agrees can still have been compiled from something else: URL
  constants absent from the source (allowing for compiler-folded string concatenation)
  are `ARTIFACT-003` too.
- When bytecode is *not* the shipped source, its string constants (pulled out of the
  marshal stream without executing anything) are handed to every content phase as a
  derived file, so a URL or command that only exists in the bytecode is still matched.

Bounds: 50,000 walk entries, 2,000 inspected bytecode files, 8 MB per pyc, 1 MB of
constants per pyc.

## Concealed executables and archives (`ARTIFACT-004` .. `011`)

Every walked file's first 4 KB is sniffed for ELF, PE (MZ + `PE\0\0`, or an MZ DOS header),
Mach-O (thin and fat), Java class (CAFEBABE + class-file major version, told apart from fat
Mach-O by the next word), WASM, DEX, Lua bytecode, zip, gzip, tar (`ustar` at 257), 7z,
rar, bzip2, xz and `#!`. The result is compared with what the name claims. Office
formats that are zips by design (docx/xlsx/pptx/odt/epub...) are not "disguised"; a zip
that contains `[Content_Types].xml` or `mimetype` is treated as a document whatever it is
called (`.instructions.docx.txt`).

Archives found in the tree are opened in memory, never written to disk:

| Bound | Value |
|---|---|
| Nesting depth | 2 (an archive inside an archive); deeper is `ARTIFACT-008` |
| Members per archive | 2,000 |
| Members per scan | 10,000 |
| Bytes read per member | 4 MB (through `take`, so a lying header cannot exceed it) |
| Decompressed bytes per scan | 128 MB |
| Retained text per scan | 32 MB |

Text members become derived files named `outer.zip!/path/in/zip` (locator
`zip://outer.zip|path/in/zip`) and go through the same per-file pipeline as a file on
disk: every content phase, the decode worklist, inline `sigil:ignore` markers, and
correlation. A member byte-identical to the file at the same relative path beside the
archive is not scanned twice — the common benign shape is a zip of the skill sitting next
to the skill. AppleDouble (`__MACOSX/`, `._*`) entries are skipped. Archive members count
toward `files_scanned`.

## Dependency sources (`DEPSRC-001` .. `007`)

Surfaces parsed: `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `bunfig.toml`, `pip.conf`/`pip.ini`
(including continuation lines), `requirements*.txt` / `constraints*.txt`,
`pyproject.toml` (`[[tool.uv.index]]` with `default`/`explicit`, `[tool.uv]`,
`[[tool.poetry.source]]` with `priority`, `[[tool.pdm.source]]`, `[project]` direct URL
dependencies, `[tool.uv.sources]`), `Pipfile`, `uv.toml`, `package.json` dependency specs,
`.cargo/config.toml`, Maven `settings.xml` / `pom.xml`; and commands in markdown, shell,
PowerShell, Python, JS/TS, YAML, JSON, Dockerfiles and Makefiles (`--index-url`,
`--extra-index-url`, `--find-links`, `pip -i/-f`, `--registry`, `--default-index`,
`npm|yarn|pip config set`, `poetry source add`, `mvn -Dmaven.repo.remote`, and the
`PIP_*`, `UV_*`, `NPM_CONFIG_REGISTRY`, `YARN_NPM_REGISTRY_SERVER`,
`CARGO_REGISTRIES_*_INDEX` variables).

Every destination is parsed (scheme, userinfo — redacted in output — host, port) and the
host classified: the ecosystem default; a short list of vendor indexes and public mirrors
(PyTorch, NVIDIA, PyG, Jetson AI Lab, npmmirror, the main Chinese PyPI mirrors, Google
Maven); a code forge (GitHub, GitLab, Bitbucket, Codeberg); a loopback or private-network
address; or anything else. Only "anything else", or plaintext `http://` to a non-local
host, is reported. Host matching is on label boundaries, so
`registry.npmjs.org.attacker.example` and `evil-nvidia.com` are "anything else".

Configuration shipped in the tree is High (it applies silently to every install in that
directory); a command in instructions is Medium (a reviewer can see it, but an agent
following the skill will run it).

## Whitespace padding (`PAD-001` .. `003`)

Applied to instruction-bearing files (markdown family, `.txt`, `.rst`, `.prompt`, JSON,
YAML, and the agent instruction files). Padding characters are ASCII space/tab/VT/FF and
the Unicode spaces and fillers that render as nothing (U+00A0, U+1680, U+2000–U+200D,
U+202F, U+205F, U+2060, U+3000, U+FEFF, U+180E, U+2800 Braille blank, U+3164/U+FFA0/U+115F/
U+1160 Hangul fillers). Line breaks include CR, CRLF, U+2028, U+2029 and U+0085.

- Vertical: 20 or more consecutive blank lines.
- Horizontal: 80 or more consecutive padding characters on one line, outside code fences.
- Block: the largest contiguous padding span (line breaks included) over 2 KB, when it is
  not already one of the above.

Text after the run decides the severity: instruction-like wording (override, secrecy,
exfiltration, commands, credentials) is High, other text Medium, nothing Low. Alignment is
not padding: a run followed by a table pipe, only punctuation (`#` comment boxes, `│`
diagram edges), or an end-of-line comment in a data file is ignored.

## Least privilege (`LPRIV-001` .. `003`)

Declarations read: `SKILL.md` frontmatter `allowed-tools` (string, comma- or
space-separated, or list; `Bash(cmd:*)` arguments respected) and `permissions` (list,
string or map), and the top-level `permissions` / `allowed-tools` of `manifest.json`,
`plugin.json`, `skill.json`, `tool.json` and `server.json`.

Capabilities used are taken from the findings the other phases already produced in the
skill's scripts (tests, examples, fixtures and docs excluded): shell execution, network,
credential/environment access, persistence-style file writes. Unrestricted `Bash` covers
everything, and so does a `Bash(...)` allowance that runs an interpreter (`python`, `node`,
`uv`, a `.py`/`.sh` script), because that runs the scripts.

`LPRIV-003` (declared but unused) needs the opposite evidence — absence — and findings are
not a capability inventory: `os.environ.get("PORT")` is environment access no credential
rule reports, and a `curl` in `SKILL.md` or a documented model download is network use by
the agent. So "unused" is judged against a broad pattern scan of the skill's scripts and
markdown, only for shell, network and environment (file reads and writes are never called
unused). The first, findings-only version of this check fired on 7 clean NVIDIA skills
that do use what they declare; this version fires on none of the 455.

Every LPRIV finding has weight 1. The most the pass can add for one declaration is 3
points (LPRIV-001 at Medium plus one Low; LPRIV-002 and LPRIV-003 are exclusive) —
below the MEDIUM threshold of 10, and below the density threshold of any skill that has a
script at all (7 points for two files) — so these findings inform a reviewer and never
decide a verdict on their own. A skill that declares nothing is not reported: there is no statement to check.

## Measurements

Every number below came from a command run on 2026-09-23/24 with the release binary built
from this branch (`sigil-final`, commit `c306cc1`) and the release binary built from its
base commit `dc82a94` (`sigil-baseline`), on a 4-CPU machine shared with other builds.

### Benchmark (Datadog `ai-skills` malicious set, four vendor catalogues)

```
Data Source: Real samples — 204 malicious AI skills (Datadog malicious-software-packages-dataset,
             ai-skills bucket); 455 clean skills (anthropics/skills, NVIDIA skills,
             openai/skills incl. .curated/.system, vercel-labs/agent-skills)
Sample Size: 204 malicious, 455 clean; both binaries, same script (benchmark_skills.py,
             --tools sigil, --workers 3), same corpora
Limitations: "Clean" means published by a vendor, not audited. Static only. One run each.
```

| | Baseline | This branch |
|---|---:|---:|
| Malicious blocked (HIGH/CRITICAL) | 142/204 (69.6%) | 144/204 (70.6%) |
| Malicious warned (MEDIUM+) | 149/204 (73.0%) | 151/204 (74.0%) |
| Clean blocked | 108/455 (23.7%) | 108/455 (23.7%) |
| Clean warned | 226/455 (49.7%) | 226/455 (49.7%) |

Verdict changes: `tjade273-agent-skills-skills-simple-formatter` and
`tjade273-agent-skills-test-skills-simple-formatter` NONE → CRITICAL (`ARTIFACT-002`; the
baseline reported nothing at all on either). One clean skill changed: `web-artifacts-builder`
NONE → LOW (the `ARTIFACT-007` observation on its shadcn component tarball). No clean skill
was added to the blocked or warned sets.

New rules on the 455 clean skills: `ARTIFACT-007` (Low) on 2 skills
(`web-artifacts-builder`, `deploy-to-vercel`); `DEPSRC-002` and `DEPSRC-005` (High) on 1
skill, `nvflare-convert-pytorch`, whose `evals/files/injection-pt/requirements.txt` is a
deliberately hostile eval fixture (a fake-credential extra index, a typosquat, a git
dependency on `example.com/evil/telemetry.git`) — a correct detection, and the skill was
already HIGH at baseline. Every other new rule fired on 0 clean skills.

New rules on the 204 malicious skills: `ARTIFACT-001` 4, `ARTIFACT-002` 2, `ARTIFACT-003` 2,
`ARTIFACT-007` 1, `DEPSRC-006` 3, `LPRIV-001` 4, `LPRIV-002` 1. `luoluoluo22-jianying-editor-skill`
(40 cached modules, one with no source) and `natemcgrady-slack-gif-creator` (a pyc compiled
from a different `gif_builder.py`) gain `ARTIFACT-001`/`003` but stay MEDIUM.

### SkillSpector parity corpus

```
Data Source: 1,796 positives mined from SkillSpector's own test suite (83 rule ids),
             each written to a one-file skill and scanned (run_parity.py)
Sample Size: 1,796 rows; SC8 7 rows, P9 50 rows; SC9, SC10, LP1-LP4 have no rows
Limitations: The corpus is noisy — some rows are SkillSpector's own false positives or
             harness artefacts, listed below.
```

| | Baseline | This branch |
|---|---:|---:|
| All rows, any finding | 416 (23.2%) | 430 (23.9%) |
| All rows, High+ | 275 (15.3%) | 285 (15.9%) |
| SC8 (shipped bytecode), any / High+ | 4 / 1 of 7 | 6 / 6 of 7 |
| P9 (whitespace padding), any / High+ | 9 / 9 of 50 | 20 / 12 of 50 |

Three PE3 rows show as "lost" against the stored baseline run; in that run each of them
carried only `PROV-BUDGET-001` (the scan budget ran out under load), not a rule match.

Rows deliberately not matched:

- SC8 `scripts/__pycache__/` — the harness writes a *file* named `__pycache__`; there is no
  bytecode in it.
- P9, 27 rows `repeated U+0078 x8292` / `x20000` — runs of the letter `x` used as filler in
  SkillSpector's tests of other features. Visible repeated letters hide nothing.
- P9 `ordinary text` (a budget test) and two rows (`U+2029 x99`, `\f x100`) whose captured
  source no longer contains the padding.

### SC9 / SC10 / LP fixtures (not in the parity corpus)

Shapes re-created from SkillSpector's own tests (`test_nested_artifacts.py`,
`test_dependency_sources.py`) and its `mcp_*_skill` fixtures, scanned by both Sigil
binaries and by `skillspector scan --no-llm`.

```
Data Source: Synthetic fixtures (32 skills), modelled on SkillSpector's tests
Sample Size: SC9 11 positive / 4 negative; SC10 10 / 3; LP 3 / 1
Limitations: Small, hand-built; measures shape coverage, not prevalence.
```

| Family | Sigil baseline | Sigil (this branch) | SkillSpector |
|---|---|---|---|
| SC9 positives flagged | 0/11 | 10/11 | 10/11 |
| SC9 negatives flagged | 0/4 | 1/4 (Low `ARTIFACT-007` only; verdict LOW) | 0/4 |
| SC10 positives flagged | 2/10 | 10/10 | 9/10 |
| SC10 negatives flagged | 0/3 | 0/3 | 1/3 (`pypi.nvidia.com` in SKILL.md) |
| LP positives flagged | 0/3 | 2/3 | 3/3 |
| LP negatives flagged | 0/1 | 0/1 | 0/1 |

Not matched on purpose: a hidden `#!` script (`.setup.sh`) — hidden hook scripts are routine
(`.husky/`, `.github/`, `.claude/hooks/`), and its content is scanned like any other file;
and SkillSpector's LP3 (no declaration at all), which would fire on most of the 350 clean
skills that declare nothing.

### Scan-time overhead (NVIDIA corpus)

```
Data Source: Real — the 382 NVIDIA skills, scanned by both binaries in alternating order
Sample Size: whole-tree scan x5 per binary; one scan per skill (382 scans) x3 per binary
Limitations: Shared 4-CPU machine (load average 10-23 during the runs). Wall-clock varied
             from 38 s to 83 s for the same scan, so CPU time (user+sys of the scanner
             process) is the reported figure; wall-clock medians are given for completeness.
```

| Mode | Baseline CPU (median) | This branch CPU (median) | Overhead |
|---|---:|---:|---:|
| Whole tree, 5 runs | 45.24 s | 46.67 s | +3.2% |
| One scan per skill (382), 3 runs | 134.26 s | 136.03 s | +1.3% |

Whole-tree wall-clock medians: 83.21 s baseline, 82.45 s this branch (−0.9%, inside the
noise).

## Known gaps

- Bytecode is inspected through its header and string constants only; there is no
  disassembler, so bytecode whose header agrees with the source and that carries no
  foreign URL constant is reported as shipped (`ARTIFACT-001`) but not as divergent.
- Archives in 7z, rar, bzip2 and xz are reported as not inspected (`ARTIFACT-008`), not
  opened. Office document XML text is not scanned (only runnable members inside it are
  reported).
- Gradle repository blocks and conda channels are not parsed for dependency sources.
- Hidden `#!` scripts are not an `ARTIFACT` finding (see above); their content is scanned.
- LPRIV compares declarations with what the other phases *report*; a capability used in
  a way no rule detects is not evidence of under-declaration.
