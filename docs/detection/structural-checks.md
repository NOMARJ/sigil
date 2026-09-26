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
`depsrc.rs`, `padding.rs`, `lpriv.rs`, `lifecycle.rs`). Their rule metadata — title, remediation,
references, tags — lives in packs like every other rule, in a new `engine_rules` section
(`cli/packs/core/v1/structural.json` and `supply_chain.json`), so JSON, SARIF and HTML
output explain them exactly like regex findings, and `sigil diff` can tell a finding from
a newly added rule apart from a change in the code. A unit test pins each rule's documented
phase, severity and evidence to what the engine emits.

## Rules

| Rule | Phase | Severity | What it means |
|---|---|---|---|
| `ARTIFACT-001` | Provenance | High | Python bytecode (`.pyc`/`.pyo`/`__pycache__`) shipped that could not be matched to its source: no size field (Python 2, 3.0–3.2), an unchecked hash, a source missing or too large to compare, a file that is not bytecode, or any divergence below. One finding per directory. |
| `ARTIFACT-002` | Obfuscation | Critical (standalone) | Bytecode Python runs *instead of* the reviewed source: an unchecked hash-based pyc whose hash does not match the shipped `.py`; a sourceless `.pyc` at an importable location; or a pyc the import system loads as-is (unchecked hash, matching checked hash, or recorded mtime *and* size equal to the source's) whose constants name URLs or three or more identifiers the source never mentions. |
| `ARTIFACT-003` | Obfuscation | Critical (corroborate) | Bytecode compiled from different source than shipped: a recorded source size no line-ending conversion explains, a checked-hash mismatch, a `__pycache__` entry with no source, or URL constants / three or more identifiers the source never mentions in a pyc Python would not load as-is. One finding per directory. |
| `ARTIFACT-004` | Obfuscation | Critical (corroborate) | ELF / PE / Mach-O / Java class / WASM / DEX / Lua bytecode under a document, text, image or source-code name (`helper.py`, `run.sh`). |
| `ARTIFACT-005` | Obfuscation | High | Archive (zip, gzip, tar, 7z, rar, bzip2, xz) under a document, text, image or source-code name (`python app.py` runs the `__main__.py` of a zip named `app.py`), or a `#!` script under a document or image name. |
| `ARTIFACT-006` | Obfuscation | High | Native executable inside a hidden file or directory. |
| `ARTIFACT-007` | Provenance | Low | Archive shipped in the tree. Observation; its contents were scanned. |
| `ARTIFACT-008` | Provenance | Medium | Archive not fully inspected (corrupt, unsupported format, nesting deeper than two, caps). |
| `ARTIFACT-009` | Obfuscation | High | Password-protected archive member. |
| `ARTIFACT-010` | Provenance | High | Archive member path or link target escapes the extraction root (zip-slip). |
| `ARTIFACT-011` | Obfuscation | High | Executable or bytecode inside an archive; any script, program or VBA project inside an Office/ODF document. |
| `ARTIFACT-012` | Provenance | Low | Python bytecode caches that match their shipped `.py` (header size or checked hash agrees, no foreign constants) — what CPython writes beside a script the first time it runs. One observation per tree. |
| `DEPSRC-001` | Network/Exfil | High | A config file replaces the default registry or index with an unrecognised host. |
| `DEPSRC-002` | Network/Exfil | High | A config file adds an extra index, find-links source or supplemental source on an unrecognised host (dependency confusion). |
| `DEPSRC-003` | Network/Exfil | Medium | A config file routes one scope (npm `@scope:registry`, yarn `npmScopes`, bunfig scopes, Cargo alternative registries, uv/poetry explicit indexes) to an unrecognised host. |
| `DEPSRC-004` | Network/Exfil | Medium | A config file disables TLS verification for package downloads. |
| `DEPSRC-005` | Network/Exfil | High | A dependency is fetched directly from a URL on an unrecognised host. |
| `DEPSRC-006` | Network/Exfil | Medium | An install command in instructions or a script (including `package.json` scripts) points pip / uv / npm / yarn / poetry / mvn / cargo at an unrecognised index or at any host over plaintext `http://`, or writes the equivalent config line (`echo 'registry=…' > ~/.npmrc`, a heredoc into `pip.conf`). |
| `DEPSRC-007` | Network/Exfil | High | Shipped configuration fetches a package source over plaintext `http://` from a non-local host. |
| `PAD-001` | Prompt Injection | High | A padding run followed by instruction-like text. |
| `PAD-002` | Prompt Injection | Medium | A padding run followed by other text. |
| `PAD-003` | Prompt Injection | Low | A large padding run with nothing after it. |
| `LPRIV-001` | Skill Security | Medium | The skill's scripts use a capability its `allowed-tools` / `permissions` declaration does not cover. |
| `LPRIV-002` | Skill Security | Low | Wildcard grant that `SKILL-008` did not already report. |
| `LPRIV-003` | Skill Security | Low | An explicit `permissions` entry (shell, network, env) nothing in the skill appears to use. |
| `INSTALL-010` | Install Hooks | Medium | Rewritten from `INSTALL-003`: a `preinstall` / `postinstall` that is exactly `node <local .js>`, where that script and the local scripts it requires pass the inert test (see below). Still runs on install, so still an `install_time_execution` action. |
| `INSTALL-011` | Install Hooks | Low | Rewritten from `INSTALL-003`: exactly `npx only-allow <pnpm\|yarn\|npm\|bun>`, a package-manager guard. |
| `INSTALL-012` | Install Hooks | Low | Rewritten from `INSTALL-004`: a `prepare` / `prepublish` whose `npm run` chain ends only in build steps. |
| `CODE-016` | Code Patterns | Medium | Rewritten from `CODE-014`: a `bin` script's `execSync` that installs the package's own `<name>-<platform>-<arch>@<version>` (the platform-binary launcher pattern). |

`SUPPLY-005` is narrowed by this change: it now reads only `package.json`
`publishConfig` (where the *author* publishes) at Low. Install-time redirection in
`.npmrc` and `pyproject.toml`, which it used to match with a substring allow-list, is
reported by `DEPSRC-*` with real host parsing, so the two no longer double-report.

## Shipped bytecode (`ARTIFACT-001` .. `003`, `012`)

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
  number. Sigil recomputes it — SipHash-1-3 (CPython 3.11+), checked against CPython
  3.11's own `_imp.source_hash`, and SipHash-2-4 (3.7–3.10), checked against CPython
  3.10.20's (test vectors in `bytecode.rs`); either match counts — over the shipped source
  and its CRLF/LF variants. An *unchecked* pyc that
  does not match is `ARTIFACT-002`: Python loads it without looking at the source. This
  is exactly the `tjade273-agent-skills-*` samples in the Datadog `ai-skills` set, where
  `formatter.cpython-311.pyc` matches `formatter.py` and both `utils.cpython-31x.pyc`
  files do not.
- **Timestamp pycs** record the source size. A size that disagrees is re-checked against
  CRLF↔LF conversion before it counts: every one of the 39 size mismatches in
  `luoluoluo22-jianying-editor-skill` equals the file's line count (compiled on Windows,
  shipped with LF), and none of them is reported. A *mismatching* mtime is never evidence,
  because git checkouts and most extractors rewrite mtimes; a *matching* mtime and size is
  used the other way round, to know that Python will load the file as-is.
- A pyc whose header agrees can still have been compiled from something else — headers
  are written by whoever built the file. Two content checks: URL constants absent from
  the source (allowing for compiler-folded string concatenation), and *foreign words*:
  identifier-like words (4+ characters) in the string constants — names, literals,
  docstrings — that the source never mentions, after dropping what the compiler adds
  (`<module>`, `<locals>`, `<listcomp>`, dunders, the `co_filename` path, the `return`
  annotations key, 3.14's `format` parameter) and undoing private-name mangling
  (`_Foo__attr` → `__attr`). Three or more foreign words is divergence. Measured by
  compiling all 799 `.py` files in the four clean catalogues with CPython 3.10, 3.11, 3.12
  and 3.13 (compile only, nothing executed) and running the same extraction: no honest
  pyc had more than one foreign word; the two `tjade273` backdoor pycs have 10 and 11.
- Divergence is `ARTIFACT-002` (standalone) when Python would load the file as-is — an
  unchecked hash, a matching checked hash, or a timestamp pyc whose recorded mtime and size
  both equal the source file's (an archive that preserves mtimes makes that easy to
  arrange) — and `ARTIFACT-003` (corroborate) otherwise, because Python recompiles the
  source instead. This closes the obvious bypass of the hash check: an unchecked pyc whose
  header hash is computed over the *shipped* source while its code is something else.
- A cache that agrees with its source in every way checked (size or checked hash, no
  foreign URL, fewer than three foreign words) is `ARTIFACT-012`, one Low observation for
  the tree. CPython writes exactly these beside a script the first time it runs, so an
  installed skill that has been used once has them; reporting them as `ARTIFACT-001` High
  made such a skill HIGH RISK on its own (see "Adversarial review" below).
- Virtual environments are walked on purpose (a skill can ship a `.venv` with a
  sourceless module in it and tell the agent to run `.venv/bin/python`; the content scan
  skips `.venv/` entirely). A developer's own venv stays quiet because the caches pip and
  the interpreter write agree with their sources and collapse into the one `ARTIFACT-012`
  observation; before that, a non-git project with a fresh `.venv` (852 pycs) produced 105
  `ARTIFACT-001` High findings, one per cache directory, plus an `ARTIFACT-003` for a regex
  read as a URL (see below). Files past the 2,000-file inspection cap are one `ARTIFACT-001`
  finding for the tree, not one per directory.
- When bytecode is *not* the shipped source, its string constants (pulled out of the
  marshal stream without executing anything) are handed to every content phase as a
  derived file, so a URL or command that only exists in the bytecode is still matched.

Bounds: 50,000 walk entries, 2,000 inspected bytecode files, 8 MB per pyc, 1 MB of
constants per pyc.

## Concealed executables and archives (`ARTIFACT-004` .. `011`)

Every walked file's first 4 KB is sniffed for ELF, PE (MZ + `PE\0\0`, or an MZ DOS header),
Mach-O (thin and fat), Java class (CAFEBABE + class-file major version, told apart from fat
Mach-O by the next word), WASM, DEX, Lua bytecode, zip, gzip, tar (`ustar` at 257), 7z,
rar, bzip2, xz and `#!`. The result is compared with what the name claims — a document,
text, image or source-code extension. Office formats that are zips by design
(docx/xlsx/pptx/odt/epub...) are not "disguised"; a zip that contains `[Content_Types].xml`
or `mimetype` is treated as a document whatever it is called (`.instructions.docx.txt`),
which means any script or program inside it is `ARTIFACT-011`. Only the document's own
parts (`*.xml`, `*.rels`, `*.xhtml`, `*.css`, `mimetype`, …) are left unscanned: every
other text member of such a zip is scanned like any archive member, so adding a one-line
`mimetype` member to a zip does not hide the `SKILL.md` packed beside it.

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
to the skill — but only when the main walk actually scanned that file: a copy of a file
under an excluded or ignored path (`node_modules/`, `.sigilignore`) is scanned from the
archive. AppleDouble (`__MACOSX/`, `._*`) entries are skipped. Archive members count
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

Configuration lines written by a script or quoted in instructions are read too:
`echo "registry=…" > ~/.npmrc`, `@scope:registry=…`, a heredoc body writing `pip.conf`
(`index-url = …`), `npm set registry …`, `pip config --user set global.index-url …`, and
`package.json` `scripts`. `registry` is also an ordinary word and keyword argument, so a
bare `registry=` counts only on a line that looks like config (it mentions `npmrc`, starts
with `registry=` / `@scope:registry=`, or is an `echo`/`printf`); pip's hyphenated keys are
never code. A code forge (github.com, gitlab.com, …) is exempt as the home of a direct git
dependency, but not as an index or `--find-links` page: those serve whatever one account
there uploaded.

Configuration shipped in the tree is High (it applies silently to every install in that
directory); a command in instructions is Medium (a reviewer can see it, but an agent
following the skill will run it) — including a plaintext `http://` index in a command,
which is `DEPSRC-006`, not `DEPSRC-007`. `pip install -i http://mirrors.aliyun.com/…` is
how a lot of documentation is written, and at High one such line in a `SKILL.md` was a
HIGH verdict on its own.

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
diagram edges), or an end-of-line comment in a data file is ignored. In JSON and YAML,
leading ASCII spaces and tabs are nesting depth, not padding (a schema 45 levels deep is
indented 90 columns); a leading run that contains any Unicode filler still counts. At most
1,000 runs per file are classified and line numbers come from one precomputed index, so a
file made of a million padded lines costs one pass.

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

## Lifecycle scripts and platform launchers (`INSTALL-010` .. `012`, `CODE-016`)

`INSTALL-003` reports every `preinstall` / `postinstall` key at Critical and
`CODE-014` every `execSync` of an interpolated command at High, because a line rule
sees the key or the call and never what it does. `cli/src/scanner/lifecycle.rs` runs
after the content phases, reads the parsed `package.json` and the files a script
names, and rewrites a finding only when a positive test passes. Anything it cannot
prove keeps the pack's rule and severity. The finding keeps its file, line, phase and
weight; its rule id, severity and snippet change, and the snippet says why.

- **`INSTALL-010`** (from `INSTALL-003`, Medium). The command is exactly
  `node [./]<path>.{js,cjs,mjs}` inside the package, with no flags or chaining. That
  script, and the relative scripts it requires two levels deep, must each be at most
  4 KiB of printable ASCII with lines of at most 200 bytes, and:
  - `require` only of a string literal naming `os`, `path`, `url`, `util` (or their
    `node:` forms), a relative `.json` inside the package, or a relative `.js` / `.cjs`
    / `.mjs` file inside it, plus `require.resolve(`. A bare `require` (aliasing) fails;
    static `import` follows the same list and `import(` fails.
  - `process` only as `.exit`, `.exitCode`, `.argv`, `.platform`, `.arch`, `.version`,
    `.versions`, `.stdout`, `.stderr`, `.cwd`. `process.env` fails, so a script cannot
    print a CI token into the install log.
  - `os` bound only as `os` (or destructured to allowed names) and used only as
    `.platform`, `.arch`, `.type`, `.release`, `.EOL`.
  - No computed member access (`x[`, `)[`, `][`, except a numeric index such as
    `argv[2]`), no computed keys, no `\x`, `\u` or octal escapes, no IPv4 literal, and
    no URL outside a `console.*` call.
  - None of `global`, `globalThis`, `this`, `self`, `arguments`, `eval`, `Function`,
    `constructor`, `__proto__`, `prototype`, `fetch`, `XMLHttpRequest`, `WebSocket`,
    `Buffer`, `atob`, `fromCharCode`, `Reflect`, `Proxy`, the property-descriptor and
    prototype functions, `WebAssembly`, `Worker`, `createRequire`, `with (`.
- **`INSTALL-011`** (from `INSTALL-003`, Low). The command is exactly
  `npx [-y |--yes ]only-allow <pnpm|yarn|npm|bun>`, and the manifest neither declares,
  bundles nor overrides `only-allow`.
- **`INSTALL-012`** (from `INSTALL-004`, Low). The `prepare` / `prepublish` command,
  the `pre`/`post` scripts npm runs around it, and every `npm|pnpm|yarn run X` they
  reach (three levels deep, again with `preX` / `postX`) consist only of `&&`, `||` and
  `;` between these steps: `tsc` with flags or `-p|--project|-b|--build <x>.json`;
  `husky` or `husky install`; `[shx] chmod +x <path>`; `shx mkdir -p`, `shx cp [-r]`,
  `shx rm -rf` or `rimraf` on paths; `true`; `exit 0`. A path must be relative to the
  package: no leading `/`, `~`, `$` or `-`, no `..` segment, no shell syntax. Each tool
  the steps use (`typescript`, `husky`, `shx`, `rimraf`) must be a dependency the
  manifest pins itself, with a registry version range (no `git`, `github:`, `file:`,
  `link:`, URL, `npm:` alias or `workspace:`), and must not be bundled, overridden
  (`overrides`, `resolutions`, `pnpm.overrides`) or resolved off the registry by a
  shipped lockfile. An **undeclared** tool name is not trusted: npm prepends
  `node_modules/.bin` to PATH for lifecycle scripts, so a dependency shipping a `tsc` /
  `husky` / `rimraf` / `shx` bin would run in place of the real tool while the package
  never named the real one, so such a `prepare` stays `INSTALL-004` (Medium).
- **`CODE-016`** (from `CODE-014`, Medium). The file is a `bin` target of its nearest
  manifest; the manifest lists at least two `optionalDependencies` named
  `<name>-<linux|darwin|win32|freebsd>-<x64|arm64|ia32|arm>`, every one at the
  manifest's own version; the call starts its line and is
  `` execSync(`npm install ${X}@${Y}<flags>`, options) `` or
  `` execSync(`${V}<flags>`, options) `` with `V` a constant holding that template;
  `X` is a constant holding `` `${N}-${P}-${A}` `` where `N` is `<pj>.name`, `P` is
  `os.platform()` or `process.platform`, `A` is `os.arch()` or `process.arch`, and
  `<pj>` is `require('./package.json')` of that same manifest; `Y` is `<pj>.version`.
  Every name is resolved through a single `const` declaration whose block encloses the
  use, with no reassignment, parameter, `catch`, `for…of`, destructuring or rest
  binding of the same name anywhere in the file, and the file contains no `eval(` or
  `with (` in code. Flags must be from a list that changes nothing about what is
  installed or where from (`--no-save`, `--no-audit`, `--no-fund`, `--prefer-online`,
  `--prefer-offline`, `--no-package-lock`, `--no-progress`, `--silent`, `--quiet`, and
  one `--prefix .`); the options object may not set `env`, `shell`, `argv0`, `uid` or
  `gid` or spread another object.

None of the manifest classes apply when a `node_modules` directory or a `binding.gyp`
sits beside the manifest: npm would run the shipped tools, or `node-gyp rebuild`, as
well. Findings from decoded content and from the tail of an oversized file are never
rewritten.

What the classifier trusts, and so what it cannot see:

- It trusts that `node`, `npx`, `tsc`, `husky`, `shx` and `rimraf` on the install-time
  `PATH` are the real tools. npm puts `node_modules/.bin` first on that `PATH`, so a
  *dependency* that declares a `bin` with one of those names would run instead. This
  pass does not fetch or read dependencies; such a dependency is only seen when it is
  scanned itself (`sigil npm <dependency>`). The rewritten `INSTALL-010` stays Medium
  and an action behaviour for that reason.
- It trusts the platform packages a launcher installs to be the publisher's own, as
  its manifest declares them. It does not fetch them.
- `INSTALL-003` itself does not cover npm's `install` key, or a key written with JSON
  escapes (`"postinstall"`); both are open gaps, independent of this pass.

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

## Adversarial review (ws/engine-v)

A second pass read the whole lane as a skeptic, re-ran its measurements, and attacked each
rule with variants of the shape it claims to cover and with benign files it must leave
alone. Every number below came from a command run on 2026-09-24.

### Reproduced

```
Data Source: Real corpora (204 malicious ai-skills, 455 clean vendor skills), SkillSpector's
             test-derived parity corpus, and the NVIDIA catalogue for timing
Sample Size: 659 benchmark samples; 1,796 parity rows; 382 skills x 3 runs per binary
Limitations: One benchmark run per binary on a shared 4-CPU machine (load average 13-28);
             the baseline benchmark is the lane's stored run of the dc82a94 binary.
```

The lane's own numbers reproduced exactly with a release build of `ws/engine` HEAD:
malicious blocked 142 → 144 and warned 149 → 151 (against the stored baseline run), clean
blocked 108 and warned 226 unchanged, the same per-rule counts on both corpora, and parity
430 rows with any finding / 285 High or above (SC8 6/7, P9 20/50 any and 12/50 High+). The
three PE3 rows "lost" against the stored parity baseline carried only `PROV-BUDGET-001`
there, as the lane said.

### What was wrong, and what changed

| Finding | Evidence (before) | Fix |
|---|---|---|
| A skill that has simply *run* was HIGH RISK. CPython writes `__pycache__/x.cpython-3xx.pyc` beside a script the first time it runs; `ARTIFACT-001` High made an installed two-file skill HIGH RISK on its own. | Synthetic skill (`SKILL.md` + one script, compiled with `py_compile`): baseline LOW, `ws/engine` **HIGH RISK** (score 9). | Caches that agree with their source are `ARTIFACT-012` (Low, one per tree). Result: LOW RISK, score 1. |
| A non-git project with a fresh `.venv` got **105** `ARTIFACT-001` High findings, one per cache directory (MEDIUM RISK, score 976). | `python3 -m venv .venv` (852 pycs) plus a two-line script. | Same aggregation: one `ARTIFACT-012`; LOW RISK. Venvs are still walked — SkillSpector's own SC8 test ships a sourceless `.venv/lib/payload.pyc`, and it is still reported (`ARTIFACT-002` + `ARTIFACT-001`). |
| The URL-constant check read a regex as a URL. pip's vendored urllib3 `util/url.py` folds its URI regex (`^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(?://…`) into one constant with `://` in it. | The venv above: `ws/engine` reported it as `ARTIFACT-003` (Critical, corroborate); with the runs-as-is upgrade it would have been `ARTIFACT-002`, a CRITICAL verdict on a clean project. | A URL needs a letter scheme and a dotted host; a host named anywhere in the source accounts for it (implicit concatenation). |
| Forged header bypass. An unchecked-hash pyc whose hash is computed over the *shipped* source, with other code in it, got only `ARTIFACT-001`. | Fixture `forged_unchecked_pyc`: no `ARTIFACT-002`. | Foreign-word check (3+ identifiers/strings the source never mentions); divergence in a pyc Python loads as-is is `ARTIFACT-002`. Result: CRITICAL. On honest bytecode: 0 of 798 pycs per CPython 3.10, 3.11, 3.12 and 3.13 and 0 of 852 venv pycs trip it (all 4,044 are `ARTIFACT-012`). |
| One `mimetype` member hid a zip's text. Any zip containing `mimetype` or `[Content_Types].xml` was treated as a document and its text members were never scanned. | Fixture: a zip with `mimetype` + an injection `SKILL.md` was **LOW RISK**; the same zip without `mimetype` was CRITICAL. | Only document parts are skipped. Result: CRITICAL (`PROMPT-001`, `CRED-005`, `CODE-007`). |
| A member identical to the file beside the archive was skipped even when that file was never scanned (excluded or ignored path). | Code reading; unit test. | Skip only if the main walk scanned the sibling. |
| Machine code under a source name was invisible. `helper.py`, `run.sh`, `index.js` that are ELF: no finding at all. | Fixtures: three LOW RISK, no findings. | `ARTIFACT-004` (and a zip named `app.py`, which `python app.py` runs, is `ARTIFACT-005`). Result: HIGH RISK each. |
| DEPSRC missed the script-written forms: `echo "registry=…" > .npmrc`, a heredoc into `pip.conf`, `npm set registry`, `pip config --user set global.index-url`, `--registry` in `package.json` scripts. | Fixtures: no DEPSRC finding on any of them. | All read now (`DEPSRC-006`, Medium). `registry=` needs an npm-config-shaped line and npm's lower-case key, so `client.login(registry=…)` and Docker `REGISTRY=` stay quiet (tested). |
| Plaintext `http://` in an *install command* was `DEPSRC-007` High, against the lane's own "command = Medium" rule. | `pip install -i http://mirrors.aliyun.com/pypi/simple/ requests` in a one-file `SKILL.md`: HIGH RISK via `DEPSRC-007` High. | `DEPSRC-006` Medium; `DEPSRC-007` High is for shipped configuration. (On this branch's scoring the one-file skill is still HIGH through the density term — 4 points in 1 file; under the integrated scoring, which requires a High finding for HIGH, it is MEDIUM.) |
| A code forge was exempt as an *index*. `--find-links https://github.com/<account>/…/releases/…` serves whatever that account uploaded. | Fixture: no DEPSRC finding. | Forges are exempt only for direct git dependencies. Result: `DEPSRC-002` High. |
| Deep JSON indentation read as padding. A key 90 columns in (a schema 45 levels deep) whose text said "delete … token" was `PAD-001` High. | Fixture `json_deep_indent`: **HIGH RISK**. | Leading ASCII spaces/tabs in JSON/YAML are nesting; Unicode filler still counts (tested). Result: LOW RISK, no finding. |
| Quadratic work on hostile files: the DEPSRC per-line dedupe, the Maven `<url>` look-back, the package.json per-dependency line search, and the PAD line numbering. | Code reading. | Linear; unit tests on a 50,000-line requirements file, a 20,000-`<url>` pom and 50,000 padded lines. |
| SipHash-2-4 (CPython 3.7–3.10 hash pycs) was unverified. | The lane said so. | Test vectors from CPython 3.10.20's `_imp.source_hash`; the implementation was already correct. |

### Measured after the fixes

Release build of `ws/engine-v`.

| | `ws/engine` HEAD | `ws/engine-v` |
|---|---:|---:|
| Malicious blocked / warned (of 204) | 144 / 151 | 144 / 151 |
| Clean blocked / warned (of 455) | 108 / 226 | 108 / 226 |
| Samples whose verdict changed | — | 0 of 659 |
| Parity rows, any / High+ (of 1,796) | 430 / 285 | 430 / 285 (no row gained or lost) |
| Adversarial attack fixtures flagged at Medium or above by any rule (of 15) | 7 | 14 |
| Adversarial benign fixtures with a HIGH or CRITICAL verdict (of 6) | 2 | 1 (the plaintext-mirror row above) |
| Engine rules on the 455 clean skills | `ARTIFACT-007` ×2 (Low), `DEPSRC-002`/`-005` ×1 (the hostile nvflare eval fixture) | identical; every new shape fires on 0 clean skills |
| CPU time, whole NVIDIA tree, median of 3 alternating runs | 45.45 s | 45.55 s (+0.2%) |
| CPU time against the lane's base binary (dc82a94) | — | 43.20 s → 45.01 s (+4.2%) |

On the 204 malicious skills the only change is that `luoluoluo22-jianying-editor-skill` and
`natemcgrady-slack-gif-creator` now also carry `ARTIFACT-012` for the caches that match
their sources; their divergent pycs keep `ARTIFACT-001`/`003` and both stay MEDIUM, as
before. The one adversarial attack fixture still missed is `setup.py` `dependency_links`,
which pip has ignored since 19.0.

The adversarial fixtures are synthetic (`advfix.py` in the review's scratch directory):
15 attack shapes and 6 benign counterparts, each a one-directory skill; they measure shape
coverage, not prevalence.

**On the integrated tree.** `ws/engine` is already merged into
`claude/sigil-skillspector-comparison-jz4v68`, whose later scoring needs a High finding
for HIGH and ignores Low observations. A trial merge of this branch into that tip (one
conflict, `inspect_one`'s timestamp arm in `bytecode.rs`: take this branch's side) passes
`cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo test`
(699 + 7 + 4 tests) and the self-scan gate. Against the tip itself, same benchmark and
corpora: malicious blocked/warned 173/184 → 173/184 and clean 8/73 → 8/73 (no verdict
changed on any of the 659 samples); adversarial attack fixtures flagged at Medium or above
5/15 → 14/15; benign fixtures at HIGH or above 2/6 → 0/6; the used-once skill HIGH RISK →
LOW RISK; the fresh `.venv` project 107 findings (MEDIUM) → an `ARTIFACT-012` and a Low
`NET-001` (LOW).

## Known gaps

- Bytecode is inspected through its header and string constants only; there is no
  disassembler. Bytecode whose header agrees with the source and whose constants name
  nothing the source does not (fewer than three foreign words, no foreign URL) is taken to
  be the source (`ARTIFACT-012`, Low). Code rewritten using only names and strings the
  source already contains — a flipped comparison, a swapped call between two names the
  file uses — is not detected.
- `setup.py` `dependency_links` is not parsed; pip has ignored it since 19.0.
- Archives in 7z, rar, bzip2 and xz are reported as not inspected (`ARTIFACT-008`), not
  opened. Office document XML text is not scanned (only runnable members inside it are
  reported).
- Gradle repository blocks and conda channels are not parsed for dependency sources.
- Hidden `#!` scripts are not an `ARTIFACT` finding (see above); their content is scanned.
- LPRIV compares declarations with what the other phases *report*; a capability used in
  a way no rule detects is not evidence of under-declaration.
