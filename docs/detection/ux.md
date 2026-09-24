# Preemptive protection: inputs, agent-tooling posture and the PreToolUse gate

This page documents three things Sigil does *before* third-party agent code
runs:

1. **`sigil scan` inputs** — archives, download URLs and GitHub tree links are
   unpacked into quarantine safely, then scanned.
2. **`sigil skills`** — an inventory and posture scan of the skills, plugins,
   hooks and MCP servers already installed for every major coding agent, with
   the `AGENTCFG-*` configuration checks.
3. **`sigil hook pretooluse`** — the Claude Code gate that stops skill, plugin
   and MCP-server acquisition and remote execution, and names the sigil
   command to run instead.

Command syntax is in [cli.md](../cli.md); CI wiring is in [cicd.md](../cicd.md).

---

## 1. What `sigil scan` accepts

| Target | What happens |
|---|---|
| A directory or a plain file | Scanned in place (unchanged). |
| A git URL (`https://github.com/o/r`, `git@…`, `….git`) | Cloned into quarantine and scanned (unchanged; same as `sigil clone`). An `<owner>/<repo>` URL on a known forge stays a clone even when the repository name looks like a file (`vercel/next.js`, `mrdoob/three.js`), and so does a GitLab project path with no `/-/`. |
| `https://github.com/<o>/<r>/tree/<ref>/<dir>` | The repository is cloned (depth 1, `core.symlinks=false`) into quarantine and **only `<dir>` is scanned**. A ref containing `/` (`feature/x`) is resolved against `git ls-remote`. |
| A local archive: `.zip`, `.skill`, `.tar.gz`, `.tgz`, `.tar`, `.whl`, `.vsix`, `.crate`, `.gz` | Unpacked into a new quarantine entry, then scanned. The format is read from the file's leading bytes, so a renamed archive is still unpacked. |
| An `http(s)` URL to an archive or a single file (`…/SKILL.md`, `…/install.sh`, `…/skill.zip`) | Downloaded into quarantine; archives are unpacked. GitHub and GitLab `/blob/` pages are rewritten to their raw URLs (the page itself is HTML, not the file). |
| An extension-less URL on a host that is not a known forge (`https://get.example.com`, `https://git.corp/team/repo`) | Probed with `git ls-remote` (30 s, no credential prompt). A remote that advertises a ref is cloned as before; anything else is downloaded as a file, named by its shebang (`script.sh`, `install.py`). An HTML answer is refused: it is neither a repository nor a file. |

Every materialised target gets a quarantine id (`sigil approve <id>` /
`sigil reject <id>`), and the scan honours the flags you passed (`--fail-on`,
`--format`, `--phases`, …).

### Safe extraction — fails closed

An archive that is unsafe to unpack is **not** partly unpacked and scanned: a
verdict about half an archive is a verdict about something you never
received. The command exits `2`, names the entry and the rule, records the
quarantine entry as rejected and deletes what was written.

| Refused | Why |
|---|---|
| `../x`, `a/../../x`, `..\..\x` (backslashes are separators) | Zip-slip: writes outside the extraction directory. |
| `/etc/x`, `C:/Windows/x` | Absolute and drive-letter paths. |
| Symlinks, hard links, device nodes, FIFOs | A symlink is how an archive writes outside its directory on a second extraction; none of them is content a scanner can judge. |
| Two members with the same name | Which one an installer keeps is up to the installer, so the scan cannot know what it saw. |
| Encrypted members | Cannot be read, so cannot be judged. |
| xz, bzip2, zstd, 7z, rar | Recognised but not supported by this build: unpack it yourself and run `sigil scan <dir>`. |
| More than 20,000 entries, more than 1 GiB written, nesting deeper than 48 | Bombs. Bytes are counted on the decompressed stream, so a header that lies about sizes buys nothing. |

### Downloads

- `https` and `http` only; at most 256 MiB; at most 5 redirects; an
  `https` → `http` redirect is refused.
- Loopback, link-local (including the `169.254.169.254` cloud-metadata
  address), private, shared (`100.64/10`) and unique-local addresses are
  refused unless `SIGIL_ALLOW_PRIVATE_URLS=1` (for internal mirrors). The
  check runs on every redirect hop against every resolved address, and the
  connection is pinned to the address that was checked, so a DNS answer that
  changes between check and connect cannot move it.
- Behind an `HTTPS_PROXY` the proxy resolves names, as it would for any
  client.

### Compared with SkillSpector

SkillSpector's input handler (`input_handler.py`) accepts git URLs, GitHub
`/tree/` links, direct file URLs from an allow-listed set of hosts, local
`.zip` files, `.md` files and directories, and fails closed on its budgets.
Sigil additionally reads `.tar.gz`/`.tgz`/`.tar`/`.gz`, `.skill`, `.whl` and
`.vsix` archives, recognises archives by content rather than extension,
refuses duplicate members, and does not restrict downloads to a host
allow-list (it refuses non-public addresses instead).

---

## 2. Trees with several skills

When the scanned tree holds two or more `SKILL.md` skills — at any depth —
the report adds a per-skill breakdown. SkillSpector only looks at immediate
children, and only with `--recursive`.

```
  Skills (20 skills)
    VERDICT         SCORE  FINDINGS  FILES  SKILL
    CRITICAL RISK     275        59     70  skills/claude-api
    HIGH RISK          56        15     10  skills/mcp-builder
    ...
    LOW RISK            0         0     12  skills/pdf
    1 finding outside any skill directory
```

JSON output gains a `skills` array (`path`, `name`, `verdict`, `grade`,
`score`, `findings_count`, `files`, `max_severity`, `rules`). The key sorts
after `findings`, so the "first `[` on stdout is the findings array" contract
holds.

Each finding goes to the deepest skill directory containing it and is
rebased onto that directory before scoring, so a skill's verdict is the one a
standalone `sigil scan <skill>` computes from the same findings. **The overall
score, verdict and exit code are unchanged** — the breakdown is reporting only.

---

## 3. `sigil skills` — installed agent tooling

`sigil skills scan` (the default) and `sigil skills list` discover what the
agents on this machine and in this project will load on their next start:

| Tool | Skills / content | MCP servers | Hooks and settings |
|---|---|---|---|
| Claude Code | `~/.claude/skills`, `.claude/skills`, `~/.claude/agents`, `~/.claude/commands` (and project), installed plugins (`installed_plugins.json`) and their hooks and `.mcp.json`, known marketplaces | `~/.claude.json` (user and per-project local scope), `.mcp.json`, managed `managed-mcp.json` | `settings.json` / `settings.local.json` hooks, `statusLine`, `apiKeyHelper`, `enableAllProjectMcpServers`, `permissions.defaultMode` |
| Claude Desktop | — | `claude_desktop_config.json` (macOS, Linux, Windows paths) | — |
| Codex | `~/.codex/skills` (incl. `.system/`), `.codex/skills`, `~/.codex/prompts` | `config.toml` `[mcp_servers.*]` | `notify`, `sandbox_mode = "danger-full-access"` |
| Gemini CLI | `~/.gemini/extensions/*` (and their `mcpServers`), `~/.gemini/skills`, commands | `settings.json` `mcpServers` | per-server `trust` |
| Cursor | `.cursor/rules`, `~/.cursor/skills` | `~/.cursor/mcp.json`, `.cursor/mcp.json` | `hooks.json` |
| Windsurf | `.windsurf/rules`, `.windsurf/workflows` | `~/.codeium/windsurf/mcp_config.json` | — |
| VS Code (Copilot) | `.github/prompts`, `.github/instructions`, `.github/skills` | user `mcp.json` / `settings.json` `mcp.servers`, `.vscode/mcp.json` | — |
| Cline / Roo / Kilo | `.clinerules`, `.roo/rules` | VS Code global-storage MCP settings, `~/.cline/…`, `.roo/mcp.json` | `alwaysAllow` / `autoApprove` |
| Continue | — | `config.json`, `config.yaml`, `.continue/mcpServers/*` | — |
| Goose | `~/.config/goose/skills` | `config.yaml` `extensions` | — |
| OpenCode | `~/.config/opencode/skill(s)`, `agent`, `command` | `opencode.json(c)` `mcp` | — |
| Zed, Amazon Q, Kiro, Junie | — | their MCP config files | — |
| OpenClaw | `~/.openclaw/skills`, `~/.openclaw/workspace/skills`, legacy `~/.clawdbot`, `~/.moltbot` | `openclaw.json` | — |
| Shared | `~/.agents/skills`, `.agents/skills` | — | — |

`scan` runs the normal scanner over every skill, plugin, extension and
instruction directory, **scans the local scripts that a hook or MCP server
runs** (`${CLAUDE_PLUGIN_ROOT}/hooks/x.sh`, `node tools/server.js`), and
inspects every configuration entry with the checks below. Secrets are
redacted in every output format.

### `AGENTCFG-*` checks

Severity follows the project policy: an idiom that is routine in legitimate
configs is at most **Low** — reported, never moving a verdict. **Medium** is
suspicious in context. **High/Critical** is an attack shape.

| Rule | Severity | Fires on | Why that severity |
|---|---|---|---|
| AGENTCFG-001 | Low | A package runner (`npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run`) of an **unpinned** package | Routine (most MCP READMEs say `npx -y …`), but it runs whatever the registry serves at every start. Pinned versions do not fire. |
| AGENTCFG-002 | Critical | A download piped or substituted into an interpreter (`curl … \| sh`, `bash <(curl …)`, `iex (irm …)`) | Executes unreviewed remote code on every start. |
| AGENTCFG-003 | High | `docker/podman run` with `--privileged`, dangerous `--cap-add`, host PID/user/IPC namespaces, unconfined profiles, or mounts of `/`, a home directory, `/etc`, the Docker socket or a credential directory | The container is the host. Named volumes and project mounts do not fire. |
| AGENTCFG-004 | Low | `--network host` | Reaches local-only services; common for local tooling. |
| AGENTCFG-005 | High | A known-format credential (`sk-ant-…`, `ghp_…`, `AKIA…`, `xox?-…`, private keys, …) in a **project-scoped** config | The file travels with the repository. |
| AGENTCFG-006 | Medium | A secret-named literal in a project-scoped config. The key's *last word* decides: `…_TOKEN`, `…_SECRET`, `…_PASSWORD`, `…_PAT`, `…_AUTH`, `…_API_KEY`, `…_ACCESS_KEY`, `clientSecret`, `PGPASSWORD`, `Authorization` | Probably a secret; placeholders (`${VAR}`, `<token>`, `your-…`) do not fire, and neither do keys that merely contain those letters (`PYTHONPATH`, `MEMORY_FILE_PATH`, `GIT_AUTHOR_NAME`, `OAUTH_CALLBACK_URL`, `TOKEN_FILE`). |
| AGENTCFG-007 | Low | A credential in a **user-level** config | Routine — vendor docs tell you to put it there — but every skill and server running as you can read it. |
| AGENTCFG-008 | Medium | A remote MCP endpoint over plaintext `http`, a raw public IP, or a raw IP behind wildcard DNS (`<ip>.sslip.io`, `<ip>.nip.io`, `<ip>.xip.io`) | Anyone on the path can rewrite tool descriptions; an unnamed host has no owner to hold to account (one malicious skill in the corpus points its `.mcp.json` at an n8n webhook on `…18.191.220.185.sslip.io`). |
| AGENTCFG-009 | High | A remote MCP endpoint on a tunnel or request-capture host (ngrok, trycloudflare, webhook.site, pipedream, interact.sh, …) | Standard exfiltration and throwaway-C2 infrastructure. |
| AGENTCFG-010 | High | An inline interpreter payload (`-c`, `-e`, `-EncodedCommand`) that decodes or evaluates (`base64 -d`, `b64decode`, `atob(`, `exec(`, `eval(`, …) | Hides what runs. |
| AGENTCFG-011 | Medium | A program run from `/tmp`, `/var/tmp` or `/dev/shm` | World-writable staging directories. |
| AGENTCFG-012 | Medium | Agent-wide auto-approval: `enableAllProjectMcpServers: true`, `defaultMode: bypassPermissions`, Codex `danger-full-access` | Any repository's `.mcp.json`, or any tool call, runs without asking. |
| AGENTCFG-013 | Low | Per-server auto-approval (`trust`, `alwaysAllow`, `autoApprove`) | A deliberate, scoped choice. |
| AGENTCFG-014 | Medium | A hook or server command that sends data to another host (`curl -d/-F/-T/-X POST`, `nc`, `/dev/tcp`) | Notifications are legitimate; review what is sent. |
| AGENTCFG-015 | High | A **hook** that forwards its stdin — the event payload with tool inputs and file contents — off the machine (`curl -d @-`, `\| nc`) | That is exfiltration of everything the agent does. |
| AGENTCFG-016 | Medium | A command that reads credential stores (`~/.ssh/`, `.aws/credentials`, `.npmrc`, keychain, …) | No agent hook needs them. |

A configuration item's verdict is its worst finding (Critical → CRITICAL
RISK, High → HIGH RISK, Medium → MEDIUM RISK); a content item's verdict is the
scanner's. `--fail-on` gates on finding severity, as `sigil scan --fail-on`
does.

### Measured on this repository's test fixtures

`cargo test inventory::` builds a temporary home and project holding every
tool family above, with benign and hostile entries side by side (unit tests,
synthetic data). Each hostile shape produces exactly its rule; the benign
look-alikes — a pinned `npx`, a pinned `uvx`, an https remote endpoint, an
`npm run lint` hook — produce none.

---

## 4. `sigil hook pretooluse` — the preemptive gate

For a `Bash` tool call the hook denies (or asks), and names the command to
run instead:

| Command | Decision | Alternative in the reason |
|---|---|---|
| `claude mcp add x -- npx -y pkg`, `codex mcp add …`, `gemini mcp add …`, `claude mcp add-json …` | deny | `sigil npm pkg && <original>` (and pin it) |
| `claude mcp add --transport http x https://host/mcp` | ask (deny for tunnel hosts) | — (remote code cannot be scanned) |
| `claude mcp add x -- docker run --privileged …` | deny | — |
| `claude plugin marketplace add o/r` | deny | `sigil clone https://github.com/o/r && <original>` |
| `claude plugin install p@m` | deny | vet the marketplace repo with `sigil clone`, then `SIGIL_BYPASS=1` |
| `gemini extensions install <url>` / `link <dir>` | deny | `sigil clone <url> && …` / `sigil scan <dir> && …` |
| `npx skills add o/r`, `clawhub install x` | deny | `sigil clone …` / `sigil scan <archive-or-url>` |
| `npx`/`bunx`/`pnpm dlx`/`yarn dlx`/`npm exec`/`uvx`/`uv tool run`/`pipx run` of a registry package | deny | `sigil npm <spec> && <original>` / `sigil pip <spec> && …` |
| `pipx install <pkg>`, `uv tool install <pkg>` | deny | `sigil pip <pkg> && <original>` |
| `deno run\|x\|install\|serve` of an `npm:` / `jsr:` / `https://` module | deny | `sigil npm <spec> && <original>` for `npm:`; otherwise download, scan, run the local file |
| `curl … \| sh`, `curl … \| bash -s stable`, `curl … \| tee f \| sh`, `curl … \| sudo -u root bash`, `bash <(curl …)`, `sh -c "$(curl …)"`, `iwr … \| iex` | deny | `sigil scan <url>`, or download → `sigil scan file` → run the file |
| Download to a file, then run that file in the same command: `curl -o i.sh … && bash i.sh`, `wget …/x.sh; sh x.sh`, `curl … > i.sh && ./i.sh`, `curl -O …/setup.py && python3 setup.py` | deny | `sigil scan <file> && <run>` after the download |
| `curl -o ~/.claude/skills/…`, `curl … > .mcp.json`, `wget -P …`, `unzip … -d ~/.claude/skills`, `tar -x … -C ~/.gemini/extensions`, `cp -r x ~/.codex/skills/`, `git clone <url> ~/.claude/skills/x`, `cp x .mcp.json` (also after `cd` into those directories) | deny | `sigil scan <src> && <original>` / `sigil clone <url> && <original>` |

Allowed look-alikes include `npx tsc` when the project has
`node_modules/.bin/tsc` (found up the tree, as npx does), `npx ./local.js`,
`npx --version`, `echo npx …`, `claude mcp list`, `claude plugin list`,
copying out of or between skill directories, `ls`/`cat`/`mkdir` on them, and
creating archives of them.

**Gating.** A command chained with `&&` after `sigil scan|clone|pip|npm` of
the *same* target is allowed — it only runs if the scan passed. "Same" means
the same kind of thing as well as the same name:

- an npm package (`npm install`, `npx`, `deno run npm:`) is vetted only by
  `sigil npm`, a PyPI package (`pip install`, `uvx`, `pipx`, `uv tool
  install`) only by `sigil pip`;
- a repository (`git clone`, `npx skills add o/r`, `gemini extensions
  install <url>`, `claude plugin marketplace add o/r`) by `sigil clone` or
  `sigil scan <url>`, compared as `host/owner/repo` (so
  `https://github.com/o/r.git`, `git@github.com:o/r` and `o/r` shorthand
  agree), with a `-b <branch>` part of the identity;
- a local path (`cp`, `unzip`, `tar -x`, a script an MCP server runs) by
  `sigil scan <path>`, compared after resolving `~` and the working
  directory (which follows `cd`).

So `sigil scan evil && npm install evil` (a directory named `evil` proves
nothing about the registry package), `sigil npm evil && pip install evil`,
`sigil skills scan && npx -y scan` and `sigil pip ruff -V 0.4.0 && pip
install ruff` are all denied. A different version is a different artifact
(`sigil npm express && npm install express@4` is denied). Crates, gems and Go
modules have no `sigil` subcommand that vets them by name, so they are never
gated. A download piped into an interpreter is **never** gated either: the
server can serve the scanner and the shell different bytes. A download saved
to a file *can* be: `curl -o i.sh URL && sigil scan i.sh && bash i.sh` is
allowed, because the scan reads the bytes that run.

**No laundering.** A sigil invocation allows only its own segment:
`sigil --version; npm install evil`, `sigil help | npm install evil` and
`sigil scan $(npm install evil)` are judged segment by segment and denied.

**Edits.** Registered for `Write|Edit|MultiEdit` as well, the hook judges
edits to agent tooling: content that pipes a download into a shell or ships
data off the machine is denied, edits to hooks or MCP server lists are asked,
ordinary files and ordinary skill edits are allowed.

`SIGIL_BYPASS=1` (environment or command prefix) and `SIGIL_GUARD_MODE`
(`enforce` / `advise` downgrades deny to ask / `off`) behave as before.

---

## 5. Measurements

```
Data Source: Real samples — 204 malicious skills (Datadog malicious-software-packages-dataset,
             ai-skills), 455 clean vendor skills (anthropics, NVIDIA, openai, vercel-labs).
Sample Size: as stated per row.
Limitations: Static reading only. "Clean" means published by a vendor catalogue, not audited.
             Single timing runs on a shared 4-CPU machine.
```

**Verdicts are unchanged.** `scripts/benchmark_skills.py --tools sigil` with the
lane binary: malicious blocked 142/204 (69.6%), warned 149/204 (73.0%); clean
blocked 108/455 (23.7%), warned 226/455 (49.7%); 0 errors. On the 615 samples
also in the baseline run (dc82a94) the level differs for **0**; the 44 openai
skills are new to this run (the baseline's discovery missed them) and account
for the change in the clean denominator (baseline: 94/411 blocked).

**The per-skill breakdown matches standalone scans.** One `sigil scan <root>`
per vendor corpus (4 scans) produced a `skills` entry for all 455 skills; the
level of every entry equals the level the benchmark recorded for a standalone
`sigil scan <skill>` of the same directory: **455/455**.

**Gate replay.** Every line in a shell (or untagged) fenced block of every
`.md` file in each skill was sent to `sigil hook pretooluse` as a Bash call,
with the old (dc82a94) and the new binary:

| Corpus | Lines | Before: deny / ask / allow | After: deny / ask / allow | Skills with ≥1 deny, before → after |
|---|---:|---|---|---|
| malicious (160 of 204 have shell blocks) | 9,460 | 84 / 132 / 9,244 | 234 / 28 / 9,198 | 56 → 65 |
| clean (344 of 455 have shell blocks) | 29,484 | 256 / 322 / 28,906 | 532 / 50 / 28,902 | 85 → 90 |

Most of the change is the policy change for remote runners (`npx`, `uvx`, …
moved from ask to deny with a `sigil npm|pip … &&` alternative: 103 malicious
and 276 clean lines). Lines that were **allowed before and are stopped now**:
47 in the malicious corpus (37 `clawhub install …`; 10 copies into
`~/.claude/agents`, `~/.claude/skills`, `~/.openclaw/skills` and
`~/.config/opencode/skills`) versus
5 in the clean corpus (3 remote `claude|codex mcp add --transport http` asks,
one `cp -R … .agents/skills/` deny, and one prose line containing
`` `pip install` `` that is now asked). One clean line moved the other way: an
`echo "… curl … | sh …"` message that is printed, not run.

The replay found two defects in the first version of the gate, both fixed
before this measurement: `curl … | python3 -m json.tool` was denied as
download-to-interpreter (7 clean lines), and `amp mcp add … -- npx …` /
`qodercli mcp add … -- npx …` slipped past the new command-position runner
check (3 malicious lines).

**Timing.** `sigil skills scan` on this machine (20 installed skills, 1 MCP
server): 2.08 s. A tree scan of the 382-skill NVIDIA corpus took 55.2 / 55.8 s
with the baseline binary and 45.4 / 44.0 s with the lane binary; the per-skill
breakdown adds a second directory walk, so the difference is machine load, not
a speed-up — read it as "no measurable overhead".

---

## 6. Adversarial review (verification pass)

An independent pass re-ran the measurements above and probed each part for
bypasses and false positives. Every number here comes from a command run in
that pass.

```
Data Source: Real samples — the same 204 malicious and 455 clean skills as §5
             (static reading only), plus synthetic fixtures for the probes.
Sample Size: as stated per row.
Limitations: The replays measure how often the gate steps in on skill
             instructions, not detection accuracy. "Clean" means published
             by a vendor, not audited.
```

**Reproduced.** The benchmark with the fixed binary gives the §5 numbers
again (malicious blocked 142/204, warned 149/204; clean blocked 108/455,
warned 226/455; 0 errors), with **0** level differences from the lane run
across all 659 samples. The per-skill breakdown agrees with standalone scans
for **455/455** skills. The line replay of the baseline binary (dc82a94)
matches the lane's recorded "before" run on all 38,944 lines.

**Found and fixed.**

| Part | Defect (all reproduced before fixing) | Fix |
|---|---|---|
| hook gating | Gates compared bare names, so a vetting call of one kind vetted another kind with the same name: `mkdir evil && sigil scan evil && npm install evil`, `sigil npm evil && pip install evil`, `sigil scan x && npx -y x`, `sigil skills scan && npx -y scan` were all **allowed**; `sigil pip ruff -V 0.4.0 && pip install ruff` dropped the version; `sigil clone URL -b dev && git clone URL` ignored the branch; a relative path stayed "vetted" after `cd`. | Typed targets (npm / PyPI / repository / path), branch and version part of the identity, paths resolved against the working directory. |
| hook, remote execution | Allowed: `curl … \| bash -s stable` (the rvm/nvm installer idiom), `curl … \| tee f \| sh`, `curl … \| sudo -u root bash`, `curl -o i.sh … && bash i.sh` and other download-then-run forms, `curl … > ~/.claude/skills/x/SKILL.md`, `pipx install x`, `uv tool install x`, `deno run npm:x` / `deno run https://…`. | All denied, with the gated alternative where one exists (`… && sigil scan i.sh && bash i.sh`). |
| `sigil scan <url>` | `https://github.com/vercel/next.js` (any repository whose name ends like a file) was downloaded as a single file — GitHub's HTML page — instead of cloned. | `<owner>/<repo>` on a forge, and a GitLab path without `/-/`, stay on the clone path. |
| `sigil skills` | AGENTCFG-006 fired Medium on `MEMORY_FILE_PATH`, `PYTHONPATH`, `GIT_AUTHOR_NAME`, `OAUTH_CALLBACK_URL`, `COMPAT_MODE` (substring `pat`/`auth`), turning a routine project `.mcp.json` MEDIUM RISK. | Key names judged by their last word(s). |
| `sigil skills` | `--format json` printed a bearer token written into a hook command in clear (the item's `detail`), and the token itself was never reported; an endpoint URL's password was shown. | Details redacted; a known-format token in a hook is AGENTCFG-005/007. |
| `sigil skills` | A malicious corpus skill's `.mcp.json` (an n8n webhook on `…18.191.220.185.sslip.io`) scanned LOW with no finding. | AGENTCFG-008 covers raw IPs behind wildcard DNS. |

**Cost of the hook fixes on real instructions.**

- Line replay (38,944 lines, one Bash call per line): **0** decisions
  change against the lane binary. None of the newly caught shapes occurs on
  a single line of either corpus.
- Block replay (new measurement: each fenced shell block sent as *one*
  command, as an agent runs a code block — 5,447 clean and 2,164 malicious
  blocks). Lane binary: clean 352 deny / 33 ask / 5,062 allow, malicious
  155 / 14 / 1,995. Fixed binary: clean 356 / 33 / 5,058, malicious
  155 / 14 / 1,995. The 4 clean blocks now denied all download code and run
  it in the same block (a Miniforge installer, two Holoscan example `.py`
  files, a MinIO binary) — the remote execution the gate exists to stop,
  on the vendor's say-so; clean skills with a denied block go from 90 to
  91. No malicious block changed: the fixes close bypasses that this
  corpus does not happen to use.

**Not changed, still open.** `SIGIL_BYPASS=1` written *inside* the command
still bypasses the whole command (existing semantics, kept on purpose), so
the gate stops an agent that follows a skill's instructions, not one that
is instructed to evade it. The hook is stateless: a download in one Bash
call and its execution in the next are not linked. The shell-guard fallback
in `plugins/claude-code/hooks/sigil-guard.sh` does not implement the new
denies; only the native `sigil hook` does.
