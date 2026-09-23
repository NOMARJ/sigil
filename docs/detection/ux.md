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
| A git URL (`https://github.com/o/r`, `git@…`, `….git`) | Cloned into quarantine and scanned (unchanged; same as `sigil clone`). |
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
| AGENTCFG-006 | Medium | A secret-named literal (`*_TOKEN`, `*_KEY`, `password`, …) in a project-scoped config | Probably a secret; placeholders (`${VAR}`, `<token>`, `your-…`) do not fire. |
| AGENTCFG-007 | Low | A credential in a **user-level** config | Routine — vendor docs tell you to put it there — but every skill and server running as you can read it. |
| AGENTCFG-008 | Medium | A remote MCP endpoint over plaintext `http` or a raw public IP | Anyone on the path can rewrite tool descriptions. |
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
| `curl … \| sh`, `bash <(curl …)`, `sh -c "$(curl …)"`, `iwr … \| iex` | deny | `sigil scan <url>`, or download → `sigil scan file` → run the file |
| `curl -o ~/.claude/skills/…`, `wget -P …`, `unzip … -d ~/.claude/skills`, `tar -x … -C ~/.gemini/extensions`, `cp -r x ~/.codex/skills/`, `git clone <url> ~/.claude/skills/x`, `cp x .mcp.json` (also after `cd` into those directories) | deny | `sigil scan <src> && <original>` / `sigil clone <url> && <original>` |

Allowed look-alikes include `npx tsc` when the project has
`node_modules/.bin/tsc` (found up the tree, as npx does), `npx ./local.js`,
`npx --version`, `echo npx …`, `claude mcp list`, `claude plugin list`,
copying out of or between skill directories, `ls`/`cat`/`mkdir` on them, and
creating archives of them.

**Gating.** A command chained with `&&` after `sigil scan|clone|pip|npm` of
the *same* target is allowed — it only runs if the scan passed. Targets are
compared after normalisation (`https://github.com/o/r.git` = `o/r`, `./dir/` =
`dir`); a different version is a different artifact (`sigil npm express &&
npm install express@4` is denied). A download piped into an interpreter is
**never** gated this way: the server can serve the scanner and the shell
different bytes.

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
