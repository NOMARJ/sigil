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
| `curl … \| sh`, `curl … \| bash -s stable`, `curl … \| tee f \| sh`, `curl … \| sudo -u root bash`, `curl … 2>&1 \| sh`, `curl … \|& sh`, `curl … \| bash >/dev/null`, `curl … \| "bash"`, `curl … \| env -i bash` (also `command`, `doas`, `busybox`, `$SHELL`), `curl … \| INSTALL_DIR=~/bin bash`, `` `curl … \| bash` ``, `bash <(curl …)`, `bash < <(curl …)`, `bash <<< "$(curl …)"`, `sh -c "$(curl …)"`, `iwr … \| iex`, and through any filter or group: `curl … \| tr -d '\r' \| bash`, `curl … \| base64 -d \| sh`, `curl … \| (bash)`, `{ curl …; } \| sh`, `curl … \| bash < /dev/stdin`, `curl … \| node -r x`, `curl … \| perl -I lib`; into a shell that `sudo -s`, `sudo -i`, `doas -s` or `su` starts; into code that reads it: `curl … \| bash -c "$(cat)"`, `curl … \| eval "$(cat)"`, `curl … \| sh -c 'source /dev/stdin'`, `curl … \| xargs -0 bash -c`, `curl … \| xargs -I{} sh -c '{}'`, `curl … \| python3 -c "import sys; exec(sys.stdin.read())"`; into a process substitution: `curl … \| tee >(bash)`, `curl … > >(bash)`; from or into a group or compound command: `{ curl …; echo; } \| sh`, `(curl …; true) \| bash`, `for …; do curl …; done \| sh`, `curl … \| { echo; bash; }`, `curl … \| if true; then bash; fi`, `curl … \| while read l; do eval "$l"; done`; and written to stdout by another name (`curl -o /dev/fd/1 … \| tr -d x \| bash`) | deny | `sigil scan <url>`, or download → `sigil scan file` → run the file |
| Download to a file, then run that file in the same command: `curl -o i.sh … && bash i.sh`, `wget …/x.sh; sh x.sh`, `curl … > i.sh && ./i.sh`, `curl -O …/setup.py && python3 setup.py`, and through wrappers, groups and redirections: `sudo -E bash i.sh`, `bash -e i.sh`, `python3 -X dev i.py`, `. ./i.sh`, `(bash i.sh)`, `bash < i.sh`, `cat i.sh \| sh`, `head i.sh \| sh`, after `curl -oi.sh …`, `curl … 1> i.sh`, `curl … \| tee i.sh` or `curl … \| dd of=i.sh`; through a substitution: `eval "$(cat i.sh)"`, `bash -c "$(cat i.sh)"`, `bash <(cat i.sh)`; through a copy: `mv i.tmp i.sh && bash i.sh`, `cp -t bin i.sh`, `cat i.sh > j.sh`, `dd if=i.sh of=j.sh`; behind more wrappers: `trap 'bash i.sh' EXIT`, `watch bash i.sh`, `flock l bash i.sh`, `flock l -c 'bash i.sh'`, `chroot / bash …`, `taskset`, `chrt`, `unshare`, `setpriv`, `strace`, `ltrace`, `script -c '…'`, `sg grp -c '…'`, `runuser -u root -- bash i.sh`; through xargs: `xargs -a i.sh -I{} sh -c '{}'`; and after the words of a substitution (`$(true) bash i.sh`) | deny | `sigil scan <file> && <run>` after the download |
| `curl -o ~/.claude/skills/…`, `curl … > .mcp.json`, `curl … \| tee ~/.claude/skills/…`, `wget -P …`, `unzip … -d ~/.claude/skills`, `tar -x … -C ~/.gemini/extensions`, `cp -r x ~/.codex/skills/`, `git clone <url> ~/.claude/skills/x`, `cp x .mcp.json` (also after `cd` into those directories, behind `sudo -E`/`env`/`command`, in a `( … )` subshell or a `bash -c '…'` string, and in any case: `~/.CLAUDE/skills` is `~/.claude/skills` on the default macOS and Windows file systems) | deny | `sigil scan <src> && <original>` / `sigil clone <url> && <original>` |

**How a command is read.** Each pipeline stage is read the way the shell
runs it (`cmdline::command_words`): grouping (`( … )`, `{ …; }`, `if`,
`then`, `do`), redirections (anywhere in the stage), leading `VAR=value`
words and wrapper commands (`sudo` with its options, `env -i`/`-u`/`-S`,
`command`, `builtin`, `exec`, `nohup`, `time`, `nice`, `timeout`, `stdbuf`,
`setsid`, `ionice`, `xargs`, `doas`, `busybox`, `flock`, `chroot`,
`taskset`, `chrt`, `unshare`, `setpriv`, `strace`, `ltrace`, `watch`,
`runuser`) are set aside before the command word is judged. `sudo -s`,
`sudo -i`, `doas -s`, `runuser <user>` and `su` with nothing to run start
a shell that reads its commands from stdin; the `-c` string of `flock`,
`script`, `sg` and `runuser`, and the string of `trap '…' EXIT`, are read
as a command line of their own. Behind `xargs`, inline code with no code
of its own (`xargs -0 bash -c`, `xargs -I{} sh -c '{}'`) runs the words
xargs reads, from stdin or from the file of `xargs -a f`. An interpreter's options are read per interpreter
family: `-e` is errexit to bash and inline code to node, `-X`/`-W` take a
value for python, `-I` for perl, `-o`/`-O` (also last in a bundle,
`-euo pipefail`) for shells, `-ExecutionPolicy` for PowerShell. Each stage is also judged with
the quoting inside its words removed (`"npm" exec x`, `de''no run npm:x`,
`pip''x install x`), the string of `bash -c '…'`, `su -c '…'` and
`eval '…'` is judged as a command line of its own (read whole, quotes and
all, so a separator inside it does not cut it short), a `cd` inside `( … )`
or a substitution (`$( … )`, `<( … )`, backticks) lasts until it closes,
and one in a list that `&` sends to the background (`cd /tmp & …`,
`cd /tmp && make &`) lasts until the `&`,
`cd -P dir`, `cd -- dir`, `cd -`, `pushd dir` and `popd` are followed, `~`,
`$HOME` and `$PWD` are expanded and a path that starts with another
variable (`$TMPDIR/i.sh`) is taken to be absolute under it, a `# comment`
is not read as part of what a stage runs, and a backslash at the end of a
line continues the command. A stdin redirection or here-document after the interpreter
(`curl … | python3 - <<'EOF'`) means the download is not what runs, unless
it reads the pipe itself (`< /dev/stdin`, `<&0`) or the pipe is copied to
another descriptor (`3<&0`). Whatever a stage reads from a download is
passed on: every later stage of the pipeline that runs its stdin
(`… | tr -d '\r' | bash`) runs the download, and a file written from it
(`cp`, `mv`, `ln`, `install`, `cat i.sh > j.sh`, `| tee j.sh`,
`dd if=i.sh of=j.sh`) is a download too. So is what a download writes to
stdout by another name (`-o /dev/fd/1`, `> /dev/stdout`). A group or
compound command that holds a download (`{ curl …; echo; } | sh`,
`for …; do curl …; done | sh`) pipes it, and every command inside one
that receives a download on stdin (`… | { echo; bash; }`, `… | while read
l; do eval "$l"; done`) reads it; so does the string of a `bash -c` whose
stage reads it (`… | sh -c 'source /dev/stdin'`), a substitution in such a
stage (`… | bash -c "$(cat)"`), and a `>( … )` a download is written to
(`… | tee >(bash)`). Code that runs what it reads counts as running its
stdin: a variable run as code (`eval "$l"`, `bash -c "$line"`) and
python, node, perl, ruby or php inline code that evaluates its stdin
(`exec(sys.stdin.read())`, `eval STDIN.read`). The words after the `)` of a
substitution are judged as a command of their own (`$(true) npm install
evil`).

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
allowed, because the scan reads the bytes that run — as long as the scan
runs after the last download to that path (`sigil scan i.sh && curl -o i.sh
URL && bash i.sh` is denied), the download is not still running in the
background (`curl -o i.sh URL & sigil scan i.sh && bash i.sh` is denied
until a `wait`), and nothing writes the file again after the scan: an
in-place edit (`sed -i`, `perl -pi`, `ruby -i`), an append or redirect
(`>> i.sh`, `tee -a i.sh`, `dd of=i.sh`) or a copy over it (`cp x i.sh`,
`mv x i.sh`, `ln -sf x i.sh`) cancels the scan. A copy of the scanned file made later in the
same `&&` chain (`cp`, `mv`, `ln`, `install`, `rsync`) holds the scanned
bytes and is vetted with it (`sigil scan t && install -m 755 t ~/bin/t &&
~/bin/t`). Only the `sigil` found on PATH vets: `./sigil`,
`vendor/bin/sigil` and `PATH=… sigil` (or `HOME=` and `XDG_…=`, which move
its state and trust ledger, any `SIGIL_…=` setting, or the dynamic
loader's `LD_…=`/`DYLD_…=`, which load code into sigil itself) do not, and neither
does any sigil call in a command that defines a `sigil` function or alias
(`alias -- sigil=true` included), loads a builtin named sigil, pins a path
with `hash -p`, changes PATH, HOME, a `SIGIL_…` setting or `LD_…`/`DYLD_…`,
names a Sigil policy file (`.sigil.yml`, `.sigil.yaml`, `sigil.yml`),
runs `sigil approve` (an approved artifact's content is allowlisted by
digest in later scans) or `sigil known-good` (an installed index is
recognised as published code), or writes into sigil's state directory
(`~/.sigil/`: cache, ledger, known-good indexes), nor one after a
sourced file (`. ./env; sigil …`). The scan's policy must not be the
command's own: `SIGIL_POLICY_FILE` names an organisation policy the scan
trusts whole, and a `.sigil.yml` in the working directory is trusted too,
so a command that sets or writes one could raise `fail_on` past every High
finding. The call must be a real scan: `-h`/`--help`, `--fail-on` or
`--severity` other than `low`/`medium`/`high`, `--phases` other than `all`,
`--config` and `--baseline` all let a hostile file pass, so such a call
vets nothing. Its options are read as sigil's argument parser reads them:
a short option's value attached (`-pnetwork`) or after `=`
(`-s=critical`), `-h` in a bundle (`-vh`), and a bundle that ends in a
valued option (`-vo i.sh x.sh` writes the report to `i.sh` and scans
`x.sh`). And its exit status must be what `&&` tests: a sigil call
that is not the last stage of its pipeline (`sigil scan i.sh | tee log &&
bash i.sh` tests tee), that sits inside a substitution (`echo $(sigil scan
i.sh) && …` tests echo), or that is only text inside quotes or a comment
vets nothing.

**No laundering.** A sigil invocation allows only its own segment:
`sigil --version; npm install evil`, `sigil help | npm install evil`,
`sigil npm evil | npm install evil`, `sigil scan $(npm install evil)` and
`$(sigil --version) npm install evil` are judged segment by segment and
denied (by the shell fallback too, when awk is available).

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
call and its execution in the next are not linked. At the time of this pass
the shell-guard fallback in `plugins/claude-code/hooks/sigil-guard.sh` did
not implement the new denies. It has since been brought in line (see the
plugin's CHANGELOG). Agent-CLI acquisition (`claude mcp add`, plugin and
extension installs, `npx skills add`, `clawhub install`) and copies or
unpacks into agent tooling are still enforced by the native `sigil hook`
only.

**Shell fallback, verification pass.** A later pass compared the fallback
with the native hook command by command.

```
Data Source: Synthetic probes, plus shell lines and fenced shell blocks from
             the §5 skill corpora (static text only, nothing executed).
Sample Size: 935 hand-written probes; 16,000 generated
             `curl … | <interpreter> <flags>` commands; 43,869 corpus lines
             and 7,649 corpus blocks.
Limitations: Measures agreement with the native hook, not detection
             accuracy. dash and mawk only; bash --posix was not run.
```

It fixed four ways the first version of the fallback allowed what the
native hook denies: a runner word anywhere in a stage exempted it from the
new checks (`curl … https://x.io/npx > ~/.claude/skills/x/SKILL.md`,
`pipx install evil npx`); the per-stage checks only ran when the literal
text `curl` or `wget` appeared (`cu''rl -o i.sh … && bash i.sh`); a `\037`
character in the command shifted the lexer's fields; and interpreter flags
the native hook tokenises (`| bash -o`, `| bash \-s`, `| pwsh -Sta`). It
also gave the fallback `npm exec`, `bun x` and `uv tool run`, which it had
never covered. After the fixes the generated commands agree with the
native hook 16,000/16,000 and the probes 927/935 (the rest: agent-CLI
acquisition, the legacy `npx` rule, and no-break spaces, which the native
tokenizer splits on and a shell does not); the corpus replay gives the same
decisions as before the fixes on all 51,518 commands.

The pass also found shapes **the native hook allowed**. The fallback
matched it, so they were open in both. They are closed now (§7):

- pipe to an interpreter: `curl … 2>&1 | sh`, `curl … |& sh`,
  `curl … | bash; …`, `curl … | bash >/dev/null`, `| "bash"`,
  `| env -i bash`, `| command bash`, `| doas bash`, `` `curl … | bash` ``,
  `bash < <(curl …)`;
- download then run: `bash -e i.sh` (`-e` is read as inline code),
  `sudo -u root bash i.sh`, `sudo -E bash i.sh`,
  `exec|command|nohup|time bash i.sh`, `. ./i.sh`, `(bash i.sh)`,
  `bash < i.sh`, `cat i.sh | sh`, `curl -oi.sh …`;
- the scan gate counts a scan that runs before the download
  (`sigil scan i.sh && curl -o i.sh … && bash i.sh`) or before a second
  download to the same path, and a shell function or `./sigil` named
  sigil satisfies it;
- downloads into agent tooling behind `sudo -E`, `env`, `command`, a
  subshell `( … )`, `bash -c '…'`, or `| tee ~/.claude/skills/…`;
- a false deny: a scan gate across a line continuation
  (`… && sigil scan i.sh && \` then `bash i.sh` on the next line), because
  a newline clears the gate.

---

## 7. Closing the shapes both gates missed

```
Data Source: Synthetic probes and generated commands written for the §6
             list, plus shell lines and fenced shell blocks from the §5 skill
             corpora (static text only, nothing executed).
Sample Size: 168 hand-written probes and 80 hand-written edge cases;
             12,444 generated download-to-interpreter commands; 22,246
             generated per-stage commands (download then run, tooling
             writes, gates, quoted command words); 43,869 corpus lines and
             7,649 corpus blocks.
Limitations: The probes and generated commands were written for these
             shapes, so they show the listed shapes are closed, not how many
             others remain. The corpus replay measures how often the gate's
             decision changes on real instructions, not detection accuracy.
             The fallback was run with dash and mawk only. Baseline: main at
             3982aa6, built in this pass.
```

**What changed.** The native hook reads each pipeline stage the way the
shell runs it (§4, "How a command is read"): grouping, redirections,
assignments and wrapper commands are set aside before the command word is
judged; an interpreter's options are read per interpreter; each stage is
also judged with the quoting inside its words removed; the string of
`bash -c '…'`, `su -c '…'` and `eval '…'` is judged as a command line of its
own; `|&` is a pipe and a backslash-newline continues the line. A download
saved to a file now invalidates an earlier scan of that path, and only the
bare `sigil` on PATH vets. The pipe check accepts wrappers before the
interpreter, `$SHELL`, redirections and `;`/`&`/`#` after it, and
`bash < <(curl …)` / `bash <<< "$(curl …)"`; a stdin redirection or
here-document after the interpreter means the download is not what runs.
Paths apply `..` as text (`cd sub; bash ../i.sh` runs the download), and
`wget -P dir -O f` saves to `f` (wget's `-O` ignores `-P`); both were read
wrongly before in both gates and were found by the edge cases below.
The shell fallback mirrors each change with the same deny reasons: the
pipe check stays a grep (it still works without awk), and the command-word
reading lives in its awk lexer. On this (shared, loaded) machine a
fallback call took 27–61 ms on six typical commands, against 15–47 ms
before (median of 15 runs each).

**Measured.**

| | main, native | main, fallback | now, native | now, fallback |
|---|---:|---:|---:|---:|
| Hand-written probes decided as expected (of 168) | 56 | 59 | 168 | 168 |

- Generated download-to-interpreter commands (interpreter × wrapper ×
  option, redirection, comment and stop words): the fallback agrees with the
  native hook on **12,444 of 12,444**, decision and reason. The first run
  of this grid found 96 disagreements, all one fallback defect (after a bare
  `2>`, it read the `&` of `2>&1` as the end of the stage), fixed before
  the measurement. With no awk on PATH (the per-stage checks off), the
  pipe check still agrees on every seventh of them (1,778 of 1,778).
  *§8: 1,666 of 1,778 now; the native hook denies 112 that the no-awk
  pipe check allows.*
- Generated per-stage commands: the decisions agree on **22,242 of
  22,246**. The 4 others are an older fallback shortcut, not part of this
  change: when a segment of a command starts with `sigil`, the fallback
  allows the whole command before its package-manager rules run, so
  `sigil pip x && 'npm' install x` is allowed there and denied natively
  (main's fallback also allows `sigil --version; npm install evil`). 867
  commands get the same decision with a different reason: 864 are allows
  worded "Command uses sigil" by the fallback and "No acquisition pattern
  matched" natively, the rest are the fallback's older generic `npx`
  reason and its "Command uses sigil" where the native hook says "Gated".
- `cargo test` covers each shape in both directions
  (`cli/src/hook_tests.rs`, `cli/src/cmdline_tests.rs`), and
  `plugins/claude-code/hooks/tests/test-guard.sh` does too, passing 256 of
  256 in both of its modes.

**Corpus replay, main against this change (native hook).** Every shell
line and every fenced shell block of the §5 corpora (43,869 lines, 7,649
blocks; cwd set to the Markdown file's directory). Three decisions change,
all on clean NVIDIA skills; no malicious-corpus decision changes:

| Command | main | now | Why |
|---|---|---|---|
| block: `curl … "https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/${RELAY_VERSION}/install.sh" --output nemo-relay-install.sh`, `less nemo-relay-install.sh`, `… sh nemo-relay-install.sh` | allow | deny | A download and its execution; the curl command spans three lines joined by `\`, which the old gate read as three commands. The reason names `sigil scan <file> && <run>`. |
| line: `\|\| curl -LsSf https://astral.sh/uv/install.sh \| sh; then` | allow | deny | `curl … \| sh` followed by `;`. |
| block: `"$VENV/bin/python" -m pip install \` / `-r "$REQUIREMENTS" \` / `"transformers==4.46.3" "typer>=0.9"` | deny | ask | Read as one command now, it carries `-r`, and the existing rule asks for `pip install -r` before looking for named packages. *§8: a package named besides `-r` is now denied, so this block is denied again.* |

Clean skills with a denied block go from 91 to 90 of 344 (the third row's
skill had no other deny); with a denied line, 90 in both; malicious skills,
65 of 160 in both. Eleven more commands keep their decision with a new
reason, all because a continued line is now quoted whole.

**Fallback against native on the corpus.** Both gates were run on all
51,518 corpus commands, before and after. After, they disagree on the
decision for 104 commands (57 distinct texts); before, main's pair
disagreed on 105 (58). No disagreement is new: the one that went is the
third row above, which both gates now ask about. The 104 are the
fallback's older limits, unchanged by this pass: agent-CLI acquisition
(`clawhub install` 53, `… mcp add` 8) and copies into agent tooling (23),
which only the native hook handles; the `pip install -r` precedence applied
to the whole command (6); `pip install` inside backticks, which its word
boundary does not cover (3); `npm install` asked about before `npx` is
denied (3); and its legacy `npx` rule, which also matches `# npx …`,
`$ npx …` and `~/.npm/_npx` (8). 784 commands get the same decision with a
different reason, the same 784 before and after.

**Left open by this pass.** Found in it (80 hand-written edge cases, on
which the two gates agree) and not changed here. The verification pass
(§8) closed the first, second, third and fifth, and showed that the fourth
was an allow as well as a deny:

- A downloaded file run through a substitution: `eval "$(cat i.sh)"`,
  `bash -c "$(cat i.sh)"`. *Closed in §8.*
- The pipe check reads the options of non-shell interpreters with one
  shared list, so an option that takes a value is read as a script name:
  `curl … | node --require x` is allowed (the download-then-run check reads
  them per interpreter). *Closed in §8.*
- The `pip install -r` precedence in the third row: `pip install -r req.txt
  evil-pkg` asks instead of denying, in both gates. *Closed in §8 (in the
  fallback, where awk is available).*
- Segmentation ignores quotes, so a separator inside a quoted string splits
  the command: `bash -c 'cd build && curl -o i.sh …' && bash i.sh` is
  judged as if the download landed in the working directory (a deny, as in
  main). *§8: the same cut let `… && bash build/i.sh` through; the string
  is now also read whole, which denies that; the deny of `bash i.sh`
  stays.*
- The fallback shortcut above (a segment starting with `sigil` allows the
  whole command), in the fallback only. *Closed in §8 where awk is
  available.*
- As before: the gate is stateless across Bash calls, `SIGIL_BYPASS=1`
  inside the command bypasses it, and the fallback does not implement
  agent-CLI acquisition or copies and unpacks into agent tooling. *Still
  open.*

---

## 8. Verification pass: what still got through

Two passes verified §7 by trying to get past it. The first was stopped by a
container restart before its gates and measurements ran; the second resumed
it, re-ran every measurement of §7 and of the first pass, reviewed the
first pass's changes as critically as the rest, and probed further. Every
number below comes from a run made in the resumed pass. "Main" is 3982aa6
and "the change" is §7 as first written, both built from source in this
pass.

```
Data Source: Synthetic probes (hand-written, deterministic), real scans of
             one hand-written fixture, and the shell lines and fenced shell
             blocks of the §5 skill corpora (static text, nothing executed).
Sample Size: 462 probes written by the first pass; 255 + 57 (pip) + 22
             (inline code) probes written by the resumed pass; 168 probes
             and 80 edge cases of §7; 12,444 + 22,246 generated commands;
             43,869 corpus lines and 7,649 corpus blocks.
Limitations: The probes were written to get past the gate, so they show
             which shapes are closed, not how many others remain. The corpus
             replay measures how often the gate's decision changes on real
             instructions, not detection accuracy. The fallback was run with
             dash and mawk, and with bash as sh; not with busybox. Timings
             are single runs (the fallback's per-command times: medians of
             15) on a shared, loaded 4-CPU machine.
```

**Reproduced.** The §7 numbers hold: on its 168 probes main decides 56
(native) and 59 (fallback) as expected and the change 168 and 168; the
corpus replay of main against the change gives the same three decision
changes and eleven reason-only changes as §7, with the same totals.

**The first pass** wrote 462 probes (its expectations, with nine labels
corrected where the allow is right: the scan and the run name the same
file, an output option, an option sigil rejects, `./sigil` not on PATH, a
download into another directory). Main decides 199 of them as expected
natively and 198 in the fallback; the change 316 and 307, and gets 155 of
them wrong in one gate or both. The first pass's fixes bring both gates to
432. Among what it closed: `curl … | bash < /dev/stdin` (let through by
the change's own here-document exemption), filters and groups between the
download and the shell (`| tr -d '\r' | bash`, `{ curl …; } | sh`),
options that take a value (`| perl -I lib`, `| node -r x`), `eval "$(cat
i.sh)"`, copies (`mv i.tmp i.sh && bash i.sh`), a scan that vets nothing
(`--fail-on critical`, `sigil scan i.sh | tee log`, a policy the command
sets), and a `cd` inside `$( … )`.

**Found in the resumed pass and fixed, in both gates** (each reproduced
before the fix; the scan-gate ones with real scans, below):

| Part | Allowed before | Now |
|---|---|---|
| pipe | a shell that `sudo -s`, `sudo -i`, `doas -s`, `su` or `runuser <user>` starts: `curl … \| sudo -s` | it reads the pipe: denied |
| pipe | code that reads the pipe: `\| bash -c "$(cat)"`, `\| eval "$(cat)"`, `\| sh -c 'source /dev/stdin'`, `\| xargs -0 bash -c`, `\| xargs -I{} sh -c '{}'`, `\| python3 -c "import sys; exec(sys.stdin.read())"`, `\| ruby -e 'eval STDIN.read'` | denied: inline Python, Node, Perl, Ruby or PHP code counts when it reads stdin and calls `exec`, `eval`, `Function` or `instance_eval`; compiling a regex or matching a JavaScript regex literal does not |
| pipe | a process substitution: `\| tee >(bash)`, `> >(bash)` | denied |
| pipe | a group or compound command that holds the download (`{ curl …; echo; } \| sh`, `(curl …; true) \| bash`, `for …; do curl …; done \| bash`) or receives it (`\| { echo; bash; }`, `\| if true; then bash; fi`, `\| while read l; do eval "$l"; done`, `\| while read l; do $l; done`) | denied |
| pipe | stdout by another name: `curl -o /dev/fd/1 … \| tr -d x \| bash`, `> /dev/stdout` | denied |
| laundering | `$(sigil --version) npm install evil`, `$(true) npm install evil`, `$(true) bash i.sh` after a download (the words after a substitution were not judged) | denied |
| download, then run | behind `trap '…' EXIT`, `watch`, `flock` (and `flock -c`), `chroot`, `taskset`, `chrt`, `unshare`, `setpriv`, `strace`, `ltrace`, `script -c`, `sg -c`, `runuser`; through `xargs -a i.sh -I{} sh -c '{}'` | denied unless scanned |
| scan gate | options read as sigil reads them: `-pnetwork`, `-p=network`, `-scritical`, `-s=critical`, `-vh`, `-hv`, `-vo i.sh x.sh` all vetted a scan that lets a hostile file pass | such a call vets nothing |
| scan gate | state that makes a later scan pass: `LD_PRELOAD=…`/`DYLD_…=` for sigil or exported, `sigil approve` (an approved artifact's content is allowlisted by digest), `sigil known-good` (an installed index), a write into `~/.sigil/` | no sigil call in the command vets |
| scan gate | the scanned file written again after the scan: `sed -i`, `perl -pi`, `>> i.sh`, `tee -a`, `dd of=`, `cp`/`mv`/`ln -sf` over it | the write cancels the scan |
| scan gate | a download still running in the background: `curl -o i.sh … & sigil scan i.sh && bash i.sh` (the scan can read the file before it is complete) | not vetted until a `wait` |
| package install | a package named besides a requirements file: `pip install -r req.txt evil-pkg`, `uv pip install -r req.txt evil-pkg`, `pip install -r req.txt -- evil-pkg`, `pip install -r req.txt -e git+https://…` were asked about as a requirements install (§7 left it open; its continued-line reading turned one clean-skill deny into such an ask) | denied as `pip install <pkg>`; the values of options that take one (`-r f`, `-c f`, `-e .`, `-i <url>`, `--target d`) are not packages, unless `-e` names a repository, so `pip install -r req.txt -e .` is still an ask |
| native hook, speed | each pattern was compiled for every stage it was checked on: a 13.6 KB command of 800 substitutions took 14.0 s with main and 14.4 s with the first pass's build, 11.5 s for 2,000 pipe stages (which main allowed: `curl … \| cat \| … \| bash`). A host that treats a hook past its time limit as an allow would let such a padded command through | patterns compiled once: 0.08 s and 0.07 s (denied); 0.76 s and 0.63 s for commands ten times that size |

The scan-gate options were checked with real scans of a hand-written
fixture (`exec(base64.b64decode("cHJpbnQoMSk="))`, which decodes to
`print(1)` and draws a High finding) in a fresh HOME: a plain scan exits
1; `--fail-on critical`, `-pnetwork`, `-s=critical`, `-vh`, a
`.sigil.yml` with `fail_on: critical` in the working directory and
`SIGIL_POLICY_FILE` naming such a file each exit 0. Under an organisation
policy that locks every key (`locked: [all]`, `allow_project_policy:
false`) the scan exits 1 with the `.sigil.yml` and with `--fail-on
critical` too. `LD_PRELOAD`, `sigil approve` and `sigil known-good` are
from reading the code (`ledger::apply_suppression` allowlists approved
content by digest; `known-good` indexes are recognised as published
code), not from a run.

A draft of this pass's own fix for substitutions judged only the text
before the `)`, which let `$(true) npm install evil` through natively; a
probe caught it before the fix was committed, and the words after the `)`
are now judged as a stage of their own. Likewise a draft of the `pip -r`
fix read a comment as packages: the corpus replay turned `pip install -r
requirements.txt  # other dependencies` (a clean NVIDIA skill) from an ask
into a deny natively. A comment now ends the words read, and the line is an
ask again; the fallback's lexer already dropped comments. And this pass's
own read-code markers, as first committed, counted `compile` and any
`exec` call: 18 probes of legitimate pipes into inline code found two
ordinary parsers of a downloaded page denied in both gates (a Python regex
compiled and matched against `sys.stdin`, a Node regex literal's `exec`
on `process.stdin`). Neither counts now; `builtins.exec(…)` and
`require('child_process').exec(d)` still do.

**Measured.**

| | main | the change | first pass | now |
|---|---|---|---|---|
| First pass's 462 probes, native / fallback | 199 / 198 | 316 / 307 | 432 / 432 | 443 / 443 |
| Resumed pass's 255 probes, native / fallback | 151 / 135 | 167 / 151 | 180 / 177 | 253 / 250 |
| §7's 168 probes, native / fallback | 56 / 59 | 168 / 168 | 168 / 168 | 168 / 168 |
| Resumed pass's 57 `pip` probes, native / fallback | 34 / 32 | 34 / 32 | 34 / 32 | 56 / 56 |
| Resumed pass's 22 pipes into inline code (19 that parse the download, 3 that run it), native / fallback | 19 / 19 | 19 / 19 | 19 / 19 | 22 / 22 |

The five of the 255 still decided otherwise than expected now: three in
the fallback only (a download copied or installed into agent tooling,
which only the native hook judges), and two in both gates (`find . -name
i.sh -exec bash {} \;`, and a policy file whose name the command computes:
`f=.sigi; echo 'fail_on: critical' > ${f}l.yml`). The one of the 57 is
the same in every build, main included: `echo pip install -r
requirements.txt evil-pkg` is asked about (expected: allowed), because the
`pip` rule looks for `pip install` anywhere in the stage. Without `awk`
the fallback decides 32 of the 57 as expected, as main's does: the `pip
-r` fix reads the lexer's words.

`cargo test` covers each shape in both directions
(`cli/src/hook_tests.rs`, `cli/src/cmdline_tests.rs`), and
`plugins/claude-code/hooks/tests/test-guard.sh` passes 417 of 417 with the
fallback, with the native hook, without `jq`, and with bash as `sh`.

**Corpus replay, main against now (native hook).** The §7 corpora again
(43,869 lines, 7,649 blocks). Four decisions change, all to deny and all on
clean NVIDIA skills: the two download-and-run commands of §7, a download
piped across a line continuation into `HELM_INSTALL_DIR=~/.local/bin
USE_SUDO=false bash` (allowed by main and by §7), and `pip install -r
requirements.txt pytest -q` (a package named beside `-r`). The block in
§7's third row is denied again, as in main. 55 commands keep their
decision with a new reason: §7's eleven, and 44 `git clone` denies whose
suggested `sigil clone` now names the repository rather than an option's
value (`--depth 1` gave `sigil clone 1`). Totals, allow / ask / deny:

| | main | §7 | now |
|---|---|---|---|
| Clean blocks | 5,059 / 34 / 376 | 5,058 / 35 / 376 | 5,057 / 34 / 378 |
| Clean lines | 31,906 / 51 / 557 | 31,905 / 51 / 558 | 31,905 / 50 / 559 |
| Malicious blocks | 2,006 / 16 / 158 | 2,006 / 16 / 158 | 2,006 / 16 / 158 |
| Malicious lines | 11,089 / 30 / 236 | 11,089 / 30 / 236 | 11,089 / 30 / 236 |

Clean skills with a denied block: 91 of 344 in main, 90 with §7, 92 now
(main's 91 and the Helm skill); with a denied line, 90 in all three;
malicious skills, 65 of 160 either way. Every new deny was read: each runs
or installs code that no scan has vetted, but they are real instructions
from clean skills, so a user following them now has to scan first or
bypass. A draft of the `pip` fix also denied `pip install -r
requirements.txt  # other dependencies` (above); that is an ask again.

**Fallback against native, now.** Generated download-to-interpreter
commands: 12,444 of 12,444, decision and reason. Generated per-stage
commands: all 22,246 on the decision; 3 differ in reason only (the
fallback's older generic runner reason for `n\px -y x`). §7's 80 edge
cases: 80 of 80. The 51,518 corpus commands: 98 decision differences (51
distinct texts), down from 105 (58) for main's pair and 104 (57) for §7's,
both reproduced in this pass: the 7 that went are the `pip install -r`
precedence, which both gates now apply per stage. The 98 are the fallback's older limits:
agent-CLI acquisition (61) and copies into agent tooling (23), which only
the native hook judges; its legacy `npx` rule, which also matches `# npx
…`, `$ npx …` and `~/.npm/_npx` (8); `pip install` inside backticks (3);
and `npm install` asked about before `npx` is denied (3). 787 commands
get the same decision with a different reason (main's pair: 784): four
more `git clone <url> -b <ref>` commands, for which the native hook's
suggestion now names the branch and the fallback's does not, and one fewer
(a `git clone --depth=1 … \` line, for which main's native hook suggested
an empty `sigil clone`).
Without `awk`, see the list below.

**`sigil scan` is unchanged.** Only the hook (`hook.rs`, `cmdline.rs`)
and the fallback changed. Scanning the 18 smallest directories of three
real corpora (6 clean MCP servers, 6 clean vendor skills, 6 malicious
skills) with main's binary and this pass's gives the same verdict, score
and findings for all 18.

**Speed.** The native hook on the same large synthetic commands: main
14.0 s (800 substitutions), 11.5 s (2,000 pipe stages), 5.4 s (300
here-documents), 2.4 s (400 `&&` downloads); now 0.08 s, 0.07 s, 0.07 s,
0.10 s. The fallback got slower: the median of 15 runs per command, main /
§7 / now, is 33 / 31 / 33 ms for `ls -la`, 22 / 26 / 26 ms for `npm
install express`, 14 / 25 / 44 ms for `curl … | sh`, 21 / 38 / 83 ms for a
download scanned and run, and 46 / 58 / 81 ms for `cd`, a download, `tar`
and a run; on a 162 KB command of 400 `&&` downloads it takes 5.1 s (the
native hook 1.0 s).

**Still open.**

- Names the gate cannot resolve: globs and brace expansion (`bash
  dl/i*.sh`, `bash dl/{i,}.sh`), variables and loops (`f=i.sh; bash
  $f`, `for f in i.sh; do bash $f; done`, `x=$(cat i.sh); eval "$x"`,
  `bash "$(pwd)/i.sh"`), `find … -exec bash {} \;`, a file name the server
  chooses (`curl -J -O`, `wget --content-disposition`), options read from a
  file (`curl -K cfg`), files unpacked from a downloaded archive (`tar xzf
  x.tgz && bash install.sh`), and a policy file whose name is computed.
- Interpreters outside the list (`elvish`, `nu`, `osascript`, `lua`),
  inline code that evaluates its stdin in a way the markers do not name,
  and `xargs npx` (a runner fed its package on stdin).
- `npm create`, `npm init <pkg>`, `go run <module>@<version>` and `uv run
  --with <pkg>` fetch and run a package; none is in the runner list.
- As in §7: the gate is stateless across Bash calls (a policy file, an
  approval or a download from an earlier call is not seen; see
  [enterprise.md](../enterprise.md) for the locked policy that closes the
  policy part; nor is a `sigil` shell function the Bash tool's shell gets
  from a profile an earlier call wrote, and `export -f sigil` in the
  command is not read as a sign of one); `SIGIL_BYPASS=1` inside the
  command bypasses it; and the fallback does not judge agent-CLI
  acquisition or copies and unpacks into agent tooling, and without `awk`
  runs only its pipe check and older rules (1,666 of 1,778 generated
  download-to-interpreter commands decided as natively; the rest are
  native denies it allows, such as `curl … | python3 -x -E`).
- The `pip` rule looks for `pip install` anywhere in a stage, so `echo pip
  install -r req.txt evil` is asked about (as in main).
- Of the first pass's 462 probes, the 19 still allowed in both gates are
  shapes of the first two items above, plus `export -f sigil`.
