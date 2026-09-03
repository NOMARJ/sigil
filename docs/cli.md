# CLI Command Reference

Complete reference for every `sigil` command, flag, and exit code.

---

## Global Behavior

- Sigil runs entirely offline by default. All eight scan phases execute locally with no network calls.
- When authenticated (`sigil login`), scans are enriched with cloud threat intelligence.
- All scanned code is quarantined under `~/.sigil/quarantine/` — nothing executes until explicitly approved.
- Exit codes reflect the scan verdict severity (see [Exit Codes](#exit-codes) below).

---

## Setup Commands

### sigil install

Copies the running `sigil` binary to an install directory (default `/usr/local/bin`, may require sudo).

```bash
sigil install [--path <dir>]
```

For shell aliases, Claude Code wiring, and git hooks, use `sigil setup`.

---

### sigil setup

Wire Sigil into AI agent and developer workflows. Every step is best-effort and idempotent — re-running never duplicates configuration.

```bash
sigil setup claude   # Register the Claude Code plugin marketplace + install sigil-security
sigil setup shell    # Append gclone/safepip/safenpm aliases to your .bashrc/.zshrc
sigil setup git      # Install a pre-commit hook running `sigil scan . --fail-on high`
sigil setup all      # claude + shell, plus git when run inside a repository
```

`setup claude` requires the `claude` CLI on PATH and skips with a pointer when it is absent. `setup git` refuses to overwrite a pre-commit hook it didn't write.

---

### sigil hook

Respond to a Claude Code hook event. Reads the hook JSON payload from stdin and prints a `permissionDecision` response. This is the native implementation behind the plugin's PreToolUse enforcement gate — the plugin's `sigil-guard.sh` delegates here when the CLI is on PATH.

```bash
sigil hook pretooluse    # currently the only supported event
```

Honors `SIGIL_GUARD_MODE` (`enforce`/`advise`/`off`) and `SIGIL_BYPASS=1`. Always exits 0; unsupported events produce no output so they never block a tool call.

---

### sigil config

Show current configuration or initialize the directory structure.

```bash
sigil config             # Show current config and scanner status
sigil config --init      # Create ~/.sigil directories
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--init` | Create all required directories under `~/.sigil/` |

**Output includes:**

- Quarantine, approved, logs, and reports directory paths
- API URL
- Authentication status
- Installed external scanners (semgrep, bandit, trufflehog, safety)

---


## Audit Commands

### sigil clone

Clone a git repository into quarantine and run a full security scan.

```bash
sigil clone <git-url>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `git-url` | Yes | Repository URL (https, git@, or ssh://) |

**Behavior:**

1. Validates the URL format (http(s), git@, ssh://)
2. Shallow clones (`--depth 1`) into `~/.sigil/quarantine/<id>/`
3. Runs all 8 scan phases + external scanners + dependency analysis
4. If authenticated, queries cloud threat intelligence
5. Generates verdict and saves report to `~/.sigil/reports/`

**Example:**

```bash
sigil clone https://github.com/someone/mcp-server
sigil clone git@github.com:org/agent-toolkit.git
```

---

### sigil pip

Download a pip package without installing it, extract into quarantine, and scan.

```bash
sigil pip <package-name>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `package-name` | Yes | PyPI package name (e.g., `requests`, `langchain`) |

**Behavior:**

1. Validates package name format (alphanumeric, hyphens, underscores, dots, scoped)
2. Downloads the package via `pip download --no-deps`
3. Extracts the wheel or tarball into quarantine
4. Runs full scan
5. If the package is approved, prompts to install with `pip install`

**Example:**

```bash
sigil pip requests
sigil pip some-agent-toolkit
```

---

### sigil npm

Download an npm package, extract into quarantine, and scan.

```bash
sigil npm <package-name>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `package-name` | Yes | npm package name (e.g., `leftpad`, `@scope/pkg`) |

**Behavior:**

1. Validates package name format (supports scoped packages like `@scope/name`)
2. Downloads via `npm pack` (creates a `.tgz` archive)
3. Extracts into quarantine
4. Runs full scan
5. If approved, prompts to install with `npm install`

**Example:**

```bash
sigil npm leftpad
sigil npm @langchain/community
```

---

### sigil scan

Scan a file, a directory, or a git URL for security issues.

```bash
sigil scan <path-or-url> [--format text|json|sarif|html] [--fail-on <severity>] [--phases <list>] [--severity <min>]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `path` | Yes | File or directory to scan. A git URL (`https://…`, `git@…`, anything ending in `.git`) is cloned into quarantine first, exactly like `sigil clone` |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | `text`, `json` (the stable contract, [ADR-0010](adr/ADR-0010-output-contract-sarif-exit-codes.md)), `sarif` (2.1.0), or `html` (one self-contained page, no scripts, safe to attach to a ticket) |
| `--fail-on` | `high` | Exit 1 when a finding at or above this severity is present |
| `--phases` | `all` | Comma-separated phase filter |
| `--severity` | `low` | Minimum severity to report |
| `--no-cache` | | Force a fresh scan even if the content is unchanged |
| `--no-ledger` | | Report findings even when the content matches a trust-ledger approval |

**Behavior:**

1. Walks the tree honouring `.gitignore` (inside real git repositories only, so an
   archive cannot hide files from the scanner) and `.sigilignore`. `node_modules/`,
   `.git/`, `target/`, `.next/`, virtualenvs and caches are never content-scanned.
   `dist/` and `build/` **are** scanned: in a published package they are the shipped
   code, and in a git checkout the project's own `.gitignore` already keeps build
   output out of the walk.
   Files over 10 MB are not read whole, but they are not skipped either: the first
   and last 2 MB are scanned (padding a script past a size cap is a known evasion)
   and findings in the tail carry their real line numbers, prefixed
   `[tail of oversized file]`.
2. Runs the eight phases, the decode worklist (decoded payloads reach every phase),
   the correlation rules, the typosquat check on direct dependencies, and the
   publish-hygiene checks.
3. Prints a verdict, a letter grade, a behaviour profile and the key risks. The grade
   is a label over the verdict, not a second score: **A** no findings, **B**
   low-severity only, **C** MEDIUM RISK, **D** HIGH RISK, **F** CRITICAL RISK.
4. Labels what it scanned (`summary.platform` in JSON, `Platform:` in text): `npm`,
   `pypi`, `agent-skill`, `mcp-server`, `claude-plugin`, `vscode-extension`,
   `agent-instructions`, `cargo`, `go`, `maven`, `rubygems` or `generic`, judged from
   the shallowest manifest in the tree. A monorepo reports its root manifest.
5. When a lifecycle script (`postinstall`, `prepare`, …) or `setup.py` runs a local
   file that has findings, the manifest gets one extra finding, `INSTALL-REF-001`,
   one level above the worst finding in that file. The file's own findings are left
   as they are.

**Example:**

```bash
sigil scan .                                    # Scan current directory
sigil scan ./vendor/                            # Scan vendor directory
sigil scan https://github.com/someone/mcp-tool  # Clone into quarantine, then scan
sigil scan ./skill --format html > report.html  # Shareable report
sigil scan ./pkg --format json | jq .summary    # verdict, score, grade, platform
sigil scan ./pkg --format sarif > sigil.sarif   # GitHub Code Scanning upload
```

---

### sigil fetch

Download a file or archive from a URL, extract if applicable, quarantine, and scan.

```bash
sigil fetch <url>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | URL to download from |

**Behavior:**

1. Downloads the file to quarantine
2. Detects archive type (`.tar.gz`, `.tgz`, `.zip`, `.tar.bz2`)
3. Extracts archives automatically
4. Runs full scan on extracted contents

**Example:**

```bash
sigil fetch https://example.com/agent-tool.tar.gz
sigil fetch https://github.com/user/repo/archive/main.zip
```

---

## Quarantine Management

### sigil list

Show all quarantined and approved items with their status, size, and verdict.

```bash
sigil list
```

**Output includes:**

- Quarantine ID
- Source (URL, package name, or path)
- Size on disk
- Scan verdict (if scanned)
- Date quarantined

---

### sigil approve

Mark a quarantined item as trusted after review.

```bash
sigil approve <quarantine-id> [--reason "why"]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `quarantine-id` | Yes | ID shown in `sigil list` output |
| `--reason` | No | Reason for approval, recorded in the trust ledger |

**Behavior:**

Marks the entry as approved and pins its content digest in the trust ledger, so
digest-matching content is allowlisted on future scans. The files themselves stay
at `~/.sigil/quarantine/<id>/` — copy them into your project yourself once approved.

---

### sigil reject

Permanently delete a quarantined item.

```bash
sigil reject <quarantine-id>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `quarantine-id` | Yes | ID shown in `sigil list` output |

**Security:**

Same path traversal protections as `sigil approve`.

**Behavior:**

Permanently removes the item from `~/.sigil/quarantine/<id>/`. This cannot be undone.

---

## Host Residue

`sigil scan` judges code *before* it runs. `sigil residue` looks at this machine
*after* something ran: the crontab entry an uninstalled skill left behind, the line a
setup script appended to `~/.zshrc`, the git hook that still fires on every commit, the
credential file an agent wrote world-readable, the cache directory of a tool that is no
longer installed, the `/etc/hosts` line that redirects an API host.

### sigil residue scan

```bash
sigil residue scan [--repo <path>] [--fail-on info|low|medium|high|critical]
sigil --format json residue scan
```

Read-only. Nine checks: shell startup files (`RES-SHELL-*`), persistence entries
(`RES-PERSIST-*`: crontab and `/etc/cron*`, launchd on macOS, systemd on Linux, autostart
entries, `sudoers.d`), git hooks in the repo, the hook templates and `core.hooksPath`
(`RES-HOOK-*`), credential file permissions (`RES-CRED-*`), leftover tool directories
(`RES-DIR-*`), `/etc/hosts` redirects of watched API hosts (`RES-NET-*`) and global agent
packages (`RES-PKG-*`). Commands found in persistence entries and hooks are judged by
shape (pipe-to-shell, base64 decode, remote `eval`, inline Python, reverse shell, a
binary in a temporary or cache path, a binary that no longer exists) and by the
detection corpus, not by keyword lists. Sigil's own footprint (the alias block written by
`sigil setup shell`, its pre-commit hook) is reported as inventory, or as tampering when
it no longer matches what Sigil writes.

Items you accept go in `~/.sigil/residue-allow`, one `RULE-ID path` per line; they are
still reported, under `items_suppressed`.

Exit codes follow the scan convention: `0` nothing at or above `--fail-on`, `1`
something is, `2` the scan could not run. The JSON document is a different kind from a
scan result (`"kind": "residue"`, `"residue_schema": 1`) and `sigil diff` refuses it as a
baseline. Secrets in evidence lines are redacted before they are printed.

### sigil residue plan

```bash
sigil residue plan [--repo <path>] [--out plan.json]
```

Shows the reversible fixes a scan would make, without making them: remove a line,
tighten a file mode, delete a file or directory, remove a crontab line. Only fixable
items at Medium or above are planned, and only targets under your home directory or the
repository; system files (`/etc/hosts`, `/etc/cron.d`, `sudoers.d`) are reported, never
touched.

### sigil residue apply

```bash
sigil residue apply [--repo <path>] [--plan plan.json] [--yes]
```

Runs the plan, asking `y/N/q` per action on a terminal (`--yes` is required when stdin
is not one). Every target is copied to `~/.sigil/backups/<id>/` with a manifest before it
is changed, and each action is checked against the file as it is now, so a file that
changed since the plan was made is skipped rather than edited blindly. Symlinks, paths
outside your home or the repository, and anything under `~/.sigil` are refused.

### sigil residue rollback

```bash
sigil residue rollback <id> | --last | --list [--force]
```

Restores a backup. A target that changed after `apply` is skipped unless `--force`.

---

## Account Commands

### sigil login

Authenticate with the Sigil cloud API to enable threat intelligence, scan history, and team features.

```bash
sigil login                       # browser-based device authorization flow
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-t, --token <token>` | API token; if omitted, a browser-based device authorization flow runs. Note: there is currently no way to generate an API token from the dashboard, so use the device flow |
| `--endpoint <url>` | API endpoint URL (default: `https://api.sigilsec.ai`) |

**Behavior:**

1. Authenticates against the Sigil API (device flow, or validates the provided token)
2. Stores the token to `~/.sigil/token`
3. Subsequent scans include threat intelligence enrichment

**What authentication enables:**

- Threat intelligence lookups (known malicious hash database)
- Publisher reputation scores
- Community threat signatures (delta sync)
- Scan history in the web dashboard
- Team policies and alerts

---

### Logging out

There is no `logout` subcommand. To clear stored credentials, delete the token file:

```bash
rm ~/.sigil/token
```

Scans return to offline-only mode.

---

## Scan Phases

Every audit command runs these eight phases. Each phase has a severity weight that multiplies the number of findings.

| Phase | Name | Weight | What It Detects |
|-------|------|--------|-----------------|
| 1 | Install Hooks | 10× | `setup.py` cmdclass, npm `postinstall`/`preinstall`, Makefile install targets |
| 2 | Code Patterns | 5× | `eval()`, `exec()`, `pickle.loads`, `child_process`, dynamic imports, `subprocess` with `shell=True` |
| 3 | Network / Exfil | 3× | `requests.post`, `fetch()`, `axios`, WebSockets, ngrok, Discord/Telegram webhooks |
| 4 | Credentials | 2× | `os.environ`, `.aws/credentials`, SSH keys, API key patterns, `DATABASE_URL` |
| 5 | Obfuscation | 5× | `base64.b64decode`, `atob()`, `String.fromCharCode`, hex escape sequences |
| 6 | Provenance | 1–3× | Git history depth, binary files, hidden dotfiles, large files, filesystem operations |
| 7 | Prompt Injection | 10× | AI agent instruction injection, system prompt overrides, jailbreak attempts |
| 8 | Skill Security | 5× | MCP permission escalation, undeclared tool capabilities, skill.yaml tampering |

**Supplementary checks (run after the 8 phases):**

- External scanners: semgrep, bandit, trufflehog, safety, npm audit
- Dependency analysis: package count, unpinned versions
- Permission/scope analysis: Docker privileged mode, GitHub Actions secrets, MCP tool configurations

---

## Verdicts and Scoring

The risk score is the sum of `(finding_count * phase_weight)` across all phases.

| Score / Evidence | Verdict | Meaning | Recommended Action |
|-------|---------|---------|-------------------|
| 0-9 | **LOW RISK** | No known malicious patterns detected | Review any flagged items, then approve |
| 10-24 | **MEDIUM RISK** | Multiple findings that warrant attention | Manual review of each finding |
| 25+ | **HIGH RISK** | Significant suspicious patterns | Do not approve without thorough review |
| Any single Critical-severity finding | **CRITICAL RISK** | Strong indicators of malicious intent, regardless of score | Reject and report |

CRITICAL is evidence-gated, not score-based: it requires at least one Critical-severity finding, and one such finding forces a CRITICAL verdict at any score.

---

## Inline Suppression

A finding you have reviewed and accepted can be silenced where it lives, with the rule
id and a reason, in any comment syntax:

```text
subprocess.run(argv)  # sigil:ignore CODE-013 -- argv list, no shell
# sigil:ignore-next-line CRED-008 -- placeholder value in a test
// sigil:ignore CODE-001,CODE-002 -- template engine, input is a constant
```

A whole-file marker within the first 50 lines covers every match of that rule in the
file:

```text
//! sigil:ignore-file PERSIST-001 -- this module inspects crontabs
```

Markers suppress by exact rule id only; there is no wildcard. A marker on the line that
carries an encoded payload also covers the findings decoded out of it. Suppressed
findings are not dropped: they are listed under `inline_suppressed` in `--format json`
(with `file:line RULE — reason` attributions), as `suppressions` in SARIF, and counted in
the text summary, so a reviewer can audit every one from the report. They do not count
toward the score, the verdict, or the exit code.

For paths rather than lines, use `.sigilignore` (gitignore syntax, whole files). For
artifacts you trust as a unit, use `sigil approve` and the trust ledger.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass — no findings at or above the `--fail-on` severity threshold (default: `high`) |
| `1` | Fail — at least one finding at or above the `--fail-on` threshold |
| `2` | Scan error — invalid path, invalid flags, or the scan could not run |

`sigil residue scan` uses the same three codes against its own `--fail-on` level (which also accepts `info`).

Use exit codes in scripts and CI pipelines to gate on scan results:

```bash
sigil scan ./vendor/
if [ $? -ge 2 ]; then
  echo "High-risk findings detected — blocking deployment"
  exit 1
fi
```

---

## Environment Variables

All configuration can be overridden via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_QUARANTINE_DIR` | `~/.sigil/quarantine` | Directory for quarantined code |
| `SIGIL_APPROVED_DIR` | `~/.sigil/approved` | Directory for approved code |
| `SIGIL_LOG_DIR` | `~/.sigil/logs` | Directory for scan logs |
| `SIGIL_REPORT_DIR` | `~/.sigil/reports` | Directory for scan reports |
| `SIGIL_CONFIG` | `~/.sigil/config` | Path to config file |
| `SIGIL_TOKEN` | `~/.sigil/token` | Path to auth token file |
| `SIGIL_API_URL` | `https://api.sigilsec.ai` | Sigil cloud API base URL |
| `SIGIL_HOME` | `~` | Home directory `sigil residue` inspects and writes backups under (tests and CI) |
| `SIGIL_TIMING` | unset | `1` prints a scan profile to **stderr** — see [Profiling a slow scan](#profiling-a-slow-scan) |
| `SIGIL_FILE_BUDGET_SECS` | `30` | Wall-clock seconds one file may spend in the content pipeline; `0` disables the bound — see [Per-file scan budget](#per-file-scan-budget) |

---

## Profiling a slow scan

`SIGIL_TIMING=1` turns on an opt-in profile. It is silent by default, writes only
to **stderr** (so `--format json` and `--format sarif` stay machine-readable on
stdout), and changes nothing about which findings are produced.

```bash
SIGIL_TIMING=1 sigil scan ./pkg --no-cache --format json > /dev/null
```

It reports two things:

- **Stage totals** — walk, read, normalise, the decode worklist, each regex phase,
  correlation, known-good. These are summed across scan threads, so they add up to
  more than the wall clock on a multi-core machine; the point is the *proportion*.
- **The slowest files**, each with the shape facts that explain the cost: size,
  line count, longest line, how many derived (decoded) units it produced, whether
  the file is machine-generated (`bundled`), and whether it hit the per-file budget
  (`BUDGET`).

```
[sigil timing] 2794 files, 4.367s wall (stage totals below are summed across scan threads, ...)
[sigil timing]   phase prompt_injection        6.004s  39.1%
[sigil timing]   phase code_patterns           2.273s  14.8%
...
[sigil timing] slowest 15 files:
[sigil timing]      1.039s    1.4MB       2 lines longest-line   1485777 derived   0 bundled  litellm/proxy/swagger/swagger-ui-bundle.js
```

A file is reported as `bundled` when its longest line is at least 4 KB or its mean
line length is at least 1 KB — the shape a minifier, bundler or sourcemap writer
produces and a person does not. The label is descriptive only: **every rule still
runs on machine-generated files**, because that is exactly where a compromised
package tends to hide its payload.

---

## Per-file scan budget

Analysis of one file is not bounded by its size: the decode worklist turns encoded
content into more content to scan. `SIGIL_FILE_BUDGET_SECS` bounds it — default
`30` seconds per file, `0` to disable. The bound is deliberately far above real
work: the slowest single file in Sigil's 268-package evaluation subset is a 5.3 MB
minified bundle at 2.3 s, so the budget is a stop against a worklist that will not
terminate, not a throttle on ordinary scanning.

When a file runs out of time, the work already done is kept and the truncation is
**reported** rather than hidden, as one Low `PROV-BUDGET-001` finding in the
Provenance phase naming that file. A scan that quietly gave up on a file would
otherwise be indistinguishable from a scan that found nothing in it.

Because the finding belongs to the Provenance phase, a `--phases` filter that
excludes Provenance also excludes it.

---

## File Types Scanned

Sigil scans the following file types:

| Extension | Language |
|-----------|----------|
| `*.py` | Python |
| `*.js`, `*.mjs` | JavaScript |
| `*.ts`, `*.tsx` | TypeScript |
| `*.jsx` | JSX |
| `*.sh` | Shell |
| `*.yaml`, `*.yml` | YAML |
| `*.json` | JSON |
| `*.toml` | TOML |

**Never content-scanned:** `node_modules/`, `.git/`, `target/`, `.next/`, `__pycache__/`, virtualenvs and tool caches. `dist/` and `build/` are scanned unless the repository's own `.gitignore` excludes them.

Custom exclusions can be added via a `.sigilignore` file (see [Configuration Guide](configuration.md)).

---

## External Scanner Integration

Sigil integrates with these security scanners when they are installed:

| Scanner | Install | What It Adds |
|---------|---------|-------------|
| [semgrep](https://semgrep.dev) | `pip install semgrep` | Advanced multi-language pattern matching |
| [bandit](https://bandit.readthedocs.io) | `pip install bandit` | Python-specific security linting |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | `brew install trufflehog` | Deep secret detection across git history |
| [safety](https://pyup.io/safety/) | `pip install safety` | Python CVE scanning against known vulnerabilities |
| npm audit | Bundled with npm | JavaScript dependency vulnerability scanning |

Check which scanners are available:

```bash
sigil config
```

All eight core scan phases run without any external scanners. External scanners add depth but are not required.

---

## See Also

- [Getting Started](getting-started.md) — Installation walkthrough and first scan
- [Configuration Guide](configuration.md) — Environment variables, .sigilignore, policies
- [Scan Phases Reference](scan-rules.md) — Detailed patterns and examples for each phase
- [CI/CD Integration](cicd.md) — Using Sigil in GitHub Actions, GitLab CI, and other pipelines
- [MCP Integration](mcp.md) — Connecting Sigil to AI agents via MCP
