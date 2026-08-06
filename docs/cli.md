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

Scan an existing file or directory for security issues.

```bash
sigil scan <path>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `path` | Yes | File or directory to scan |

**Behavior:**

1. Verifies the path exists
2. Copies into quarantine (if not already quarantined)
3. Runs all 8 scan phases + external scanners
4. Generates verdict and saves report

**Example:**

```bash
sigil scan .                           # Scan current directory
sigil scan ./vendor/                   # Scan vendor directory
sigil scan ./downloaded-mcp-server/    # Scan a specific directory
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

Move a quarantined item to the approved directory after review.

```bash
sigil approve <quarantine-id>
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `quarantine-id` | Yes | ID shown in `sigil list` output |

**Security:**

- Validates the quarantine ID format (alphanumeric and underscores only)
- Uses `realpath` to prevent path traversal attacks
- Verifies the source path is within the quarantine directory

**Behavior:**

Moves the item from `~/.sigil/quarantine/<id>/` to `~/.sigil/approved/<id>/`.

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

## Account Commands

### sigil login

Authenticate with the Sigil cloud API to enable threat intelligence, scan history, and team features.

```bash
sigil login
sigil login --email dev@example.com --password mysecret
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--email <email>` | Email address (interactive prompt if omitted) |
| `--password <password>` | Password (interactive prompt if omitted) |

**Behavior:**

1. Authenticates against the Sigil API (`POST /v1/auth/login`)
2. Stores the JWT token to `~/.sigil/token`
3. Subsequent scans include threat intelligence enrichment

**What authentication enables:**

- Threat intelligence lookups (known malicious hash database)
- Publisher reputation scores
- Community threat signatures (delta sync)
- Scan history in the web dashboard
- Team policies and alerts

---

### sigil logout

Remove stored authentication credentials.

```bash
sigil logout
```

Deletes the token file at `~/.sigil/token`. Scans return to offline-only mode.

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

| Score | Verdict | Meaning | Recommended Action |
|-------|---------|---------|-------------------|
| 0 | **CLEAN** | No suspicious patterns detected | Safe to approve |
| 1-9 | **LOW RISK** | Minor findings, likely false positives | Review flagged items, then approve |
| 10-24 | **MEDIUM RISK** | Multiple findings that warrant attention | Manual review of each finding |
| 25-49 | **HIGH RISK** | Significant suspicious patterns | Do not approve without thorough review |
| 50+ | **CRITICAL** | Multiple strong indicators of malicious intent | Reject and report |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | CLEAN — no findings, or command completed successfully |
| `1` | CRITICAL — score 50+, or command error |
| `2` | HIGH_RISK — score 25-49 |
| `3` | MEDIUM_RISK — score 10-24 |
| `4` | LOW_RISK — score 1-9 |

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

**Excluded by default:** `node_modules/`, `.git/`, test files, example files, documentation files.

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
