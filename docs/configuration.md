# Configuration Guide

Everything that controls Sigil's behavior — environment variables, config file, ignore patterns, scan policies, shell aliases, and git hooks.

---

## Precedence

Configuration is resolved in this order (highest priority first):

1. **Command-line flags** — override everything
2. **Environment variables** — override config file and defaults
3. **Config file** (`~/.sigil/config`) — overrides defaults
4. **Built-in defaults** — used when nothing else is set

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_QUARANTINE_DIR` | `~/.sigil/quarantine` | Where quarantined code is stored |
| `SIGIL_APPROVED_DIR` | `~/.sigil/approved` | Where approved code is moved |
| `SIGIL_LOG_DIR` | `~/.sigil/logs` | Scan execution logs |
| `SIGIL_REPORT_DIR` | `~/.sigil/reports` | Detailed scan reports (text) |
| `SIGIL_CONFIG` | `~/.sigil/config` | Path to the config file |
| `SIGIL_TOKEN` | `~/.sigil/token` | Path to the authentication token file |
| `SIGIL_API_URL` | `https://api.sigilsec.ai` | Sigil cloud API base URL |

**Example: custom quarantine location**

```bash
export SIGIL_QUARANTINE_DIR=/opt/security/quarantine
export SIGIL_APPROVED_DIR=/opt/security/approved
```

**Example: point to a self-hosted API**

```bash
export SIGIL_API_URL=https://sigil.internal.company.com
```

---

## Directory Structure

After running `sigil config --init` or `sigil install`, Sigil creates:

```
~/.sigil/
├── quarantine/     # Untrusted code awaiting scan and review
├── approved/       # Code that passed review
├── logs/           # Scan execution logs
├── reports/        # Detailed scan reports (text files)
├── config          # User configuration file
├── token           # JWT authentication token (after sigil login)
└── signatures.json # Cached threat signatures (after first authenticated scan)
```

---

## Config File

The config file at `~/.sigil/config` stores persistent settings. It uses a simple `KEY=VALUE` format.

```bash
# ~/.sigil/config
API_URL=https://api.sigilsec.ai
AUTO_APPROVE_THRESHOLD=0
DEFAULT_SEVERITY=low
```

View current config:

```bash
sigil config
```

Initialize directories and create the config file:

```bash
sigil config --init
```

---

## .sigilignore

The `.sigilignore` file tells Sigil which files and directories to skip during scanning. It uses glob patterns, similar to `.gitignore`.

### File Location

Place `.sigilignore` in the root of the directory being scanned. Sigil checks for it automatically.

### Syntax

```bash
# Comments start with #
# Each line is a glob pattern

# Directories
node_modules/
.git/
__pycache__/
vendor/
dist/
build/

# File patterns
*.min.js
*.bundle.js
*.map
*.lock

# Specific files
package-lock.json
yarn.lock
poetry.lock
```

### Default Exclusions

Even without a `.sigilignore` file, Sigil always skips:

- `node_modules/` — npm dependencies
- `.git/` — git internal files
- Test files and example files
- Documentation files

### Pattern Rules

| Pattern | Matches |
|---------|---------|
| `*.min.js` | Any file ending in `.min.js` |
| `vendor/` | The `vendor` directory and everything in it |
| `docs/*.md` | Markdown files in the `docs` directory |
| `!important.js` | Negation — do NOT ignore this file even if another rule matches |

---

## Scan Policies (Team Tier)

Teams on the Team plan can configure scan policies that apply to all members. Policies define auto-approve thresholds, required review rules, and package allow/block lists.

### Auto-Approve Threshold

Automatically approve quarantined items with a risk score at or below this threshold.

| Threshold | Effect |
|-----------|--------|
| `0` (default) | Only auto-approve CLEAN scans (score 0) |
| `9` | Auto-approve CLEAN and LOW_RISK |
| `24` | Auto-approve CLEAN, LOW_RISK, and MEDIUM_RISK (not recommended) |
| `-1` | Disable auto-approve — everything requires manual review |

### Required Review

Force manual review for specific verdicts regardless of auto-approve threshold:

- **HIGH_RISK and CRITICAL** — always require manual review (default)
- **MEDIUM_RISK** — optionally require review
- **All** — require review for every scan

### Package Allowlist

Packages that are always approved, bypassing scanning. Use for trusted internal packages.

```
@myorg/shared-utils
@myorg/config
internal-auth-lib
```

### Package Blocklist

Packages that are always rejected, regardless of scan results. Use for known-malicious packages or packages your organization prohibits.

```
malicious-package-name
deprecated-unsafe-lib
```

### Policy Sync

Policies are stored in the Sigil cloud and sync to all authenticated team members. When a policy changes, it takes effect on the next scan.

Configure policies via the web dashboard at **Settings > Scan Policies**, or via the API:

```bash
# Get current policy
curl -H "Authorization: Bearer $TOKEN" https://api.sigilsec.ai/v1/settings/policy

# Update policy
curl -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auto_approve_threshold": 0, "require_review_for": ["HIGH_RISK", "CRITICAL"]}' \
  https://api.sigilsec.ai/v1/settings/policy
```

---

## Shell Aliases

### Installation

```bash
sigil setup shell          # Append aliases to your ~/.bashrc or ~/.zshrc
```

Sigil detects your shell from `$SHELL` (bash or zsh). The step is idempotent — re-running it never duplicates the block. `install.sh --with-aliases` installs the same block.

### Alias Definitions

```bash
# Installed by `sigil setup shell`
alias gclone='sigil clone'     # Git clone with quarantine + scan
alias safepip='sigil pip'      # pip install with scan first
alias safenpm='sigil npm'      # npm install with scan first
```

Useful extras you can add manually:

```bash
alias safefetch='sigil fetch'
alias audit='sigil scan'
alias audithere='sigil scan .'
alias qls='sigil list'
```

### Removing Aliases

Aliases are added to your shell config file. To remove them, delete the block between the `# >>> sigil aliases >>>` and `# <<< sigil aliases <<<` markers, then reload your shell.

---

## Git Hooks

### Pre-Commit Hook

Install a pre-commit hook that scans the repository before each commit:

```bash
sigil setup git          # Install in the current repo
```

The hook runs `sigil scan . --fail-on high` — all eight scan phases, blocking the commit on HIGH or CRITICAL findings.

### Hook Behavior

- **HIGH/CRITICAL findings:** the scan exits non-zero and the commit is blocked
- **Clean or lower-severity findings:** the commit proceeds
- **Bypass:** `git commit --no-verify` skips the hook for a single commit
- **Missing binary:** if `sigil` is not on PATH the hook warns and lets the commit through

### Hook Location

The hook is written to `.git/hooks/pre-commit`. An existing pre-commit hook not written by sigil is never overwritten. Teams using the [pre-commit framework](https://pre-commit.com) can use the repo's `.pre-commit-hooks.yaml` instead.

---

## Authentication

### Token Storage

After `sigil login`, the JWT token is stored at `~/.sigil/token` (or the path specified by `SIGIL_TOKEN`). The file contains only the raw JWT string.

### Token Lifecycle

- Tokens are issued by the Sigil API with an expiration time
- The CLI reads the token on each authenticated request
- If the token is expired or missing, the CLI falls back to offline mode (no threat intelligence)
- Run `sigil login` again to refresh an expired token

### What Data Is Sent

When authenticated, scan metadata is sent to the Sigil API. **Source code is never transmitted.**

**Sent:**
- Which scan rules triggered (e.g., "Phase 2: eval() found")
- File type distribution (e.g., "12 Python files, 8 JavaScript files")
- Risk score and verdict
- Package name, version, and hash

**Never sent:**
- Source code or file contents
- Credentials or environment variable values
- File paths on your machine

---

## See Also

- [CLI Command Reference](cli.md) — Full reference for every command and flag
- [Getting Started](getting-started.md) — Installation and first scan walkthrough
- [CI/CD Integration](cicd.md) — Configuration for CI/CD pipelines
- [Scan Phases Reference](scan-rules.md) — What each scan phase detects
