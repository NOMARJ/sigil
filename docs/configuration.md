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
  -d '{"auto_approve_threshold": 0, "require_review_for": ["HIGH", "CRITICAL"]}' \
  https://api.sigilsec.ai/v1/settings/policy
```

---

## Shell Aliases

### Installation

```bash
sigil aliases              # Detect shell and install to config file
sigil aliases --print      # Print aliases without installing
```

Sigil detects your shell by checking for `~/.zshrc`, `~/.bashrc`, or Fish config.

### Alias Definitions

```bash
# Git clone with quarantine
alias gclone='sigil clone'

# Safe package installation
alias safepip='sigil pip'
alias safenpm='sigil npm'
alias safefetch='sigil fetch'

# Quick scanning
alias audit='sigil scan'
alias audithere='sigil scan .'

# Quarantine management
alias qls='sigil list'
alias qapprove='sigil approve "$(ls -t "$HOME/.sigil/quarantine" | head -1)"'
alias qreject='sigil reject "$(ls -t "$HOME/.sigil/quarantine" | head -1)"'
```

### Customization

To customize aliases, run `sigil aliases --print` and add only the ones you want to your shell config manually. You can rename them or modify the behavior.

### Removing Aliases

Aliases are added to your shell config file (`.bashrc`, `.zshrc`, or Fish config). To remove them, open the file and delete the block between the `# SIGIL ALIASES` comments, then reload your shell.

---

## Git Hooks

### Pre-Commit Hook

Install a pre-commit hook that scans staged files for dangerous patterns:

```bash
sigil hooks              # Install in current repo
sigil hooks /path/to/repo    # Install in specific repo
```

The hook runs before every commit and checks staged files for:

- `eval(`, `exec(`, `__import__(`
- `subprocess` with `shell=True`
- `os.system`, `pickle.loads`, `child_process`

### Hook Behavior

- **Finding detected:** Hook prints a warning with the file and pattern, then exits with code 1 (blocking the commit)
- **No findings:** Hook exits with code 0 (commit proceeds)
- **Bypass:** `git commit --no-verify` skips the hook when you know the pattern is safe

### Hook Location

The hook is written to `.git/hooks/pre-commit` in the target repository. It does not modify any global git configuration.

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
