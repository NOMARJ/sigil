# Getting Started with Sigil

Sigil is an automated security auditing CLI for AI agent code. It scans repositories, packages, and agent tooling for malicious patterns using a quarantine-first workflow -- nothing executes until you explicitly approve it.

## Prerequisites

- **Operating system:** macOS or Linux (Windows via WSL)
- **Shell:** Bash 4+ or Zsh
- **Required tools:** `grep`, `find`, `file` (pre-installed on most systems)
- **Git:** Required for `sigil clone` and provenance analysis
- **Optional tools for enhanced scanning:**
  - `semgrep` -- advanced pattern matching
  - `bandit` -- Python security linting
  - `trufflehog` -- secret detection
  - `safety` -- Python CVE scanning

## Installation

### Option 1: Quick Install (recommended)

```bash
curl -sSL https://sigilsec.ai/install.sh | sh
```

This downloads the CLI, installs it to `/usr/local/bin`, creates the `~/.sigil` directory structure, and installs shell aliases.

### Option 2: Homebrew (macOS/Linux)

```bash
brew install nomarj/tap/sigil
```

### Option 3: npm (global)

```bash
npm install -g @nomarj/sigil
```

### Option 4: Manual Install

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Make the CLI executable and copy to PATH
chmod +x bin/sigil
sudo cp bin/sigil /usr/local/bin/sigil

# Initialize directories
sigil config --init
```

### Option 5: Full Interactive Install

```bash
# After cloning or downloading
./bin/sigil install
```

This runs the full installer which:
1. Copies the binary to `/usr/local/bin`
2. Creates `~/.sigil/{quarantine,approved,logs,reports}`
3. Installs shell aliases in your `.bashrc` or `.zshrc`
4. Optionally installs recommended security scanners

### Verify Installation

```bash
sigil help
```

You should see the Sigil help menu listing all available commands.

## Installing Optional Security Scanners

Sigil's built-in scanner runs all six phases without any external tools. However, installing additional scanners improves detection quality:

```bash
# Python security scanners
pip install semgrep bandit safety

# Secret detection (macOS)
brew install trufflehog

# Secret detection (Linux)
# See https://github.com/trufflesecurity/trufflehog for Linux install options
```

Check which scanners are available:

```bash
sigil config
```

This displays the status of each scanner (installed or not installed).

## First Scan Walkthrough

### Scanning a Git Repository

Let's scan a repository before using it:

```bash
sigil clone https://github.com/someone/interesting-mcp-server
```

What happens:

1. Sigil clones the repository into `~/.sigil/quarantine/<id>/` (shallow clone, depth 1)
2. The six scan phases run against the quarantined copy
3. External scanners run if available
4. A risk score and verdict are displayed
5. A detailed report is saved to `~/.sigil/reports/`

Example output:

```
[sigil] Cloning https://github.com/someone/interesting-mcp-server into quarantine...
[sigil] Cloned to: /home/user/.sigil/quarantine/20260215_143000_interesting_mcp_server

+----------------------------------------------+
|               S I G I L                      |
|      Automated Security Analysis             |
|              by NOMARK                       |
+----------------------------------------------+

=== Phase 1: Install Hook Analysis ===
[PASS] No suspicious setup.py hooks
[PASS] No npm install hooks

=== Phase 2: Code Pattern Analysis ===
[warn] Found 'eval(':
  src/parser.py:42: result = eval(expression)

=== Phase 3: Network & Exfiltration Analysis ===
[warn] Outbound network call 'requests.post':
  src/api.py:18: requests.post(endpoint, json=data)

=== Phase 4: Credential & Secret Access ===
[warn] Potential credential access 'API_KEY':
  src/config.py:5: api_key = os.environ.get('API_KEY')

=== Phase 5: Obfuscation Detection ===
[PASS] No obfuscation patterns detected

=== Phase 6: Provenance & Metadata ===
[info] Git history: 47 commits, 3 authors
[PASS] No binary executables found

+--------------------------------------+
|  VERDICT: MEDIUM RISK                |
|  Risk Score: 12                      |
|  Manual review recommended.          |
+--------------------------------------+

Quarantine ID: 20260215_143000_interesting_mcp_server
Full report:   /home/user/.sigil/reports/20260215_143000_interesting_mcp_server_report.txt

Actions:
  sigil approve 20260215_143000_interesting_mcp_server  -- Move to working directory
  sigil reject  20260215_143000_interesting_mcp_server  -- Delete from quarantine
```

### Scanning a pip Package

```bash
sigil pip some-agent-toolkit
```

Sigil downloads the package (without installing it), extracts it into quarantine, and runs the full scan.

### Scanning an npm Package

```bash
sigil npm langchain-community-plugin
```

Same quarantine-and-scan workflow for npm packages.

### Scanning a Local Directory

```bash
sigil scan ./some-downloaded-code/
```

Copies the directory into quarantine and scans the copy.

## Understanding Verdicts

After every scan, Sigil produces a risk score and verdict:

| Score | Verdict | What It Means | What to Do |
|-------|---------|---------------|------------|
| 0 | **CLEAN** | No suspicious patterns detected | Safe to approve |
| 1-9 | **LOW RISK** | Minor findings, likely false positives | Review the flagged items, then approve |
| 10-24 | **MEDIUM RISK** | Multiple findings that warrant attention | Read the report, check each finding manually |
| 25-49 | **HIGH RISK** | Significant suspicious patterns | Do not approve without thorough manual review |
| 50+ | **CRITICAL** | Multiple strong indicators of malicious intent | Reject and report |

### Reading the Report

The full report is saved as a text file. View it with:

```bash
# The path is shown in the scan output
cat ~/.sigil/reports/<quarantine-id>_report.txt
```

The report lists every finding from every phase, with file names and line numbers. Review each finding to determine whether it is a true positive or a false positive.

### Taking Action

After reviewing the scan results:

```bash
# Approve -- move the code out of quarantine
sigil approve <quarantine-id>

# Reject -- permanently delete the quarantined code
sigil reject <quarantine-id>

# See all quarantined items and their verdicts
sigil list
```

Approved code is moved to `~/.sigil/approved/<id>/`. You can then copy or symlink it into your project.

## Shell Aliases Setup

Sigil can install shell aliases that wrap your existing commands with automatic quarantine and scanning:

```bash
sigil aliases
```

This adds the following aliases to your `.bashrc` or `.zshrc`:

| Alias | What It Does |
|-------|-------------|
| `gclone <url>` | `git clone` with quarantine + scan |
| `safepip <pkg>` | `pip install` with scan first, prompts to install after |
| `safenpm <pkg>` | `npm install` with scan first, prompts to install after |
| `safefetch <url>` | Download + quarantine + scan |
| `audit <path>` | Shortcut for `sigil scan` |
| `audithere` | Scan the current directory |
| `qls` | Show quarantine status |
| `qapprove` | Approve the most recent quarantined item |
| `qreject` | Reject the most recent quarantined item |

After installation, reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

You can also print the aliases without installing them:

```bash
sigil aliases --print
```

## Git Hooks Setup

Install a pre-commit hook that scans staged files for dangerous patterns:

```bash
# Install in the current repository
sigil hooks

# Install in a specific repository
sigil hooks /path/to/repo
```

The pre-commit hook checks every staged file for patterns like `eval()`, `exec()`, `__import__()`, `subprocess` with `shell=True`, `os.system`, `pickle.loads`, and `child_process`. If any are found, the commit is blocked with a warning. You can bypass it with `git commit --no-verify` when you know the pattern is safe.

## Connecting to Cloud (sigil login)

By default, Sigil runs entirely offline. To enable community threat intelligence, scan history, and team features, authenticate with the Sigil cloud:

```bash
sigil login
```

This prompts for your email and password (or opens a browser for SSO). After authentication, the CLI stores a JWT token locally and includes it in API calls.

**What changes after login:**

| Feature | Offline | Authenticated |
|---------|---------|---------------|
| Six scan phases | Yes | Yes |
| External scanner integration | Yes | Yes |
| Threat intelligence lookups | No | Yes |
| Publisher reputation scores | No | Yes |
| Community threat signatures | No | Yes |
| Scan history in dashboard | No | Yes |
| Team policies | No | Yes (Team tier) |

**What is sent to the cloud:**

- Which scan rules triggered (e.g., "Phase 2: eval() found")
- File type distribution (e.g., "12 Python files, 8 JavaScript files")
- Risk score and verdict
- Package name/version/hash

**What is NEVER sent:**

- Source code
- File contents
- Credentials or environment variables

## Configuration

View your current configuration:

```bash
sigil config
```

Initialize the directory structure:

```bash
sigil config --init
```

Override directories via environment variables:

```bash
export SIGIL_QUARANTINE_DIR=/custom/path/quarantine
export SIGIL_APPROVED_DIR=/custom/path/approved
export SIGIL_LOG_DIR=/custom/path/logs
export SIGIL_REPORT_DIR=/custom/path/reports
```

## Next Steps

- Read the [Scan Rules Reference](scan-rules.md) to understand what each phase detects
- Read the [Threat Model](threat-model.md) to understand limitations and false positives
- Read the [Architecture](architecture.md) for details on how the system works
- Read the [API Reference](api-reference.md) if you are building integrations
