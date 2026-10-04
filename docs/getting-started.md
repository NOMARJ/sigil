# Getting Started with Sigil

Sigil is an automated security auditing CLI for AI agent code. It scans repositories, packages, and agent tooling for malicious patterns using a quarantine-first workflow -- nothing executes until you explicitly approve it.

## Prerequisites

- **Operating system:** macOS or Linux (Windows via WSL)
- **Shell:** Bash or Zsh, only for the optional `sigil setup shell` aliases
- **Git:** Required for `sigil clone` and provenance analysis
- **pip / npm:** Required only for `sigil pip` / `sigil npm`

## Installation

### Option 1: Quick Install (recommended)

```bash
curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
sh install.sh
```

Detects your platform (Linux or macOS, x64 or arm64), downloads the pre-built binary from the latest GitHub release and checks it against the release's `SHA256SUMS.txt`. If it cannot download or run a release binary it stops and suggests `cargo install sigil-cli`. Installs to `/usr/local/bin` (set `INSTALL_DIR` to change it) and sets up the Claude Code plugin when the `claude` CLI is on your PATH (skip with `--no-integrations`). Shell aliases are added only with `sh install.sh --with-aliases`.

### Option 2: Homebrew

```bash
brew install nomarj/tap/sigil
```

### Option 3: npm global package

```bash
npm install -g @nomarj/sigil
```

### Option 4: Manual Install

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil/cli

# Build the Rust CLI (needs a Rust toolchain) and copy it to /usr/local/bin
cargo build --release
sudo ./target/release/sigil install
```

`sigil install` only copies the binary (`--path <dir>` picks another existing directory). There is no directory initialization step: Sigil creates what it needs under `~/.sigil/` the first time a command uses it.

### Option 5: Full Setup

```bash
# After installing with any option above
sigil setup all
```

This wires Sigil into your tools in one step:

1. Registers the Sigil Claude Code plugin, if the `claude` CLI is on your PATH (`sigil setup claude`)
2. Installs shell aliases in your `.bashrc` or `.zshrc` (`sigil setup shell`)
3. Installs a git pre-commit hook, when run from the root of a git repository (`sigil setup git`)

### Verify Installation

```bash
sigil help
```

You should see the Sigil help menu listing all available commands.

## Installing Optional Security Scanners

Sigil's built-in scanner runs all eight phases without any external tools. The CLI does not call `semgrep`, `bandit`, `trufflehog` or `safety`, so installing them does not change its results.

## First Scan Walkthrough

### Scanning a Git Repository

Let's scan a repository before using it:

```bash
sigil clone https://github.com/someone/interesting-mcp-server
```

What happens:

1. Sigil clones the repository into `~/.sigil/quarantine/<id>/` (shallow clone, depth 1)
2. The eight scan phases run against the quarantined copy
3. A risk score and verdict are displayed
4. The report is printed to the terminal; nothing is saved unless you pass `-o FILE` (see [Reading the Report](#reading-the-report))

Example output for a small repository with an `eval()` call, an outbound `requests.post` and an `API_KEY` read (the clone progress lines are omitted and the `fix:` advice is shortened):

```
  sigil Scan complete in 745ms
  3 files scanned
  Platform: generic
  3 findings
  Risk score: 20
  Grade: D
  Breakdown: 0 critical, 1 high, 0 medium, 2 low

  >> Code Patterns (1 finding)
  --------------------------------------------------------
  HIGH     [CODE-001] src/parser.py:2
       eval() call — arbitrary code execution: result = eval(expression)
       fix: eval() in Python, JavaScript, PHP or Ruby compiles and runs a string as code, so read the string it receives. ...

  >> Network/Exfil (1 finding)
  --------------------------------------------------------
  LOW      [NET-001] src/api.py:4
       HTTP request via requests library: requests.post(endpoint, json=data)

  >> Credentials (1 finding)
  --------------------------------------------------------
  LOW      [CRED-001] src/config.py:3
       Sensitive environment variable read (Python): api_key = os.environ.get('API_KEY')

  Behaviour profile: dynamic_execution, network_outbound, reads_credentials
  Key risks:
    > HIGH: eval() call — arbitrary code execution (CODE-001) — src/parser.py:2

============================================================
  HIGH RISK -- Dangerous patterns found; review before use
============================================================
  Grade: D

  These patterns also appear in legitimate code (network calls,
  base64, env access). If you trust this package after review:
    sigil scan <path> -f json > scan.json
    sigil explain scan.json   why a finding fired
    sigil approve <id>        trust it — suppresses these findings

  Note: Sigil scans detect known malicious patterns through static analysis.
  A low risk result does not guarantee the absence of all threats.
  Always review code before use. See sigilsec.ai/terms for full terms.
```

`sigil list` shows the quarantine ID (eight hex characters) to pass to `sigil approve` or `sigil reject`.

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

Scans the directory in place; it is not copied into quarantine.

## Understanding Verdicts

After every scan, Sigil produces a risk score and verdict:

| Score / Evidence                     | Verdict           | What It Means                                              | What to Do                                    |
| ------------------------------------ | ----------------- | ---------------------------------------------------------- | --------------------------------------------- |
| 0-9                                  | **LOW RISK**      | No known malicious patterns detected                       | Review any flagged items, then approve        |
| 10-24                                | **MEDIUM RISK**   | Multiple findings that warrant attention                   | Read the report, check each finding manually  |
| HIGH gate (see the CLI reference)    | **HIGH RISK**     | Significant suspicious patterns                            | Do not approve without thorough manual review |
| Critical evidence                    | **CRITICAL RISK** | Strong indicators of malicious intent, regardless of score | Reject and report                             |

CRITICAL is evidence-gated: it needs one Critical finding from a rule whose
evidence stands alone, or Critical findings from two *different* rules that are
individually inconclusive (a private key in a test fixture, for instance). See
[Verdicts and Scoring](cli.md#verdicts-and-scoring) for the full rule.

### Reading the Report

The report is printed to the terminal and is not saved by default. To keep a copy, pass the global `-o` flag, which writes the report to that file instead (`-f` picks the format: text, json, sarif, html, markdown or junit):

```bash
sigil -o report.txt clone https://github.com/someone/interesting-mcp-server
cat report.txt
```

The report lists every finding from every phase, with file names and line numbers. Review each finding to determine whether it is a true positive or a false positive.

### Taking Action

After reviewing the scan results:

```bash
# Approve -- mark as trusted and pin its digest in the trust ledger
sigil approve <quarantine-id>

# Reject -- permanently delete the quarantined code
sigil reject <quarantine-id>

# See all quarantined items and their verdicts
sigil list
```

Approved code stays at `~/.sigil/quarantine/<id>/` — approval records the item in the trust ledger (so future digest-matching scans are allowlisted). Copy or symlink the files into your project yourself.

## Shell Aliases Setup

Sigil can install shell aliases that wrap your existing commands with automatic quarantine and scanning:

```bash
sigil setup shell
```

This adds the following aliases to your `.bashrc` or `.zshrc`:

| Alias           | What It Does                       |
| --------------- | ---------------------------------- |
| `gclone <url>`  | `git clone` with quarantine + scan |
| `safepip <pkg>` | `pip install` with scan first      |
| `safenpm <pkg>` | `npm install` with scan first      |

After installation, reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

## Git Hooks Setup

Install a pre-commit hook that scans the repository before each commit:

```bash
# Install in the current repository (run from its root)
sigil setup git
```

The pre-commit hook runs `sigil scan . --fail-on high` — all eight scan phases — and blocks the commit on HIGH or CRITICAL findings. You can bypass it with `git commit --no-verify` when you know a finding is safe.

## Connecting to Cloud (sigil login)

By default, Sigil runs entirely offline. To enable community threat intelligence, scan history, and team features, authenticate with the Sigil cloud:

```bash
sigil login
```

This prompts for your email and password (or opens a browser for SSO). After authentication, the CLI stores a JWT token locally and includes it in API calls.

**What changes after login:**

| Feature                      | Offline | Authenticated   |
| ---------------------------- | ------- | --------------- |
| Eight scan phases            | Yes     | Yes             |
| Threat intelligence lookups  | No      | Yes             |
| Publisher reputation scores  | No      | Yes             |
| Community threat signatures  | No      | Yes             |
| Scan history in dashboard    | No      | Yes             |
| Team policies                | No      | Yes (Team tier) |

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

View the scan policy that applies to the current directory:

```bash
sigil config --policy
```

There is no initialization step: Sigil creates what it needs under `~/.sigil/` the first time a command uses it. See the [Configuration Guide](configuration.md#directory-structure) for the layout.

Override the quarantine directory via an environment variable:

```bash
export SIGIL_QUARANTINE_DIR=/custom/path/quarantine
```

## Next Steps

- Read the [Scan Rules Reference](scan-rules.md) to understand what each phase detects
- Read the [Threat Model](threat-model.md) to understand limitations and false positives
- Read the [Architecture](architecture.md) for details on how the system works
- Read the [API Reference](api-reference.md) if you are building integrations
