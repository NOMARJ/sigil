# Getting Started with Sigil

Sigil is an automated security auditing CLI for AI agent code. It scans repositories, packages, and agent tooling for malicious patterns using a quarantine-first workflow -- nothing it fetches is installed or run before you review it, with one exception: `sigil pip` lets pip run a source-only package's `setup.py` (see [Scanning a pip Package](#scanning-a-pip-package)).

## Prerequisites

- **Operating system:** macOS or Linux; on Windows, the native x64 `sigil.exe` from the release zip (see the [Installation Guide](installation.md#windows)) or WSL
- **Shell:** Bash or Zsh, only for the optional `sigil setup shell` aliases
- **Git:** Required for `sigil clone` and provenance analysis
- **pip / npm:** Required only for `sigil pip` / `sigil npm`

## Installation

### Option 1: Quick Install (recommended)

```bash
curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
sh install.sh
```

Detects your platform (Linux or macOS, x64 or arm64), downloads the pre-built binary from the latest GitHub release and checks it against the release's `SHA256SUMS.txt` when `sha256sum` or `shasum` is available. If neither hashing tool is installed, the installer warns and continues without checksum verification; install one of these tools before running it to verify the download. `--skip-verify` also disables this check. If it cannot download or run a release binary it stops and suggests `cargo install sigil-cli`. Installs to `/usr/local/bin` (set `INSTALL_DIR` to change it) and sets up the Claude Code plugin when the `claude` CLI is on your PATH (skip with `--no-integrations`). Shell aliases are added only with `sh install.sh --with-aliases`.

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

# Build the Rust CLI (needs Rust 1.89 or newer and, on Linux, a C compiler, make
# and perl for the vendored OpenSSL) and copy it to /usr/local/bin
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

Sigil downloads the package (without installing it), extracts it into quarantine, and runs the full scan. It downloads with `pip download`, so for a package published only as a source distribution, pip runs the package's `setup.py` on your machine to read its metadata, before the scan.

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

| Evidence                                                                                          | Verdict           | What It Means                                              | What to Do                                    |
| ------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------- | --------------------------------------------- |
| Nothing that reaches MEDIUM (typically no findings, or Low-severity observations only)            | **LOW RISK**      | No known malicious patterns detected                       | Review any flagged items, then approve        |
| A Medium-or-above finding in the code itself, a High or Critical one anywhere, or 10+ points of Medium-and-above findings | **MEDIUM RISK**   | Findings that warrant attention                            | Read the report, check each finding manually  |
| HIGH gate (see the CLI reference)                                                                 | **HIGH RISK**     | Significant suspicious patterns                            | Do not approve without thorough manual review |
| Critical evidence                                                                                 | **CRITICAL RISK** | Strong indicators of malicious intent, regardless of score | Reject and report                             |

The verdict is not read off the risk score, which is informational: Low
findings count toward the score but never raise the verdict, and a single High
finding in the code the package runs is enough for at least MEDIUM. The clone
example above scores 20 and is HIGH RISK because its one High finding (`eval()`) sits in
a three-file repository.

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

# See all quarantined items and their status
sigil list
```

Approved code stays at `~/.sigil/quarantine/<id>/` — approval records the item in the trust ledger (so future digest-matching scans are allowlisted). Copy or symlink the files into your project yourself.

## Shell Aliases Setup

Sigil can install shell aliases that wrap your existing commands with automatic quarantine and scanning:

```bash
sigil setup shell
```

This adds the following aliases to your `.bashrc` or `.zshrc`:

| Alias           | What It Does                                                         |
| --------------- | -------------------------------------------------------------------- |
| `gclone <url>`  | `git clone` with quarantine + scan                                   |
| `safepip <pkg>` | `sigil pip`: download into quarantine and scan (does not install)    |
| `safenpm <pkg>` | `sigil npm`: download into quarantine and scan (does not install)    |

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

Sigil needs no account, and the eight scan phases run locally. `sigil scan` does go online for one thing by default: when the scanned directory has a `requirements.txt`, `package-lock.json`, `Cargo.lock` or `go.mod`, it looks the listed dependencies up in the OSV advisory database, and npm and PyPI packages on their registry; for CVE-numbered advisories it also fetches CISA KEV and FIRST EPSS data, sending those CVE IDs (without a connection these lookups are skipped and the scan still completes). For community threat intelligence and scan history, authenticate with the Sigil cloud:

```bash
sigil login
```

The CLI prints a verification URL and code. Open the URL, confirm the code, and finish signing in in your browser while the CLI waits. After authentication, the CLI stores the access token in `~/.sigil/token`. For non-interactive use, pass an existing token with `sigil login --token "$SIGIL_API_TOKEN"`. There is currently no way to generate an API token from the dashboard: the token to pass is the one a browser sign-in saved in `~/.sigil/token`, and it expires (the CLI does not refresh it), so sign in again and replace it when it does. Logging in does not change a plain scan; the token is sent only by the cloud options below.

**The cloud options** (each is something you run explicitly):

| Option                    | What it does                                                                     |
| ------------------------- | -------------------------------------------------------------------------------- |
| `sigil scan --enrich`     | Pro: looks the scanned directory's hash up in the threat database                |
| `sigil fetch`             | Pro: downloads community threat signatures, which later fresh scans apply        |
| `sigil scan --submit`     | Sends the scan result to the Sigil API (scan history)                            |
| `sigil scan --enhanced`   | Pro: uploads file contents for LLM analysis (requires login)                     |
| `sigil explain scan.json` | Sends a saved scan report's findings for AI adjudication of one (requires login) |

The `sigil scan` options run only on a fresh scan. Re-scanning an unchanged directory reuses the cached result (`sigil: using cached result`) and skips them without a message, so add `--no-cache`, for example `sigil scan . --enrich --no-cache`. Signatures from `sigil fetch` likewise reach a directory scanned before the fetch only after `sigil clear-cache` or with `--no-cache`.

**What is sent to the cloud:** only what these options send. `--enrich` sends a SHA-256 hash of the scanned files' paths and sizes. `--submit` sends the scan result: each finding's rule, severity, file path, line and the flagged source line, plus the score and verdict. `--enhanced` uploads the contents of up to 50 eligible text files under the target directory, collected independently of scan exclusions. `sigil explain` sends every finding in the scan report it reads, flagged source lines included. Without them, nothing goes to the Sigil API. See [Data Handling](data-handling.md) for the full breakdown.

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

- Read the [Scan Phases](cli.md#scan-phases) reference to understand what each phase detects
- Read the [Threat Model](threat-model.md) to understand limitations and false positives
- Read the [Architecture](architecture.md) for details on how the system works
- Read the [API Reference](api-reference.md) if you are building integrations
