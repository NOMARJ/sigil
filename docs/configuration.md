# Configuration Guide

Everything that controls Sigil's behavior — environment variables, config file, ignore patterns, scan policies, shell aliases, and git hooks.

---

## Precedence

Configuration is resolved in this order (highest priority first):

1. **Command-line flags** — override everything
2. **Environment variables** — override config file and defaults
3. **Config file** (`~/.sigil/config`) — overrides defaults
4. **Built-in defaults** — used when nothing else is set

What a *scan* enforces — the exit gate, disabled rules, ignored paths,
baselines, custom rules — is set by the scan policy described next, which has
its own precedence (organisation file, project file, flags) and lock rules.
For rolling a policy out across a fleet, see [enterprise.md](enterprise.md).

---

## Scan policy (`.sigil.yml`)

A scan policy is a YAML file. Sigil reads, in order:

1. the **organisation policy** named by `SIGIL_POLICY_FILE`, if set (an
   unreadable or invalid file is an error, exit `2`);
2. the **project policy**: `--config FILE`, or else the first of
   `.sigil.yml`, `.sigil.yaml`, `sigil.yml` in the scan root, then in the
   current directory (skip discovery with `--no-project-config` or
   `SIGIL_NO_PROJECT_CONFIG=1`);
3. **flags**: `--fail-on`, `--fail-on-verdict`, `--severity`, `--baseline`,
   `--rules`, and for the LLM stage `--llm-review`, `--no-llm-review` and
   `--llm-model` (or `SIGIL_LLM_MODEL`).

Later layers override earlier ones, except that a key the organisation policy
lists under `locked:` can afterwards only be made stricter.

```yaml
version: 1                          # optional; the only version is 1
fail_on: high                       # exit 1 on a finding at or above this (default high)
fail_on_verdict: HIGH               # also exit 1 when the verdict is at or above this
min_severity: low                   # hide findings below this (same as --severity)
disable_rules: [NET-012, "PROV-*"]  # rule ids or globs (* and ?), case-insensitive
severity_overrides:                 # rule id or glob -> severity
  CODE-013: low
ignore_paths: [tests/fixtures/, "*.snap"]   # .sigilignore (gitignore) syntax
rule_packs: [.sigil/rules/]         # custom packs: files or directories
trusted_domains: [api.openai.com]   # excuse network findings to these hosts
baseline: .sigil-baseline.json      # accept the findings recorded here
llm_review: false                   # optional LLM review stage (sends masked code to a model)
llm_may_downgrade: false            # let a model's dismissal lower a finding by one level
llm_provider: anthropic             # or openai-compatible
llm_model: claude-opus-5
llm_max_calls: 25                   # per scan
llm_max_tokens: 200000              # per scan, input + output
# Organisation policy only:
locked: [fail_on, disable_rules]    # or [all]
allow_project_policy: true          # false = project files may only tighten
llm_endpoint: https://llm.internal.example.com/v1   # where the LLM stage sends code
```

| Key | Type | Effect |
|---|---|---|
| `fail_on` | `low`/`medium`/`high`/`critical` | exit 1 when an active finding is at or above it |
| `fail_on_verdict` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` | exit 1 when the verdict is at or above it |
| `min_severity` | severity | findings below it are dropped from the report and the score (counted in `policy.hidden_below_min_severity`) |
| `disable_rules` | list of ids/globs | matching findings move to `policy.suppressed` |
| `severity_overrides` | map id/glob → severity | rewrites a finding's severity before everything else; later entries win |
| `ignore_paths` | list of globs | findings in matching paths move to `policy.suppressed` |
| `rule_packs` | list of paths | adds custom rule packs (relative to the policy file) |
| `trusted_domains` | list of host names | a Network/Exfil finding up to High whose URLs all point at these hosts (or their subdomains) moves to `policy.suppressed`; never Critical findings, credential-flow chains, data-egress rules (`SKILL-017`, `NET-011`, `NET-018`), reverse shells, decoded or truncated lines, or a line with a URL whose host cannot be read with certainty (userinfo `@`, percent encoding, templates, shell quoting) |
| `baseline` | path | findings recorded in the baseline move to `policy.suppressed` |
| `locked` | list of keys, or `all` | organisation only; see below |
| `allow_project_policy` | bool | organisation only; `false` makes every project file tighten-only |
| `llm_review` | bool | run the optional LLM review stage on `sigil scan` (as `--llm-review`); `true` takes effect from the organisation policy or a `--config` file, not a discovered `.sigil.yml`; see [llm-review.md](llm-review.md) |
| `llm_may_downgrade` | bool | let a model's dismissal lower a finding by one level; never a Critical, prompt-injection or agent-manipulation finding, or a finding in a file that addresses the reviewer |
| `llm_provider` | `anthropic`/`openai-compatible` | which API the stage speaks (default: Anthropic, or OpenAI-compatible when an endpoint is set) |
| `llm_model` | model id | the model (as `--llm-model`) |
| `llm_endpoint` | URL | organisation only; the OpenAI-compatible endpoint the stage sends code to (`https`, or `http` to localhost) |
| `llm_max_calls` | 1–1000 | per-scan cap on requests (default 25) |
| `llm_max_tokens` | 10,000–10,000,000 | per-scan cap on input + output tokens (default 200,000) |

The LLM keys cannot be set by a policy file inside a tree scanned from
outside it: such a file may only set `llm_may_downgrade: false`. A project
file found by discovery cannot turn the stage on, raise `llm_max_calls` or
`llm_max_tokens`, or choose `llm_provider` or `llm_model`, even when you work
inside its tree: that takes `--llm-review`, `--llm-model`, the environment
(`SIGIL_LLM_ENDPOINT`, `SIGIL_LLM_MODEL`), the organisation policy, or naming
the file with `--config`, because the stage sends code off the machine on the
API key of whoever runs the scan. A locked
`llm_review`, `llm_provider` or `llm_model` is fixed at the organisation's
value, a locked `llm_may_downgrade` can only be switched off, and locked caps
can only be lowered. API keys are read from the environment only.

Validation is strict: an unknown key, a misspelt severity, a URL where a host
name belongs, or a single-label trusted domain such as `com` is an error
naming the file and key, with a "did you mean" where one fits. Check a
file without scanning with `sigil config --validate FILE` (`--org` for an
organisation file). `sigil config --policy` prints the effective policy for
the current directory, and `sigil scan -v` prints which files applied.

**Suppressed is not deleted.** Every finding a policy takes out of the
verdict stays in the report: in `policy.suppressed` in JSON (with
`suppressed_by` naming the file and key), as SARIF results with
`suppressions[].kind = "external"`, as skipped JUnit test cases, and counted
in the text and Markdown summaries. Score, verdict and exit code are computed
without them.

**Locked keys** (organisation policy). A project file or flag may lower a
locked `fail_on`, `fail_on_verdict` or `min_severity` and may raise
severities, but may not add to a locked `disable_rules`, `ignore_paths`,
`trusted_domains` or `rule_packs`, set a locked `baseline`, or loosen a value.
Refusals are warnings on stderr and entries in `policy.refused`. Locking the
gate (`fail_on`, `fail_on_verdict`) is not enough on its own: every unlocked
key among `min_severity`, `severity_overrides`, `baseline`, `disable_rules`,
`ignore_paths`, `trusted_domains` and `llm_may_downgrade` can still take
findings out from under it. `sigil config --validate FILE --org` lists each
one; `locked: [all]` closes them all.

**The scanned-tree guard.** A project file found in the scan root is trusted
only when you run Sigil from inside that tree. Scanning a tree from outside
applies its policy tighten-only (exactly as a fully locked policy), because a
policy shipped inside code you are auditing is part of what is being audited.
Such a file that does not load (malformed YAML, unknown key) is set aside
with a refusal instead of stopping the scan, so a tree cannot keep Sigil from
reporting on it by shipping a broken one; your own policy file, or one named
with `--config`, still fails the run with exit `2`.
Pass `--config <file>` to vouch for it. `sigil clone`/`pip`/`npm` never read
a policy from quarantined content; they apply only the organisation and
`--config` rule packs.

**Sigil's own files.** Findings in the trusted policy file and in the
baselines in use (for example the hidden-file rule firing on `.sigil.yml`, or
a rule matching the text a baseline `message` glob quotes) are suppressed with
kind `config_file`, so adopting a policy or a baseline adds no findings of
its own. A Critical finding is never excused this way: a prompt injection
written into a `.sigil.yml` comment is reported like anywhere else. To quote
a Critical pattern in a baseline, add a `sigil:ignore` marker for it.

## Custom rules

`--rules PATH` (repeatable, a file or a directory) and a policy's
`rule_packs` add rule packs in JSON or YAML, and YARA rule files (`.yar`,
`.yara`; see [YARA rules](enterprise.md#yara-rules)). Two JSON/YAML shapes are
accepted: the full pack schema used by `cli/packs/core/v1/`, and a compact
form:

```yaml
pack: {id: acme-rules, name: ACME rules, version: 1.0.0}   # optional
rules:
  - id: ACME-001                  # PREFIX-NAME; must not reuse any existing id
    pattern: 'internal-artifacts\.acme\.example'   # Rust regex, matched per line
    severity: high                # low | medium | high | critical
    description: Reference to the internal artifact mirror
    phase: code_patterns          # optional, default code_patterns
    extensions: [py, js]          # optional file filter
    files: [setup.py]             # optional exact file names
    suffixes: [.mcp.json]         # optional file-name suffixes
    exclude_paths: [tests/]       # optional: skip paths containing these
    exclude_lines: ["# example"]  # optional: skip lines containing these
    remediation: What a reviewer should check.
    references: [CWE-200]
    tags: [data-leak]
    weight: 5                     # optional, default the phase weight; at most 100
```

Custom packs only add rules: a pack id or rule id that already exists is
refused. A pattern that does not compile, matches the empty string, or names
an unknown phase or severity is an error, with every problem listed. When
`SIGIL_PACK_PUBLIC_KEY` is set, custom packs must be signed (`sigil rules
sign`), exactly like packs in `~/.sigil/packs/`.

| Command | Does |
|---|---|
| `sigil rules list [--json] [--phase P]` | every active rule, with origin (`embedded`, `released`, `user`, `custom`) and what the scan policy does to it |
| `sigil rules show ID` | one rule: pattern, filters, suppressions, remediation, references, policy status |
| `sigil rules validate PATH` | check a pack; exit 0 valid, 1 invalid, 2 unreadable |
| `sigil rules test PACK TARGET` | run only that pack over a file or directory and print matches |
| `sigil rules sign PACK --key KEY` | validate, convert and sign; writes JSON to `-o` or stdout |

## Baselines

```bash
sigil baseline . [--reason TEXT] [-o FILE]   # default ./.sigil-baseline.json
sigil scan . --baseline .sigil-baseline.json  # or `baseline:` in .sigil.yml
```

`sigil baseline` runs the same scan as `sigil scan` (with the policy's
suppressions applied) and records every active finding by fingerprint and a
hash of the matched text. A later scan moves matching findings to
`policy.suppressed`; each entry matches one finding, line numbers are
ignored, and entries that no longer match are reported as stale. Hand-written
glob rules (`rule`, `path`, `message`, mandatory `reason`, optional `expires`)
can live in the same file; see [schemas.md](schemas.md#baseline-file). A
`sigil scan -f json` report is also accepted as a baseline.

## Report formats and `--output`

| `-f/--format` | Use |
|---|---|
| `text` (default) | terminal |
| `json` | the stable machine contract (ADR-0010); adds a `policy` block when a policy is active |
| `sarif` | SARIF 2.1.0 for GitHub code scanning and IDEs |
| `html` | one self-contained page |
| `markdown` / `md` | pull-request comments and CI job summaries |
| `junit` | CI test reports: one test case per finding, failures at or above `fail_on`, suppressed findings skipped |

`-o/--output FILE` writes the report to a file instead of stdout (text is
then written without colour). An unknown format is an error (exit `2`).

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
