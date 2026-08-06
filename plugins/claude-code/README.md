# Sigil Security Plugin for Claude Code

Automated security auditing for AI agent code directly in Claude Code.

## Features

- **🚧 Enforcement Gate** - PreToolUse hook blocks unscanned installs and clones, routing them through quarantine
- **🔍 Scan Repositories** - Audit entire repos for malicious patterns before cloning
- **📦 Package Auditing** - Check npm and pip packages for supply-chain threats
- **📄 File Analysis** - Scan individual files or code selections
- **🛡️ Quarantine Workflow** - Review and approve/reject findings with risk scores
- **🤖 Security Agents** - Specialized AI agents for threat analysis and quarantine management
- **🔌 Bundled MCP Server** - Registers Sigil's MCP tools automatically on install

## What Gets Scanned?

Sigil analyzes **8 threat categories** with severity weighting:

| Phase                | What It Detects                                                | Severity       |
| -------------------- | -------------------------------------------------------------- | -------------- |
| **Install Hooks**    | `setup.py` cmdclass, npm `postinstall`, Makefile targets       | Critical (10x) |
| **Code Patterns**    | `eval()`, `exec()`, `pickle`, `child_process`, dynamic imports | High (5x)      |
| **Network/Exfil**    | Outbound HTTP, webhooks, socket connections, DNS tunneling     | High (3x)      |
| **Credentials**      | ENV var access, API keys, SSH keys, AWS credentials            | Medium (2x)    |
| **Obfuscation**      | Base64 decode, charCode, hex encoding, minified payloads       | High (5x)      |
| **Provenance**       | Shallow git history, binary files, hidden files, author count  | Low (1-3x)     |
| **Prompt Injection** | AI agent instruction injection in code, docs, tool descriptions | Critical (10x) |
| **Skill Security**   | MCP permission escalation, over-broad agent tool grants        | High (5x)      |

## Risk Scoring

| Score | Verdict         | Action                      |
| ----- | --------------- | --------------------------- |
| 0     | **CLEAN**       | Auto-approve (configurable) |
| 1–9   | **LOW RISK**    | Approve with review         |
| 10–24 | **MEDIUM RISK** | Manual review required      |
| 25–49 | **HIGH RISK**   | Blocked, requires override  |
| 50+   | **CRITICAL**    | Blocked, no override        |

## Installation

### Prerequisites

1. **Sigil CLI must be installed:**

```bash
# Homebrew (macOS/Linux)
brew tap nomarj/tap
brew install sigil

# npm (macOS/Linux)
npm install -g @nomarj/sigil

# Cargo (Rust)
cargo install sigil-cli

# curl installer
curl -fsSLO https://www.sigilsec.ai/install.sh && sh install.sh
```

2. **Claude Code 1.0.33+**

### Install Plugin

**Option 1: From GitHub (Recommended)**

```bash
# Add Sigil marketplace
claude plugin marketplace add NOMARJ/sigil

# Install the plugin
claude plugin install sigil-security@sigil-marketplace
```

**Option 2: Local Development**

```bash
# Clone the repo
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Install locally
claude plugin install ./plugins/claude-code
```

**Option 3: Direct Path**

```bash
# Point Claude Code to the plugin directory
claude --plugin-dir /path/to/sigil/plugins/claude-code
```

## Usage

### Skills (Invoke with `/`)

The plugin provides 6 skills for security scanning and remediation:

#### 1. Scan Repository

```
/sigil-security:scan-repo /path/to/repo
```

Audits an entire repository for malicious patterns across all files.

**Example:**

```
/sigil-security:scan-repo ~/projects/untrusted-mcp-server
```

#### 2. Scan Package

```
/sigil-security:scan-package <package-name>
```

Downloads and scans an npm or pip package before installation.

**Examples:**

```
/sigil-security:scan-package lodash
/sigil-security:scan-package requests
```

#### 3. Scan File

```
/sigil-security:scan-file /path/to/file.py
```

Analyzes a specific file for security vulnerabilities.

**Example:**

```
/sigil-security:scan-file ./src/agent/tools.ts
```

#### 4. Quarantine Review

```
/sigil-security:review-quarantine
```

Reviews all quarantined items and helps decide whether to approve or reject.

#### 5. Fix Finding

```
/sigil-security:fix-finding
```

Analyzes a Sigil scan finding and proposes a code fix with explanation. Provide a finding from scan output, a file path and line number, or a description of the security issue.

**Example:**

```
/sigil-security:fix-finding Phase 2 finding in src/agent/tools.py line 42: eval() usage
```

#### 6. Generate Policy

```
/sigil-security:generate-policy /path/to/project
```

Generates a Sigil sandbox policy YAML (`sigil-policy.yaml`) from scan results. The policy controls filesystem, network, process, and credential access for sandboxed agent execution.

**Example:**

```
/sigil-security:generate-policy ~/projects/my-mcp-server
```

### Agents

The plugin includes 2 specialized security agents:

#### 🔍 security-auditor

Expert security auditor for analyzing Sigil scan results and identifying threats.

**When to use:**

- Analyzing scan findings
- Understanding risk scores
- Getting remediation recommendations
- Assessing false positives

**Invoke with:**

```
@security-auditor analyze these scan results
```

#### 🛡️ quarantine-manager

Manages the quarantine workflow and guides approval/rejection decisions.

**When to use:**

- Reviewing quarantined items
- Making approve/reject decisions
- Understanding quarantine status
- Coordinating multi-finding reviews

**Invoke with:**

```
@quarantine-manager review the latest quarantine
```

### Enforcement Gate (PreToolUse Hook)

The plugin enforces the quarantine-first workflow, it doesn't just suggest it. A PreToolUse hook (`hooks/sigil-guard.sh`) inspects every Bash command Claude Code is about to run and applies this policy:

| Command pattern                                                        | Decision | Why                                                          |
| ---------------------------------------------------------------------- | -------- | ------------------------------------------------------------ |
| `git clone`, `gh repo clone`                                            | **deny** | Use `sigil clone <url>` — quarantine + scan first            |
| `npm install <pkg>`, `npm add`, `yarn add`, `pnpm add`                  | **deny** | Use `sigil npm <pkg>`                                        |
| `pip install <pkg>`, `uv add`                                           | **deny** | Use `sigil pip <pkg>`                                        |
| `cargo install/add`, `gem install`, `go install/get`                    | **deny** | Quarantine + scan the source with `sigil clone` first        |
| `curl \| sh` / `wget \| bash`                                           | **deny** | Piping a download into a shell executes unscanned code       |
| Bare lockfile restores (`npm install`, `npm ci`, `pip install -r`, `bundle install`) | **ask**  | Lockfile deps can still run install scripts — confirm trust  |
| One-shot runners (`npx`, `dlx`, `pipx run`)                             | **ask**  | Downloads and executes in one step with no scan              |
| Everything else                                                         | allow    |                                                              |

**Escape hatches:**

- `SIGIL_BYPASS=1 <command>` — allow a single command through the gate
- `SIGIL_GUARD_MODE=advise` — downgrade every deny to ask (advisory mode)
- `SIGIL_GUARD_MODE=off` — disable the gate entirely
- `SIGIL_GUARD_MODE=enforce` — the default

### SessionStart Check

A SessionStart hook verifies the `sigil` binary is available when a session begins. If it's missing, Claude Code is told how to install it instead of failing mid-task.

### Advisory Prompts

UserPromptSubmit hooks additionally suggest Sigil skills when you mention "clone", "install", "package", "security", "scan", or "malware" in a prompt.

### Bundled MCP Server

Installing the plugin also registers Sigil's MCP server (`npx -y @nomark/sigil-mcp-server`), giving Claude Code direct tool access to scanning, quarantine management, and the public scan database. See [docs/mcp.md](../../docs/mcp.md) for the full tool reference.

## Examples

### Scan a Suspicious MCP Server

```
User: I want to install this MCP server from GitHub: https://github.com/someone/cool-mcp

Claude: Before installing, let me scan this with Sigil for security threats.

/sigil-security:scan-repo https://github.com/someone/cool-mcp

[Sigil scans the repository]

🔍 SCAN RESULTS: HIGH RISK

Risk Score: 32 / 100
Threat Level: HIGH

📋 Findings:
1. Install Hook Detected - npm postinstall script executes on install
   Location: package.json:15
   Severity: 10x (CRITICAL)

2. Network Exfiltration - HTTP POST to unknown endpoint
   Location: src/index.ts:47
   Severity: 3x (HIGH)

💡 Analysis:
The postinstall hook executes immediately when you run `npm install`,
sending data to an external server. This is a common supply-chain attack pattern.

✅ Recommendations:
- DO NOT APPROVE this package
- Find an alternative MCP server from a trusted source
- Report this package to the maintainer if it's a known repository

🛡️ Decision: REJECT

Would you like me to suggest alternative MCP servers?
```

### Review a Clean Package

````
User: Can I safely install the requests library?

Claude: Let me scan it first to confirm it's safe.

/sigil-security:scan-package requests

[Sigil scans the package]

🔍 SCAN RESULTS: CLEAN

Risk Score: 0 / 100
Threat Level: CLEAN

📋 Findings:
No security threats detected.

💡 Analysis:
The requests library is a well-maintained, widely-used HTTP library
from the Python community. No malicious patterns found.

✅ Recommendations:
- 8/8 phases passed — no findings detected
- Official PyPI package
- 50M+ downloads/month, trusted maintainer

🛡️ Decision: APPROVE

You can install with:
```bash
pip install requests
````

```

### Quarantine Management

```

User: What's in my quarantine right now?

Claude: Let me check your quarantine status.

/sigil-security:review-quarantine

@quarantine-manager

[Quarantine Manager lists items]

📦 QUARANTINE REVIEW

3 items currently quarantined:

1. **suspicious-ai-toolkit** (npm)
   Scan ID: abc123
   Risk Score: 45 / 100 (HIGH)
   Findings: Install hook + eval usage

2. **helper-utils** (pip)
   Scan ID: def456
   Risk Score: 12 / 100 (MEDIUM)
   Findings: Base64 encoding detected

3. **github.com/user/agent-tool** (git)
   Scan ID: ghi789
   Risk Score: 3 / 100 (LOW)
   Findings: Single HTTP request in tests

🎯 Recommendations:

- abc123 (suspicious-ai-toolkit): REJECT - Multiple critical threats
- def456 (helper-utils): REVIEW - Likely false positive (base64 is common)
- ghi789 (agent-tool): APPROVE - Low risk, HTTP in test suite

Commands:

```bash
sigil reject abc123
sigil approve def456  # after reviewing code
sigil approve ghi789
```

Would you like me to analyze any specific item in detail?

````

## Configuration

### Enforcement Mode

The PreToolUse gate is controlled with environment variables — no settings file required:

```bash
SIGIL_GUARD_MODE=enforce   # default: deny risky installs/clones
SIGIL_GUARD_MODE=advise    # every deny becomes an ask
SIGIL_GUARD_MODE=off       # disable the gate
SIGIL_BYPASS=1 <command>   # allow one specific command through
```

### Auto-Approve Threshold

Configure in your Sigil CLI settings (`~/.sigil/config.yaml`):

```yaml
quarantine:
  auto_approve_threshold: 0 # Only auto-approve CLEAN (0)
  # auto_approve_threshold: 9  # Auto-approve CLEAN and LOW (0-9)
```

## Troubleshooting

### "Sigil command not found"

The Sigil CLI must be installed first. See [Installation](#prerequisites).

```bash
# Verify installation
which sigil
sigil --version
```

### Skills not showing up

Verify plugin installation:

```bash
claude plugin list
```

Should show:

```
sigil-security@1.1.0 (enabled)
```

### Hooks not triggering

Check Claude Code version:

```bash
claude --version
```

Requires Claude Code 1.0.33 or later.

## More Information

- **Sigil Documentation**: [github.com/NOMARJ/sigil](https://github.com/NOMARJ/sigil)
- **Detection Patterns**: [docs/detection-patterns.md](https://github.com/NOMARJ/sigil/blob/main/docs/detection-patterns.md)
- **Threat Intelligence**: [docs/threat-intelligence-2025.md](https://github.com/NOMARJ/sigil/blob/main/docs/threat-intelligence-2025.md)
- **Case Studies**: [docs/CASE-STUDY-OPENCLAW-ATTACK.md](https://github.com/NOMARJ/sigil/blob/main/docs/CASE-STUDY-OPENCLAW-ATTACK.md)

## Support

- **GitHub Issues**: [github.com/NOMARJ/sigil/issues](https://github.com/NOMARJ/sigil/issues)
- **Website**: [sigilsec.ai](https://sigilsec.ai)
- **Email**: team@sigilsec.ai

## License

Apache 2.0 — See [LICENSE](../../LICENSE) for details.

---

**SIGIL** by [NOMARK](https://nomark.ai)
_A protective mark for every line of code._
