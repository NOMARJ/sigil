<p align="center">
  <h1 align="center">SIGIL</h1>
  <p align="center"><strong>Automated security auditing for AI agent code</strong></p>
  <p align="center">
    <em>A protective mark for every line of code.</em>
    <br />
    by <a href="https://nomark.ai">NOMARK</a>
  </p>
  <p align="center">
    <a href="https://github.com/NOMARJ/sigil/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
    <a href="https://sigilsec.ai"><img src="https://img.shields.io/badge/website-sigilsec.ai-black" alt="Website"></a>
  </p>
</p>

---

Sigil scans repositories, packages, MCP servers, skills, and agent tooling for malicious patterns **before they reach your working environment**. Nothing runs until it's been scanned, scored, and explicitly approved.

The AI tooling ecosystem moves fast. Developers clone repos from tutorials, install MCP servers with 12 GitHub stars, and pull agent skills from Discord — all of which get direct access to API keys, databases, and cloud credentials. Traditional dependency scanners catch known CVEs but miss the real threat: **intentionally malicious code** designed to exfiltrate credentials, establish backdoors, or execute arbitrary commands via install hooks.

Sigil fills this gap with a **quarantine-first approach**.

## Quick Install

**Install via Script:**

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Run the installer — downloads the prebuilt release binary for your
# platform and wires up the Claude Code integration by default
# (opt out with --no-integrations)
./install.sh

# Optional: add gclone/safepip/safenpm shell aliases
./install.sh --with-aliases
```

**Package managers:**

```bash
# Homebrew (macOS/Linux)
brew install nomarj/tap/sigil

# npm (macOS/Linux)
npm install -g @nomarj/sigil

# Cargo (Rust)
cargo install sigil-cli

# curl installer
curl -fsSLO https://www.sigilsec.ai/install.sh && sh install.sh
```

**Coming Soon:**

- **Docker**: `docker pull nomark/sigil`

> **Note**: The `sigil` package name on crates.io is occupied by an unrelated project. Install the Rust CLI with `cargo install sigil-cli`.

[**→ See all installation methods**](docs/installation.md)

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  You run a   │────▶│  Sigil       │────▶│  Clean?      │
│  command     │     │  quarantines │     │  Approve.    │
│              │     │  & scans     │     │  Dirty?      │
│  gclone      │     │              │     │  Reject.     │
│  safepip     │     │  8 phases.   │     │              │
│  safenpm     │     │  <3 seconds. │     │  You decide. │
└──────────────┘     └──────────────┘     └──────────────┘
```

Sigil runs **eight analysis phases** on every scan (all free; LLM analysis requires Pro):

| Phase                | What It Catches                                                                    | Tier    |
| -------------------- | ---------------------------------------------------------------------------------- | ------- |
| **Install Hooks**    | `setup.py` cmdclass, npm `postinstall`, Makefile targets that execute on install   | Free    |
| **Code Patterns**    | `eval()`, `exec()`, `pickle.loads`, `child_process`, dynamic imports               | Free    |
| **Network / Exfil**  | Outbound HTTP, webhooks, socket connections, DNS tunnelling                        | Free    |
| **Credentials**      | ENV var access, `.aws`, `.kube`, SSH keys, API key patterns                        | Free    |
| **Obfuscation**      | Base64 decode, charCode, hex encoding, minified payloads                           | Free    |
| **Provenance**       | Git history depth, author count, binary files, hidden files                        | Free    |
| **Prompt Injection** | AI agent instruction injection in code, docs, and tool descriptions                | Free    |
| **Skill Security**   | MCP permission escalation, over-broad agent tool grants                            | Free    |
| **🔒 LLM Analysis**  | AI-powered zero-day detection, contextual threat correlation, advanced remediation | **Pro** |

Each finding is weighted and scored. You get a clear verdict:

| Score / Evidence                      | Verdict           | What Happens                                        |
| ------------------------------------- | ----------------- | --------------------------------------------------- |
| 0–9                                   | **LOW RISK**      | No known malicious patterns detected                |
| 10–24                                 | **MEDIUM RISK**   | Suspicious patterns — review before approving       |
| 25+                                   | **HIGH RISK**     | Dangerous patterns — review carefully before use    |
| Any single Critical-severity finding  | **CRITICAL RISK** | Strong malicious indicators — regardless of score   |

CRITICAL is evidence-gated, not score-based: a pile of medium/low heuristics can only ever reach HIGH RISK, but one Critical-severity finding forces a CRITICAL verdict.

## Usage

### Core Commands

```bash
# Clone a repo into quarantine, scan it, get a verdict
sigil clone https://github.com/someone/cool-mcp-server

# Download and scan a pip package before installing
sigil pip some-agent-toolkit

# Download and scan an npm package before installing
sigil npm langchain-community-plugin

# Scan a directory or file already on disk
sigil scan ./downloaded-skill/

# 🔒 Pro: Enhanced LLM-powered scanning (requires authentication)
sigil login                               # browser-based device authorization
sigil scan ./code --enhanced              # AI-powered threat detection
sigil scan ./code --enhanced --verbose    # With detailed output

# Download and scan any URL
sigil fetch https://example.com/agent-tool.tar.gz

# Manage quarantine
sigil list              # See all quarantined items
sigil approve abc123    # Mark trusted: pins the item's digest in the trust ledger
                        # (files stay at ~/.sigil/quarantine/<id>/ — copy them out yourself)
sigil reject abc123     # Permanently delete quarantined code

# Wire Sigil into your tooling
sigil setup claude      # Register the Claude Code plugin (marketplace + install)
sigil setup shell       # Add gclone/safepip/safenpm aliases to your shell rc
sigil setup git         # Install a pre-commit hook (sigil scan --fail-on high)
sigil setup all         # All of the above
```

### Shell Aliases

Aliases are opt-in: run `./install.sh --with-aliases` to append them to your shell rc. Use the commands you already know — Sigil protects you automatically:

| Alias                  | What It Does                       |
| ---------------------- | ---------------------------------- |
| `gclone <url>`         | `git clone` with quarantine + scan |
| `safepip <pkg>`        | `pip install` with scan first      |
| `safenpm <pkg>`        | `npm install` with scan first      |
| `safefetch <url>`      | Download + quarantine + scan       |
| `audithere`            | Scan current directory             |
| `qls`                  | Quarantine status                  |
| `qapprove` / `qreject` | Approve or reject most recent item |

## IDE & Agent Integrations

Sigil works where you work. Install the plugin for your editor, or connect AI agents via MCP:

| Integration                     | Coverage                                                                           | Install                                     |
| ------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------- |
| **VS Code / Cursor / Windsurf** | Scan workspace, files, selections, packages. Findings in Problems panel.           | [plugins/vscode](plugins/vscode/)           |
| **JetBrains IDEs**              | IntelliJ, WebStorm, PyCharm, GoLand, CLion, etc. Tool window + inline annotations. | [plugins/jetbrains](plugins/jetbrains/)     |
| **Claude Code Plugin**          | 6 skills + 2 security agents. Blocks unscanned installs/clones by default.         | [plugins/claude-code](plugins/claude-code/) |
| **Claude Code (MCP)**           | 9 tools: scan, scan_package, clone, quarantine, approve, reject, check_package, search_database, report_threat. | [plugins/mcp-server](plugins/mcp-server/)   |
| **GitHub Actions**              | Run Sigil as a CI check on every PR.                                               | [action.yml](action.yml)                    |

### Claude Code Plugin (Recommended)

Install as a native Claude Code plugin — enforcement, skills, agents, and the MCP server in one step:

```bash
# Add Sigil marketplace
claude plugin marketplace add NOMARJ/sigil

# Install the plugin
claude plugin install sigil-security@sigil-marketplace
```

This provides:

- **Enforcement by default** - a PreToolUse hook blocks `git clone`, `npm install <pkg>`, and `pip install <pkg>` in Claude Code sessions, redirecting them through Sigil's quarantine (bypass per-command with `SIGIL_BYPASS=1`, tune with `SIGIL_GUARD_MODE=enforce|advise|off`)
- **Bundled MCP server** - registered automatically, no separate config
- `/sigil-security:scan-repo` - Scan repositories
- `/sigil-security:scan-package` - Audit npm/pip packages
- `/sigil-security:scan-file` - Analyze specific files
- `/sigil-security:review-quarantine` - Manage findings
- `/sigil-security:fix-finding` - Propose fixes for scan findings
- `/sigil-security:generate-policy` - Generate sandbox policies from scan results
- `@security-auditor` - Expert threat analysis agent
- `@quarantine-manager` - Quarantine workflow agent

[**→ See Claude Code plugin documentation**](plugins/claude-code/README.md)

### MCP Server (Other Agents)

Any MCP-compatible client (Cursor, Windsurf, custom agents) can use Sigil's tools directly:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "npx",
      "args": ["-y", "@nomark/sigil-mcp-server"]
    }
  }
}
```

> **Note**: `@nomark/sigil-mcp-server` v1.3.0 is not yet published to npm — the `npx` config above will work once it is. Until then, build from source (`cd plugins/mcp-server && npm install && npm run build`) and point your MCP client at `node /path/to/sigil/plugins/mcp-server/dist/index.js`.

[**→ See MCP integration guide**](docs/mcp.md)

## Threat Intelligence

When authenticated (`sigil login`), Sigil connects to a **community-powered threat intelligence database**. Every scan from every user contributes anonymised pattern data. When someone flags a malicious package, the threat signature propagates to all users within minutes.

**What gets transmitted depends on how you use Sigil** — see [docs/data-handling.md](docs/data-handling.md) for the exact per-tier breakdown:

- **Offline / unauthenticated (default):** nothing. All eight phases run locally; no network calls, no account.
- **Authenticated threat intel (`sigil login`):** scan submissions include finding metadata (rule IDs, severities, file paths) **and the flagged source lines** (the code excerpts shown in your scan output). Full files are not uploaded.
- **Pro AI investigation:** the relevant source files for a finding are uploaded and shared with an LLM provider to produce the analysis. This is what you are paying for — the AI reads your code. Never enable Pro analysis on code you cannot share.

**Offline mode:** All eight scan phases run locally without authentication. Threat intelligence lookups are skipped, but you still get full local analysis.

```bash
# Authenticate to enable threat intel
sigil login
```

**[Learn more about authentication →](docs/authentication-guide.md)**

## Why Not [Existing Tool]?

| Capability                 | Sigil       | Aardvark/Codex | Claude Code   | Snyk       | Semgrep |
| -------------------------- | ----------- | -------------- | ------------- | ---------- | ------- |
| **Pre-install quarantine** | ✅          | ❌             | ❌            | ❌         | ❌      |
| **Supply-chain attacks**   | ✅ Primary  | ⚠️ Limited     | ⚠️ Limited    | ⚠️ CVEs    | ❌      |
| **Install hook scanning**  | ✅          | ❌             | ❌            | ❌         | ❌      |
| **Malware analysis**       | ⚠️ Patterns | ✅ Dedicated   | ⚠️ Context    | ❌         | ❌      |
| **AI-powered analysis**    | ❌          | ✅ GPT-5       | ✅ Claude     | ⚠️ Limited | ❌      |
| **Deep vuln scanning**     | ⚠️ Patterns | ✅ 92% recall  | ✅ Primary    | ✅         | ✅      |
| **Auto-patching**          | ❌          | ✅ Codex       | ✅ AI patches | ⚠️ Limited | ❌      |
| **AI agent / MCP focus**   | ✅          | ✅             | ✅            | ❌         | ❌      |
| **Multi-ecosystem**        | ✅ All      | ✅             | ✅            | ✅         | ✅      |
| **Free tier**              | ✅ Full     | Private beta   | Waitlist      | Limited    | OSS     |

**The Complete Stack:**

- **Sigil** (Layer 1): Quarantine-first _before_ code enters your environment (supply-chain protection)
- **Aardvark/Codex Security** (Layer 2): Deep AI analysis _after_ code is committed (GPT-5 powered)
- **Claude Code Security** (Layer 2): Deep AI analysis _after_ code is committed (Claude powered)

**Positioning:**

- Aardvark and Claude Code Security compete (both do deep vulnerability scanning)
- Sigil complements both (different layer: pre-install vs post-commit)
- **Use Sigil + (Aardvark OR Claude Code Security)** for complete coverage

[**→ See complete integration guide**](docs/ai-security-stack-integration.md)

Snyk and Dependabot flag known CVEs — they don't scan for intentional malice. Socket.dev is npm-only. Semgrep is a pattern engine, not a workflow. **The AI security stack (Sigil + Aardvark/Claude Code Security) provides defense-in-depth.**

## Detection Accuracy — Measured, Not Marketed

Sigil publishes its measured detection numbers, including the ones that
aren't flattering. Full method and results:
[`evaluation_results/honest_detection_eval.md`](evaluation_results/honest_detection_eval.md).

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged
             malicious npm/PyPI packages) + a 20-package clean control set of
             popular npm/PyPI packages fetched from the live registries.
Sample Size: 351 malicious samples; 20 clean control packages.
Limitations: Dataset has GuardDog selection bias (Datadog's own disclaimer).
             Offline static phases only. Small clean control set.
```

| Metric | Measured |
| --- | --- |
| Recall (malicious detected, any severity) | 96.87% |
| Recall at ≥ High | 90.31% |
| False-positive rate at ≥ High, clean packages, first scan | **70%** |
| FP rate after trust-ledger approval (`sigil approve`) | 0% |
| FP rate at ≥ High with Pro AI adjudication | 30% |

**What this means in practice:** the static phases deliberately over-trigger —
network calls, base64, and env access are dangerous in malware and routine in
legitimate code, and a first scan of a normal package will often come back
MEDIUM or HIGH. That is the designed workflow, not a bug: review the findings,
then `sigil approve` what you trust (drops its findings to zero on re-scan) or
use Pro's false-positive verification to have AI adjudicate them. Recall is
unaffected by ledger approvals (measured `recall_delta = 0`).

## Pricing

The CLI is **free and open source** with all eight scan phases. **Sigil Pro turns your scanner into an AI security consultant.**

|                                    | Open Source | Pro — $29/mo | Team — $99/mo  |
| ---------------------------------- | ----------- | ------------ | -------------- |
| Full CLI scanning                  | ✅          | ✅           | ✅             |
| **🤖 AI Finding Investigation**    | —           | ✅           | ✅             |
| **🔍 False Positive Verification** | —           | ✅           | ✅             |
| **💬 Interactive Security Chat**   | —           | ✅           | ✅             |
| **⚡ Smart Model Routing**         | —           | ✅           | ✅             |
| Monthly AI credits                 | —           | 5,000        | 50,000         |
| Monthly cloud scans                | —           | 500          | 5,000          |
| Cloud threat intelligence          | —           | ✅           | ✅             |
| Scan history                       | —           | 90 days      | 1 year         |
| Web dashboard                      | —           | ✅           | ✅             |
| Team management & policies         | —           | —            | Up to 25 seats |
| CI/CD integration                  | —           | —            | ✅             |
| Slack / webhook alerts             | —           | —            | ✅             |

**Why upgrade?** Transform cryptic security alerts into actionable intelligence. Instead of wondering "Is this real?", get AI-powered explanations, threat assessments, and verification in seconds.

[See full pricing →](https://sigilsec.ai/pricing)

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

**Getting Started:**

- [Getting Started Guide](docs/getting-started.md) — Installation and first scan
- [CLI Reference](docs/cli.md) — All commands and options
- [Authentication Guide](docs/authentication-guide.md) — Connect to Sigil Pro
- [Configuration](docs/configuration.md) — Environment variables and settings

**Technical Deep Dives:**

- [Architecture Overview](docs/architecture.md) — System design
- [Detection Patterns](docs/detection-patterns.md) — What Sigil scans for
- [Threat Intelligence 2025](docs/threat-intelligence-2025.md) — Current threat landscape
- [API Reference](docs/api-reference.md) — REST API endpoints

**Integration Guides:**

- [CI/CD Integration](docs/cicd.md) — GitHub Actions, GitLab CI, etc.
- [IDE Plugins](docs/ide-plugins.md) — VS Code, JetBrains setup
- [MCP Server](docs/mcp.md) — Use Sigil as an MCP tool for AI agents
- [AI Security Stack](docs/ai-security-stack-integration.md) — Sigil + Aardvark + Claude Code Security
- [Claude Code Security Integration](docs/claude-code-security-integration.md) — Defense-in-depth with Anthropic
- [AI Agent Integration](docs/ai-agent-integration.md) — Claude Code, MCP, and other AI agents

**Security Research:**

- [Case Study: OpenClaw Attack](docs/CASE-STUDY-OPENCLAW-ATTACK.md) — Real-world supply chain attack
- [Prompt Injection Patterns](docs/prompt-injection-patterns.md) — Detection techniques
- [Malicious Signatures](docs/malicious-signatures.md) — Threat signature database

[**Browse all documentation →**](docs/README.md)

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

**Today:** Quarantine-first scanning for pip, npm, and git repos. Eight-phase behavioral detection. Cloud threat intelligence with community reporting and signature sync. Dashboard with scan history, team management, and policy controls. Rust CLI binary, VS Code / Cursor / Windsurf extension (`.vsix`), JetBrains plugin, MCP server for AI agents, and GitHub Actions integration.

**Now:** Hosted cloud — sign up and scan without running infrastructure.

**Next:** Docker image and Go/Cargo scanning. VS Code Marketplace and JetBrains Marketplace listings. Custom scan rules via YAML. Enterprise SSO, RBAC, and audit logs. GitLab, Jenkins, and CircleCI integrations.

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? Please report it responsibly. See [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>SIGIL</strong> by <a href="https://nomark.ai">NOMARK</a>
  <br />
  <em>A protective mark for every line of code.</em>
</p>
