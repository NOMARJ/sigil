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

**Homebrew (macOS/Linux):**
```bash
brew tap nomarj/tap
brew install sigil
```

**npm (All platforms):**
```bash
npm install -g @nomark/sigil
```

**Cargo (Rust):**
```bash
cargo install sigil
```

**curl installer:**
```bash
curl -sSL https://sigilsec.ai/install.sh | sh
```

**Docker:**
```bash
docker pull nomark/sigil:latest
docker run --rm -v $(pwd):/workspace nomark/sigil scan .
```

[**→ See all installation methods**](docs/installation.md)

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  You run a   │────▶│  Sigil       │────▶│  Clean?      │
│  command     │     │  quarantines │     │  Approve.    │
│              │     │  & scans     │     │  Dirty?      │
│  gclone      │     │              │     │  Reject.     │
│  safepip     │     │  6 phases.   │     │              │
│  safenpm     │     │  <3 seconds. │     │  You decide. │
└──────────────┘     └──────────────┘     └──────────────┘
```

Sigil runs **six analysis phases** on every scan:

| Phase | What It Catches |
|-------|----------------|
| **Install Hooks** | `setup.py` cmdclass, npm `postinstall`, Makefile targets that execute on install |
| **Code Patterns** | `eval()`, `exec()`, `pickle.loads`, `child_process`, dynamic imports |
| **Network / Exfil** | Outbound HTTP, webhooks, socket connections, DNS tunnelling |
| **Credentials** | ENV var access, `.aws`, `.kube`, SSH keys, API key patterns |
| **Obfuscation** | Base64 decode, charCode, hex encoding, minified payloads |
| **Provenance** | Git history depth, author count, binary files, hidden files |

Each finding is weighted and scored. You get a clear verdict:

| Score | Verdict | What Happens |
|-------|---------|-------------|
| 0 | **CLEAN** | Auto-approve (configurable) |
| 1–9 | **LOW RISK** | Approve with review |
| 10–24 | **MEDIUM RISK** | Manual review required |
| 25–49 | **HIGH RISK** | Blocked, requires override |
| 50+ | **CRITICAL** | Blocked, no override |

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

# Download and scan any URL
sigil fetch https://example.com/agent-tool.tar.gz

# Manage quarantine
sigil list              # See all quarantined items
sigil approve abc123    # Move approved code out of quarantine
sigil reject abc123     # Permanently delete quarantined code
```

### Shell Aliases

After running `sigil install`, these aliases are available in every terminal session. Use the commands you already know — Sigil protects you automatically:

| Alias | What It Does |
|-------|-------------|
| `gclone <url>` | `git clone` with quarantine + scan |
| `safepip <pkg>` | `pip install` with scan first |
| `safenpm <pkg>` | `npm install` with scan first |
| `safefetch <url>` | Download + quarantine + scan |
| `audithere` | Scan current directory |
| `qls` | Quarantine status |
| `qapprove` / `qreject` | Approve or reject most recent item |

### Git Hooks

```bash
# Auto-scan any repo on clone (global git hook)
sigil install --git-hooks
```

## IDE & Agent Integrations

Sigil works where you work. Install the plugin for your editor, or connect AI agents via MCP:

| Integration | Coverage | Install |
|-------------|----------|---------|
| **VS Code / Cursor / Windsurf** | Scan workspace, files, selections, packages. Findings in Problems panel. | [plugins/vscode](plugins/vscode/) |
| **JetBrains IDEs** | IntelliJ, WebStorm, PyCharm, GoLand, CLion, etc. Tool window + inline annotations. | [plugins/jetbrains](plugins/jetbrains/) |
| **Claude Code Plugin** | 4 skills + 2 security agents. Auto-suggests scans on clone/install. | [plugins/claude-code](plugins/claude-code/) |
| **Claude Code (MCP)** | 6 tools: scan, scan_package, clone, quarantine, approve, reject. | [plugins/mcp-server](plugins/mcp-server/) |
| **GitHub Actions** | Run Sigil as a CI check on every PR. | [action.yml](action.yml) |

### Claude Code Plugin (Recommended)

Install as a native Claude Code plugin for skills, agents, and auto-recommendations:

```bash
# Add Sigil marketplace
claude plugin marketplace add https://github.com/NOMARJ/sigil.git

# Install the plugin
claude plugin install sigil-security@sigil
```

This provides:
- `/sigil-security:scan-repo` - Scan repositories
- `/sigil-security:scan-package` - Audit npm/pip packages
- `/sigil-security:scan-file` - Analyze specific files
- `/sigil-security:quarantine-review` - Manage findings
- `@security-auditor` - Expert threat analysis agent
- `@quarantine-manager` - Quarantine workflow agent

[**→ See Claude Code plugin documentation**](plugins/claude-code/README.md)

### Claude Code MCP Server

Alternatively, use the MCP server for tool-based integration:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["/path/to/sigil/plugins/mcp-server/dist/index.js"]
    }
  }
}
```

Build the MCP server first:

```bash
cd plugins/mcp-server && npm install && npm run build
```

`npx @nomark/sigil-mcp-server` will be available once the package is published to npm.

## Threat Intelligence

When authenticated (`sigil login`), Sigil connects to a **community-powered threat intelligence database**. Every scan from every user contributes anonymised pattern data. When someone flags a malicious package, the threat signature propagates to all users within minutes.

No source code is ever transmitted — only pattern match metadata (which rules triggered, file types, risk scores).

**Offline mode:** All six scan phases run locally without authentication. Threat intelligence lookups are skipped, but you still get full local analysis.

```bash
# Authenticate to enable threat intel
sigil login
```

**[Learn more about authentication →](docs/authentication-guide.md)**

## Why Not [Existing Tool]?

| Capability | Sigil | Aardvark/Codex | Claude Code | Snyk | Semgrep |
|-----------|-------|----------------|-------------|------|---------|
| **Pre-install quarantine** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Supply-chain attacks** | ✅ Primary | ⚠️ Limited | ⚠️ Limited | ⚠️ CVEs | ❌ |
| **Install hook scanning** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Malware analysis** | ⚠️ Patterns | ✅ Dedicated | ⚠️ Context | ❌ | ❌ |
| **AI-powered analysis** | ❌ | ✅ GPT-5 | ✅ Claude | ⚠️ Limited | ❌ |
| **Deep vuln scanning** | ⚠️ Patterns | ✅ 92% recall | ✅ Primary | ✅ | ✅ |
| **Auto-patching** | ❌ | ✅ Codex | ✅ AI patches | ⚠️ Limited | ❌ |
| **AI agent / MCP focus** | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Multi-ecosystem** | ✅ All | ✅ | ✅ | ✅ | ✅ |
| **Free tier** | ✅ Full | Private beta | Waitlist | Limited | OSS |

**The Complete Stack:**
- **Sigil** (Layer 1): Quarantine-first *before* code enters your environment (supply-chain protection)
- **Aardvark/Codex Security** (Layer 2): Deep AI analysis *after* code is committed (GPT-5 powered)
- **Claude Code Security** (Layer 2): Deep AI analysis *after* code is committed (Claude powered)

**Positioning:**
- Aardvark and Claude Code Security compete (both do deep vulnerability scanning)
- Sigil complements both (different layer: pre-install vs post-commit)
- **Use Sigil + (Aardvark OR Claude Code Security)** for complete coverage

[**→ See complete integration guide**](docs/ai-security-stack-integration.md)

Snyk and Dependabot flag known CVEs — they don't scan for intentional malice. Socket.dev is npm-only. Semgrep is a pattern engine, not a workflow. **The AI security stack (Sigil + Aardvark/Claude Code Security) provides defense-in-depth.**

## Pricing

The CLI is **free and open source** with all six scan phases. Paid tiers add cloud-backed threat intelligence, scan history, team management, and CI/CD integration.

| | Open Source | Pro — $29/mo | Team — $99/mo |
|---|-----------|-------------|--------------|
| Full CLI scanning | ✅ | ✅ | ✅ |
| Cloud threat intelligence | — | ✅ | ✅ |
| Scan history | — | 90 days | 1 year |
| Web dashboard | — | ✅ | ✅ |
| Team management & policies | — | — | Up to 25 seats |
| CI/CD integration | — | — | ✅ |
| Slack / webhook alerts | — | — | ✅ |

[See full pricing →](https://sigilsec.ai/pricing)

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

**Getting Started:**
- [Getting Started Guide](docs/getting-started.md) — Installation and first scan
- [CLI Reference](docs/cli.md) — All commands and options
- [Authentication Guide](docs/authentication-guide.md) — Connect to Sigil Pro ⭐ **NEW**
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
- [AI Security Stack](docs/ai-security-stack-integration.md) — Sigil + Aardvark + Claude Code Security ⭐ **NEW**
- [Claude Code Security Integration](docs/claude-code-security-integration.md) — Defense-in-depth with Anthropic
- [AI Agent Integration](docs/ai-agent-integration.md) — Claude Code, MCP, and other AI agents

**Security Research:**
- [Case Study: OpenClaw Attack](docs/CASE-STUDY-OPENCLAW-ATTACK.md) — Real-world supply chain attack
- [Prompt Injection Patterns](docs/prompt-injection-patterns.md) — Detection techniques
- [Malicious Signatures](docs/malicious-signatures.md) — Threat signature database

[**Browse all documentation →**](docs/README.md)

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full roadmap.

**Today:** Quarantine-first scanning for pip, npm, and git repos. Six-phase behavioral detection. Cloud threat intelligence with community reporting and signature sync. Dashboard with scan history, team management, and policy controls. Rust CLI binary, VS Code / Cursor / Windsurf extension (`.vsix`), JetBrains plugin, MCP server for AI agents, and GitHub Actions integration.

**Now:** Hosted cloud — sign up and scan without running infrastructure.

**Next:** Homebrew tap and npm package. Docker image and Go/Cargo scanning. VS Code Marketplace and JetBrains Marketplace listings. Custom scan rules via YAML. Enterprise SSO, RBAC, and audit logs. GitLab, Jenkins, and CircleCI integrations.

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
