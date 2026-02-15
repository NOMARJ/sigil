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

```bash
curl -sSL https://sigilsec.ai/install.sh | sh
```

Or via Homebrew:

```bash
brew install nomarj/tap/sigil
```

Or via npm (global):

```bash
npm install -g @nomarj/sigil
```

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
| **Claude Code (MCP)** | 6 tools: scan, scan_package, clone, quarantine, approve, reject. | [plugins/mcp-server](plugins/mcp-server/) |
| **GitHub Actions** | Run Sigil as a CI check on every PR. | [action.yml](action.yml) |

```bash
# MCP server — add to .mcp.json or claude_desktop_config.json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["./plugins/mcp-server/dist/index.js"]
    }
  }
}
```

## Threat Intelligence

When authenticated (`sigil login`), Sigil connects to a **community-powered threat intelligence database**. Every scan from every user contributes anonymised pattern data. When someone flags a malicious package, the threat signature propagates to all users within minutes.

No source code is ever transmitted — only pattern match metadata (which rules triggered, file types, risk scores).

**Offline mode:** All six scan phases run locally without authentication. Threat intelligence lookups are skipped, but you still get full local analysis.

```bash
# Authenticate to enable threat intel
sigil login
```

## Why Not [Existing Tool]?

| Capability | Sigil | Snyk | Socket.dev | Semgrep | CodeQL |
|-----------|-------|------|-----------|---------|--------|
| Quarantine workflow | ✅ | ❌ | ❌ | ❌ | ❌ |
| AI agent / MCP focus | ✅ | ❌ | Partial | ❌ | ❌ |
| Install hook scanning | ✅ | ❌ | ✅ | ❌ | ❌ |
| Credential exfil detection | ✅ | ❌ | Partial | Rules needed | Rules needed |
| Multi-ecosystem (pip, npm, git, URL) | ✅ | ✅ | npm only | Any (rules) | GitHub only |
| Community threat intel | ✅ | Advisory DB | ✅ | Community | ❌ |
| Free tier with full CLI | ✅ | Limited | Limited | OSS free | Public repos |

Snyk and Dependabot flag known CVEs in dependency trees — they don't scan source code for intentional malice. Socket.dev is npm-only. Semgrep is a pattern engine, not an end-to-end workflow. CodeQL requires GitHub hosting. **None of them quarantine code before it runs.**

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

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full development plan.

**Delivered:** CLI (bash + Rust), 6-phase scanner, shell aliases, git hooks, FastAPI backend, Next.js dashboard, IDE plugins (VS Code, JetBrains, MCP server), GitHub Action, Docker deployment, SARIF output, scan caching, diff/baseline scanning.

**In progress:** Cloud threat intelligence network, hosted deployment.

**Next:** Distribution (Homebrew, npm, VS Code Marketplace), Docker image scanning, custom scan rules, enterprise SSO, CI/CD platform integrations.

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
