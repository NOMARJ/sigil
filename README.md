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

The AI tooling ecosystem moves fast. Developers clone repos from tutorials, install MCP servers with 12 GitHub stars, and pull agent skills from Discord â€” all of which get direct access to API keys, databases, and cloud credentials. Traditional dependency scanners catch known CVEs but miss the real threat: **intentionally malicious code** designed to exfiltrate credentials, establish backdoors, or execute arbitrary commands via install hooks.

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
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  You run a   â”‚â”€â”€â”€â”€â–¶â”‚  Sigil       â”‚â”€â”€â”€â”€â–¶â”‚  Clean?      â”‚
â”‚  command     â”‚     â”‚  quarantines â”‚     â”‚  Approve.    â”‚
â”‚              â”‚     â”‚  & scans     â”‚     â”‚  Dirty?      â”‚
â”‚  gclone      â”‚     â”‚              â”‚     â”‚  Reject.     â”‚
â”‚  safepip     â”‚     â”‚  6 phases.   â”‚     â”‚              â”‚
â”‚  safenpm     â”‚     â”‚  <3 seconds. â”‚     â”‚  You decide. â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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
| 1â€“9 | **LOW RISK** | Approve with review |
| 10â€“24 | **MEDIUM RISK** | Manual review required |
| 25â€“49 | **HIGH RISK** | Blocked, requires override |
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

After running `sigil install`, these aliases are available in every terminal session. Use the commands you already know â€” Sigil protects you automatically:

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

## Threat Intelligence

When authenticated (`sigil login`), Sigil connects to a **community-powered threat intelligence database**. Every scan from every user contributes anonymised pattern data. When someone flags a malicious package, the threat signature propagates to all users within minutes.

No source code is ever transmitted â€” only pattern match metadata (which rules triggered, file types, risk scores).

**Offline mode:** All six scan phases run locally without authentication. Threat intelligence lookups are skipped, but you still get full local analysis.

```bash
# Authenticate to enable threat intel
sigil login
```

## Why Not [Existing Tool]?

| Capability | Sigil | Snyk | Socket.dev | Semgrep | CodeQL |
|-----------|-------|------|-----------|---------|--------|
| Quarantine workflow | âœ… | âŒ | âŒ | âŒ | âŒ |
| AI agent / MCP focus | âœ… | âŒ | Partial | âŒ | âŒ |
| Install hook scanning | âœ… | âŒ | âœ… | âŒ | âŒ |
| Credential exfil detection | âœ… | âŒ | Partial | Rules needed | Rules needed |
| Multi-ecosystem (pip, npm, git, URL) | âœ… | âœ… | npm only | Any (rules) | GitHub only |
| Community threat intel | âœ… | Advisory DB | âœ… | Community | âŒ |
| Free tier with full CLI | âœ… | Limited | Limited | OSS free | Public repos |

Snyk and Dependabot flag known CVEs in dependency trees â€” they don't scan source code for intentional malice. Socket.dev is npm-only. Semgrep is a pattern engine, not an end-to-end workflow. CodeQL requires GitHub hosting. **None of them quarantine code before it runs.**

## Pricing

The CLI is **free and open source** with all six scan phases. Paid tiers add cloud-backed threat intelligence, scan history, team management, and CI/CD integration.

| | Open Source | Pro â€” $29/mo | Team â€” $99/mo |
|---|-----------|-------------|--------------|
| Full CLI scanning | âœ… | âœ… | âœ… |
| Cloud threat intelligence | â€” | âœ… | âœ… |
| Scan history | â€” | 90 days | 1 year |
| Web dashboard | â€” | âœ… | âœ… |
| Team management & policies | â€” | â€” | Up to 25 seats |
| CI/CD integration | â€” | â€” | âœ… |
| Slack / webhook alerts | â€” | â€” | âœ… |

[See full pricing â†’](https://sigilsec.ai/pricing)

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full development plan.

**Now:** CLI with local scanning, shell aliases, git hooks.
**Next:** Cloud threat intelligence, web dashboard, Pro tier.
**Later:** Team policies, CI/CD gates, marketplace verification API.

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? Please report it responsibly. See [SECURITY.md](SECURITY.md).

## License

Apache 2.0 â€” see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>SIGIL</strong> by <a href="https://nomark.ai">NOMARK</a>
  <br />
  <em>A protective mark for every line of code.</em>
</p>
