# Sigil

**Automated Security Auditing for AI Agent Code**

*A protective mark for every line of code.*

By [NOMARK](https://nomark.ai)

---

Sigil scans downloaded repositories, packages, skills, MCP servers, and agent tooling for malicious patterns before they reach your working environment. Nothing runs until it's been scanned, scored, and explicitly approved.

## The Problem

AI developers routinely install MCP servers from GitHub repos with 12 stars, community agent skills from unreviewed marketplaces, and LangChain tools from tutorial blogs. Each carries risks that traditional security tools (Snyk, Dependabot) weren't designed to catch:

- **Install-hook exploitation** — `setup.py` and npm `postinstall` scripts execute code before you've reviewed anything
- **Credential exfiltration** — Agent tooling runs with access to API keys, database URLs, and cloud credentials
- **Obfuscated payloads** — Malicious code hidden behind base64, dynamic imports, and eval chains
- **Supply chain depth** — A simple MCP server can pull 40+ transitive dependencies

## Quick Start

```bash
# Install
chmod +x bin/sigil
sudo cp bin/sigil /usr/local/bin/sigil
sigil install

# Audit a git repo before using it
sigil clone https://github.com/someone/sketchy-mcp-server

# Audit a pip package before installing
sigil pip some-agent-toolkit

# Audit a npm package
sigil npm langchain-community-tool

# Scan a directory you already have
sigil scan ./downloaded-code

# Manage quarantine
sigil list
sigil approve <quarantine-id>
sigil reject <quarantine-id>
```

## How It Works

Sigil uses a **quarantine-first** approach. Code is downloaded into an isolated quarantine directory, scanned across 6 analysis phases, scored, and given a verdict — all before it touches your working environment.

### 6-Phase Scan Engine

| Phase | What It Scans | Weight |
|-------|--------------|--------|
| 1. Install Hooks | `setup.py` cmdclass, npm pre/postinstall, Makefile targets | Critical (10x) |
| 2. Code Patterns | `eval()`, `exec()`, `pickle.loads`, `child_process`, dynamic imports | High (5x) |
| 3. Network/Exfil | Outbound HTTP, webhooks, socket connections, DNS tunnelling | High (3x) |
| 4. Credentials | ENV var access, `.aws`, `.kube`, SSH keys, API key patterns | Medium (2x) |
| 5. Obfuscation | Base64 decode, charCode, hex encoding, minified payloads | High (5x) |
| 6. Provenance | Git history depth, author count, binary files, hidden files | Low (1-3x) |

### Risk Verdicts

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 | **CLEAN** | No findings. Safe to use. |
| 1-9 | **LOW RISK** | Minor findings, likely benign. |
| 10-24 | **MEDIUM RISK** | Patterns that warrant inspection. |
| 25-49 | **HIGH RISK** | Multiple concerning patterns. |
| 50+ | **CRITICAL** | Strong indicators of malicious intent. |

## Shell Aliases

After running `sigil install`, these aliases are available in every terminal:

| Alias | Description |
|-------|-------------|
| `gclone <url>` | Git clone with quarantine audit |
| `safepip <pkg>` | Pip install with scan + approval prompt |
| `safenpm <pkg>` | npm install with scan + approval prompt |
| `safefetch <url>` | Download with quarantine audit |
| `audithere` | Scan current directory |
| `qls` | Show quarantine status |
| `qapprove` / `qreject` | Approve or reject most recent item |

## External Scanners

Sigil's built-in pattern scanner always runs. For deeper analysis, install optional scanners:

```bash
pip install semgrep bandit safety
brew install trufflehog  # macOS
```

Sigil auto-detects and integrates with: **Semgrep**, **Bandit**, **TruffleHog**, **Safety**, **npm audit**.

## Configuration

```bash
# Environment variables
export SIGIL_QUARANTINE_DIR=~/.sigil/quarantine
export SIGIL_APPROVED_DIR=~/.sigil/approved
export SIGIL_LOG_DIR=~/.sigil/logs
export SIGIL_REPORT_DIR=~/.sigil/reports
```

## Architecture

```
DEVELOPER LAYER     CLI Tool  |  Shell Aliases  |  Git Hooks
                         |
API SERVICE LAYER   Scan Engine  |  Threat Intel DB  |  Scoring
                         |
VISIBILITY LAYER    Web Dashboard  |  Audit History  |  Policies
```

## Project Structure

```
bin/           CLI tool (bash — will be ported to Rust)
cli/           Rust CLI source (future)
api/           Python FastAPI backend service
dashboard/     Next.js web dashboard (future)
docs/          Documentation
.github/       CI/CD workflows
```

## Roadmap

- [x] Bash CLI with 6-phase scan engine
- [x] Shell alias installer
- [x] Git pre-commit hook
- [ ] Port CLI to Rust (cross-platform binary)
- [ ] FastAPI cloud service + threat intelligence
- [ ] Next.js web dashboard
- [ ] CI/CD integration (GitHub Action + GitLab CI)
- [ ] Marketplace verification API

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

**SIGIL by NOMARK** — A protective mark for every line of code.
