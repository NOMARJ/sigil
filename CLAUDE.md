# Sigil — Development Guide

## Project Overview
Sigil is an automated security auditing CLI for AI agent code. It scans repos, packages, and agent tooling for malicious patterns using a quarantine-first workflow.

## Repository Structure
```
bin/           - CLI tool (bash, will be ported to Rust)
cli/           - Rust CLI source (future)
api/           - Python FastAPI backend service
dashboard/     - Next.js web dashboard
plugins/       - IDE integrations
  vscode/      - VS Code / Cursor / Windsurf extension
  jetbrains/   - IntelliJ / WebStorm / PyCharm plugin
  mcp-server/  - MCP server for Claude Code + AI agents
docs/          - Documentation
.github/       - CI/CD workflows
```

**Infrastructure:** Azure Terraform configurations are maintained in a separate private repository at [NOMARJ/sigil-infra](https://github.com/NOMARJ/sigil-infra) to protect sensitive subscription and deployment details.

## Quick Start
```bash
chmod +x bin/sigil
./bin/sigil help
./bin/sigil scan <path>
```

## Architecture
Three-layer system:
1. **CLI** (Developer Layer) — `bin/sigil` bash script, future Rust binary
2. **API Service** — Python FastAPI for scan engine + threat intel
3. **Dashboard** — Next.js for visibility and team management

## Scan Phases
The scanner runs 6 phases with weighted severity:
1. Install Hooks (Critical 10x) — setup.py, npm postinstall
2. Code Patterns (High 5x) — eval, exec, pickle, child_process
3. Network/Exfil (High 3x) — outbound HTTP, webhooks, sockets
4. Credentials (Medium 2x) — ENV vars, API keys, SSH keys
5. Obfuscation (High 5x) — base64, charCode, hex encoding
6. Provenance (Low 1-3x) — git history, binaries, hidden files

## Testing
```bash
./bin/sigil scan .                    # Self-scan
./bin/sigil clone <test-repo-url>     # Test clone workflow
```

## Key Commands
- `sigil clone <url>` — quarantine + scan git repo
- `sigil pip <pkg>` — download + scan pip package
- `sigil npm <pkg>` — download + scan npm package
- `sigil scan <path>` — scan existing directory
- `sigil approve/reject <id>` — manage quarantine
