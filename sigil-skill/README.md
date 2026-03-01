# sigil-scan

Automated security auditing for AI agent code. A [skills.sh](https://skills.sh) skill that provides eight-phase threat analysis purpose-built for AI agents.

## What It Does

Sigil scans code before your agent runs it — detecting install hooks, dangerous code patterns, network exfiltration, credential access, obfuscation, provenance issues, prompt injection attacks, and AI skill security threats. It works locally, offline, and across all major AI coding agents.

**This is not a replacement for server-side scanning.** It's an additional layer that catches what server-side providers cannot — scanning at the point of use, on your machine, right before execution.

## Install

```bash
npx skills add nomarj/sigil-skill --skill sigil-scan
```

Or for specific agents:

```bash
npx skills add nomarj/sigil-skill -a claude-code -a cursor -a codex
```

Global install (available across all projects):

```bash
npx skills add nomarj/sigil-skill --skill sigil-scan -g
```

## What Gets Scanned

| Phase | Weight | What It Detects |
|-------|--------|-----------------|
| Install Hooks | 10x | setup.py cmdclass, npm postinstall, Makefile install targets |
| Code Patterns | 5x | eval, exec, pickle, child_process, dynamic imports |
| Network/Exfil | 3x | HTTP requests, webhooks, raw sockets, DNS exfiltration |
| Credentials | 2x | ENV var access, hardcoded keys, SSH/AWS credential files |
| Obfuscation | 5x | base64, charCode, hex encoding, string obfuscation |
| Provenance | 1-3x | Hidden files, binaries, shallow clones, suspicious filenames |
| Prompt Injection | 10x | Jailbreaks, instruction overrides, system prompt exfiltration, tool abuse |
| Skill Security | 5x | Malicious skill manifests, MCP server exploits, credential embedding |

## Capabilities

### Scan on Demand
Ask your agent to scan any target — directory, repo URL, package name, or GitHub shorthand:
- "Scan this repo for security issues"
- "Is `owner/repo` safe to use?"
- "Audit this MCP server before I install it"

### Pre-Clone Quarantine
Before cloning a repo or installing a package, the skill intercepts, scans in quarantine, and presents findings before any code reaches your environment.

### Environment Audit
Scans your local environment for exposed credentials — `.env` files with API keys, SSH keys with wrong permissions, secrets leaked in shell history.

### Installed Skills Audit
Scans all skills installed across all your agent directories (`~/.agents/skills/`, `~/.claude/skills/`, `~/.cursor/skills/`, etc.) and reports risk assessments for each.

## Risk Verdicts

| Verdict | Score | Meaning |
|---------|-------|---------|
| LOW RISK | 0-9 | No significant patterns detected |
| MEDIUM RISK | 10-24 | Suspicious patterns warrant review |
| HIGH RISK | 25-49 | Patterns strongly suggest elevated risk |
| CRITICAL RISK | 50+ | Very high concentration of dangerous patterns |

## Requirements

- **Sigil CLI binary** — installed automatically on first use
- macOS (arm64/x64), Linux (x64), or WSL
- Internet required only for initial binary download; all scanning is local and offline

## Supported Agents

Works with all agents that support skills.sh:
- Claude Code
- Cursor
- Codex
- Amp
- Cline
- Gemini CLI
- GitHub Copilot
- Windsurf
- Aider
- OpenCode
- Roo Code
- Continue

## License

Apache-2.0

---

*Sigil provides risk assessments based on automated pattern detection. Risk assessments do not constitute a guarantee of security or a definitive determination of malicious intent.*
