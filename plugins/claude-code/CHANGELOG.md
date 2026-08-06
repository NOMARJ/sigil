# Changelog

All notable changes to the Sigil Security plugin for Claude Code will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-06

### Added
- PreToolUse enforcement gate (`hooks/sigil-guard.sh`): blocks `git clone`, `npm install <pkg>`, `pip install <pkg>`, `cargo`/`gem`/`go` installs, and curl-pipe-to-shell in Claude Code sessions, redirecting to Sigil's quarantine-first equivalents. Lockfile restores and one-shot runners (`npx`, `dlx`, `pipx run`) prompt for confirmation instead
- Escape hatches for the gate: `SIGIL_BYPASS=1` (single command) and `SIGIL_GUARD_MODE=enforce|advise|off`
- SessionStart hook (`hooks/session-setup.sh`) that checks the `sigil` binary is available and surfaces install instructions when it is missing
- Automatic MCP server registration: installing the plugin now registers `@nomark/sigil-mcp-server` via `mcpServers` in the plugin manifest

### Changed
- Skills now invoke `sigil` from PATH instead of the repo-relative `./bin/sigil`, so they work in any project directory
- `scan-file` skill gained `name` and `allowed-tools` frontmatter matching the other skills
- `security-auditor` agent and plugin documentation updated to cover all 8 scan phases, adding Prompt Injection (Critical 10x) and Skill Security (High 5x)

## [1.0.0] - 2026-02-22

### Added
- Initial release of Sigil Security plugin for Claude Code
- Four security scanning skills:
  - `scan-repo` - Scan repositories for malicious patterns
  - `scan-package` - Audit npm and pip packages before installation
  - `scan-file` - Analyze specific files for security vulnerabilities
  - `review-quarantine` - Review and manage quarantined findings
- Two specialized security agents:
  - `security-auditor` - Expert threat analysis and remediation guidance
  - `quarantine-manager` - Quarantine workflow coordination
- Automated hooks for security recommendations:
  - Auto-suggest Sigil when user mentions cloning, installing, or security
  - Advisory prompts suggesting quarantine alternatives when `git clone`, `pip install`, or `npm install` appear in a prompt (advisory only — commands were not blocked; enforcement arrived in 1.1.0)
- Comprehensive documentation and usage examples
- Support for all 6 Sigil scan phases:
  - Install Hooks (Critical 10x)
  - Code Patterns (High 5x)
  - Network/Exfiltration (High 3x)
  - Credentials (Medium 2x)
  - Obfuscation (High 5x)
  - Provenance (Low 1-3x)

### Security
- Implements quarantine-first workflow for AI agent code
- Detects supply-chain attacks before code execution
- Risk-based scoring system (CLEAN, LOW, MEDIUM, HIGH, CRITICAL)
- Threat intelligence integration via Sigil CLI

## [Unreleased]

### Planned
- Custom scan rule configuration
- Integration with Sigil Pro dashboard
- Team policy enforcement
- CI/CD integration helpers
- Enhanced false positive detection
