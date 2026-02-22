# Changelog

All notable changes to the Sigil Security plugin for Claude Code will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-22

### Added
- Initial release of Sigil Security plugin for Claude Code
- Four security scanning skills:
  - `scan-repo` - Scan repositories for malicious patterns
  - `scan-package` - Audit npm and pip packages before installation
  - `scan-file` - Analyze specific files for security vulnerabilities
  - `quarantine-review` - Review and manage quarantined findings
- Two specialized security agents:
  - `security-auditor` - Expert threat analysis and remediation guidance
  - `quarantine-manager` - Quarantine workflow coordination
- Automated hooks for security recommendations:
  - Auto-suggest Sigil when user mentions cloning, installing, or security
  - Intercept `git clone`, `pip install`, `npm install` commands with quarantine alternatives
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
