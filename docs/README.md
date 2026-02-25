# Sigil Documentation

**Complete guide to securing your AI agent development workflow**

---

## 📚 Documentation Index

### Getting Started

| Document | Description |
|----------|-------------|
| [**Getting Started**](./getting-started.md) | Quick start guide for new users |
| [**CLI Reference**](./cli.md) | Complete command-line interface documentation |
| [**Authentication Guide**](./authentication-guide.md) | Connect CLI to Sigil Pro for cloud threat intelligence |
| [**Configuration**](./configuration.md) | Environment variables, config files, and customization |

### Core Concepts

| Document | Description |
|----------|-------------|
| [**Architecture**](./architecture.md) | System design and component overview |
| [**Detection Patterns**](./detection-patterns.md) | What Sigil scans for and how it works |
| [**Scan Rules**](./scan-rules.md) | Pattern matching rules and severity weights |
| [**Threat Model**](./threat-model.md) | Security threats Sigil is designed to prevent |

### Advanced Usage

| Document | Description |
|----------|-------------|
| [**CI/CD Integration**](./cicd.md) | GitHub Actions, GitLab CI, and pipeline setup |
| [**IDE Plugins**](./ide-plugins.md) | VS Code, Cursor, Windsurf, JetBrains integrations |
| [**MCP Server Integration**](./mcp.md) | Use Sigil as an MCP server for AI agents |
| [**Deployment Guide**](./deployment.md) | Self-hosting the API and dashboard |

### API & Development

| Document | Description |
|----------|-------------|
| [**API Reference**](./api-reference.md) | REST API endpoints and authentication |
| [**Threat Intelligence 2025**](./threat-intelligence-2025.md) | Current threat landscape and detection priorities |
| [**Malicious Signatures**](./malicious-signatures.md) | Community-maintained threat signature database |

### Security Research

| Document | Description |
|----------|-------------|
| [**Prompt Injection Patterns**](./prompt-injection-patterns.md) | Detection and prevention of prompt injection attacks |
| [**Prompt Injection Extension**](./PROMPT-INJECTION-EXTENSION.md) | Advanced prompt injection detection techniques |
| [**Case Study: OpenClaw Attack**](./CASE-STUDY-OPENCLAW-ATTACK.md) | Analysis of a real-world AI agent supply chain attack |

### Support

| Document | Description |
|----------|-------------|
| [**Troubleshooting**](./troubleshooting.md) | Common issues and solutions |

---

## 🚀 Quick Navigation

### I want to...

**Get started with Sigil**
→ [Getting Started](./getting-started.md) → [CLI Reference](./cli.md)

**Understand how it works**
→ [Architecture](./architecture.md) → [Detection Patterns](./detection-patterns.md)

**Connect to Sigil Pro**
→ [Authentication Guide](./authentication-guide.md) ⭐ **NEW**

**Integrate with my CI/CD pipeline**
→ [CI/CD Integration](./cicd.md)

**Use Sigil in my IDE**
→ [IDE Plugins](./ide-plugins.md)

**Deploy my own instance**
→ [Deployment Guide](./deployment.md) → [API Reference](./api-reference.md)

**Learn about threats**
→ [Threat Model](./threat-model.md) → [Case Study: OpenClaw Attack](./CASE-STUDY-OPENCLAW-ATTACK.md)

**Contribute threat signatures**
→ [Malicious Signatures](./malicious-signatures.md)

**Debug an issue**
→ [Troubleshooting](./troubleshooting.md)

---

## 📖 Document Types

### 🟢 User Guides
Documentation for end users installing and using Sigil:
- Getting Started
- CLI Reference
- Authentication Guide
- Configuration
- Troubleshooting

### 🔵 Technical Documentation
Deep dives into architecture and implementation:
- Architecture
- Detection Patterns
- Scan Rules
- Threat Model
- API Reference

### 🟡 Integration Guides
Connect Sigil to your existing tools and workflows:
- CI/CD Integration
- IDE Plugins
- MCP Server Integration
- Deployment Guide

### 🔴 Security Research
Analysis of threats and attack patterns:
- Threat Intelligence 2025
- Malicious Signatures
- Prompt Injection Patterns
- Case Studies

---

## 🔐 Authentication & Pro Features

Sigil works in two modes:

**Free (Offline)** — Local pattern scanning, no account required
- All 6 scan phases
- Built-in threat signatures
- Works 100% offline

**Pro (Cloud-Connected)** — Enhanced threat detection with cloud intelligence
- Hash-based malware lookup
- Auto-updating threat signatures
- Community-reported threats
- Advanced detection patterns

[**Learn how to authenticate →**](./authentication-guide.md)

---

## 🌐 External Resources

- **Website**: [sigilsec.ai](https://sigilsec.ai)
- **GitHub**: [NOMARJ/sigil](https://github.com/NOMARJ/sigil)
- **Issues**: [Report a bug](https://github.com/NOMARJ/sigil/issues)
- **Security**: security@sigilsec.ai

---

## 📝 Contributing to Documentation

Found an error or want to improve these docs?

1. Fork the repository
2. Edit the relevant `.md` file in `docs/`
3. Submit a pull request

See [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for guidelines.

---

## 🗂️ Internal Documentation

Internal team documentation (deployment guides, infrastructure details) is maintained separately in `docs/internal/` and is **not tracked in git** per the project's documentation policy.

See `docs/internal/README.md` for the internal documentation index (team members only).

---

**Last Updated**: February 2025
