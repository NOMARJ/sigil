# Claude Code Plugin Guide

The Sigil Security plugin for Claude Code provides automated security auditing directly in your Claude Code sessions with skills, specialized agents, and auto-recommendations.

## Features

### 🎯 Skills (4)

Invoke security scans with the `/` slash command:

- `/sigil-security:scan-repo` - Scan entire repositories for malicious patterns
- `/sigil-security:scan-package` - Audit npm/pip packages before installation
- `/sigil-security:scan-file` - Analyze specific files or code selections
- `/sigil-security:quarantine-review` - Review and manage quarantine findings

### 🤖 Agents (2)

Specialized security agents for deep analysis:

- `@security-auditor` - Expert threat analysis, risk assessment, and remediation guidance
- `@quarantine-manager` - Quarantine workflow coordination and approval decisions

### 🔔 Hooks

Automatic security recommendations when you:
- Mention "clone", "install", "security", "scan", "package", or "malware"
- Use commands like `git clone`, `pip install`, or `npm install`

Claude Code will suggest using Sigil's quarantine-first workflow.

## Installation

### Prerequisites

**1. Install Sigil CLI**

The plugin requires the Sigil CLI to be installed and available in your PATH:

```bash
# Homebrew (macOS/Linux) - Recommended
brew tap nomarj/tap
brew install sigil

# npm (all platforms)
npm install -g @nomark/sigil

# Cargo (Rust)
cargo install sigil

# curl installer
curl -sSL https://sigilsec.ai/install.sh | sh
```

Verify installation:
```bash
sigil --version
```

**2. Claude Code 1.0.33+**

Check your version:
```bash
claude --version
```

Update if needed:
```bash
claude update
```

### Install Plugin

#### Option 1: From GitHub Marketplace (Recommended)

```bash
# Add the Sigil marketplace
claude plugin marketplace add https://github.com/NOMARJ/sigil.git

# Install the plugin
claude plugin install sigil-security@sigil
```

#### Option 2: From Release Archive

Download the latest release from [GitHub Releases](https://github.com/NOMARJ/sigil/releases):

```bash
# Download latest plugin release
wget https://github.com/NOMARJ/sigil/releases/latest/download/sigil-security-plugin.tar.gz

# Extract
mkdir -p sigil-security-plugin
tar -xzf sigil-security-plugin.tar.gz -C sigil-security-plugin

# Install
claude plugin install ./sigil-security-plugin
```

#### Option 3: Local Development

For development or testing:

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Install from local directory
claude plugin install ./plugins/claude-code
```

### Verify Installation

```bash
# List installed plugins
claude plugin list
```

You should see:
```
sigil-security@1.0.0 (enabled)
```

Test a skill:
```bash
# Start Claude Code
claude

# Try a skill
/sigil-security:scan-repo .
```

## Usage

### Skills

#### Scan Repository

```
/sigil-security:scan-repo /path/to/repo
```

**Examples:**
```
/sigil-security:scan-repo ~/projects/untrusted-mcp-server
/sigil-security:scan-repo https://github.com/someone/cool-tool
/sigil-security:scan-repo .
```

**Output:**
```
🔍 SCAN RESULTS: [VERDICT]

Risk Score: [X] / 100
Threat Level: [CLEAN|LOW_RISK|MEDIUM_RISK|HIGH_RISK|CRITICAL]

📋 Findings:
[Detailed threat analysis]

💡 Analysis:
[Security expert commentary]

✅ Recommendations:
[Action items]

🛡️ Decision: [APPROVE|REJECT|REVIEW]
```

#### Scan Package

```
/sigil-security:scan-package <package-name>
```

**Examples:**
```
/sigil-security:scan-package lodash
/sigil-security:scan-package requests
/sigil-security:scan-package @anthropic/sdk
```

Claude will automatically detect whether it's an npm or pip package and use the appropriate scanner.

#### Scan File

```
/sigil-security:scan-file /path/to/file
```

**Examples:**
```
/sigil-security:scan-file ./src/agent/tools.ts
/sigil-security:scan-file setup.py
```

Analyzes a specific file for:
- Dangerous code patterns (eval, exec, pickle)
- Network access (HTTP, webhooks, sockets)
- Credential exposure (API keys, tokens)
- Code obfuscation (base64, hex, charCode)
- Suspicious imports

#### Review Quarantine

```
/sigil-security:quarantine-review
```

Lists all quarantined items and helps you decide whether to approve or reject each one.

**Output:**
```
📦 QUARANTINE REVIEW

3 items currently quarantined:

1. **package-name** (npm)
   Scan ID: abc123
   Risk Score: 45 / 100 (HIGH)
   Findings: Install hook + eval usage

Commands:
sigil approve abc123
sigil reject abc123
```

### Agents

#### Security Auditor

Invoke for expert security analysis:

```
@security-auditor analyze these scan results
@security-auditor explain this threat pattern
@security-auditor is this a false positive?
```

**Use when:**
- Analyzing scan findings
- Understanding risk scores
- Getting remediation recommendations
- Assessing false positives
- Learning about security patterns

**Example:**
```
User: @security-auditor I got a HIGH risk score for base64 encoding in my config loader. Is this safe?

Security Auditor: Base64 encoding alone isn't necessarily malicious. Let me analyze the context...

[Examines the code]

In your case, this appears to be a legitimate use - you're decoding environment variables for configuration. This is standard practice and not a threat.

However, the HIGH score was triggered because base64 is commonly used for obfuscation in malicious code. To reduce false positives in future scans, consider:

1. Adding comments explaining the base64 usage
2. Using named constants instead of inline encoding
3. Placing config code in clearly labeled directories (e.g., /config/)

Decision: APPROVE (False positive - legitimate config usage)
```

#### Quarantine Manager

Invoke for quarantine workflow help:

```
@quarantine-manager review the latest scan
@quarantine-manager what should I do with item abc123
@quarantine-manager show quarantine status
```

**Use when:**
- Reviewing quarantined items
- Making approve/reject decisions
- Understanding quarantine status
- Coordinating multi-finding reviews
- Documenting security decisions

**Example:**
```
User: @quarantine-manager I have 5 items in quarantine. Help me prioritize.

Quarantine Manager: Let me review your quarantine and prioritize by risk...

📊 QUARANTINE TRIAGE

🚨 CRITICAL (Immediate action):
1. suspicious-ai-toolkit (npm) - Score: 67 - Install hook + network exfil
   → REJECT immediately

⚠️ HIGH (Review required):
2. unknown-mcp-server (git) - Score: 34 - Eval usage + credentials
   → Review code, likely REJECT

📋 MEDIUM (Manual review):
3. helper-utils (pip) - Score: 18 - Base64 encoding
   → Likely false positive, APPROVE after review

✅ LOW (Safe to approve):
4. lodash (npm) - Score: 3 - Minimal findings
5. requests (pip) - Score: 2 - Standard HTTP library

Recommended order:
1. Reject #1 (suspicious-ai-toolkit) immediately
2. Review #2 (unknown-mcp-server) code before decision
3. Quick review #3 (helper-utils) for context
4. Bulk approve #4-5 (lodash, requests)

Would you like me to help with any specific item?
```

### Automated Recommendations

The plugin automatically suggests Sigil when you:

**Trigger words:**
```
User: I want to clone this repo from GitHub
User: Let's install the langchain package
User: Can you check this code for security issues
User: This package looks suspicious
```

**Intercepted commands:**
```
User: git clone https://github.com/someone/repo
→ Claude: Before cloning, let me scan this with Sigil for security threats.

User: pip install some-package
→ Claude: I recommend scanning this package first with Sigil.

User: npm install @someone/tool
→ Claude: Let me check this npm package for malicious code before installing.
```

## Configuration

### Default Agent

By default, the `security-auditor` agent is active. To change this, add to your Claude Code settings:

```json
{
  "plugins": {
    "sigil-security": {
      "agent": "quarantine-manager"
    }
  }
}
```

### Auto-Approve Threshold

Configure the Sigil CLI to auto-approve certain risk levels:

Edit `~/.sigil/config.yaml`:

```yaml
quarantine:
  auto_approve_threshold: 0  # Only auto-approve CLEAN (0)
  # auto_approve_threshold: 9  # Auto-approve CLEAN and LOW_RISK (0-9)
```

### Sigil Pro Integration

If you have a Sigil Pro account, authenticate:

```bash
sigil login
```

This enables:
- Cloud threat intelligence
- Scan history across devices
- Team collaboration
- Custom scan rules

## Troubleshooting

### "Sigil command not found"

**Cause:** Sigil CLI is not installed or not in PATH.

**Fix:**
```bash
# Install Sigil
brew install nomarj/tap/sigil

# Verify
which sigil
sigil --version
```

### Skills not showing up

**Cause:** Plugin not installed or disabled.

**Fix:**
```bash
# List plugins
claude plugin list

# If not listed, install
claude plugin install sigil-security@sigil

# If disabled, enable
claude plugin enable sigil-security
```

### "Plugin version mismatch"

**Cause:** Cached old version.

**Fix:**
```bash
# Update plugin
claude plugin update sigil-security

# Or reinstall
claude plugin uninstall sigil-security
claude plugin install sigil-security@sigil
```

### Hooks not triggering

**Cause:** Claude Code version too old.

**Fix:**
```bash
# Check version (need 1.0.33+)
claude --version

# Update Claude Code
claude update
```

### "Permission denied" when scanning

**Cause:** Sigil doesn't have permission to read files.

**Fix:**
```bash
# Check file permissions
ls -la /path/to/file

# Grant read access
chmod +r /path/to/file

# Or run with appropriate permissions
sudo sigil scan /path
```

## Examples

### Complete Workflow: MCP Server Security Audit

```
User: I found this MCP server on GitHub that adds PostgreSQL support. Can I install it?
      https://github.com/someone/postgres-mcp

Claude: Let me scan this MCP server for security threats before you install it.

/sigil-security:scan-repo https://github.com/someone/postgres-mcp

[Sigil scans the repository]

🔍 SCAN RESULTS: MEDIUM RISK

Risk Score: 18 / 100
Threat Level: MEDIUM_RISK

📋 Findings:
1. Code Pattern - process.env access
   Location: src/database.ts:23
   Severity: 2x (MEDIUM)

2. Network Access - PostgreSQL connection
   Location: src/client.ts:45
   Severity: 3x (HIGH)

3. Credential Handling - Database credentials
   Location: src/config.ts:12
   Severity: 2x (MEDIUM)

💡 Analysis:
This MCP server requires database credentials and makes network connections to PostgreSQL.
These patterns are EXPECTED for a database integration, but you should:

1. Verify the source is trustworthy
2. Review how credentials are handled
3. Check if credentials are stored securely
4. Ensure no credential leakage

Let me review the credential handling...

@security-auditor analyze the credential handling in this code

Security Auditor: I've reviewed the credential handling. The code:
✅ Uses environment variables (not hardcoded)
✅ Doesn't log credentials
✅ Uses standard PostgreSQL library
✅ No obvious exfiltration attempts

This appears to be a legitimate PostgreSQL MCP server. The MEDIUM score is due to
the nature of database integrations requiring credentials and network access.

Recommendation: APPROVE if:
- You trust the maintainer
- You'll use it in a non-production environment first
- You store credentials securely in .env

Decision: APPROVE with review

Would you like to approve this from quarantine?

User: Yes, approve it.

@quarantine-manager approve the postgres-mcp scan

Quarantine Manager: Approving postgres-mcp (scan ID: abc123)...

✅ Approved and moved out of quarantine

You can now install the MCP server:
1. Clone: git clone https://github.com/someone/postgres-mcp
2. Install dependencies: cd postgres-mcp && npm install
3. Configure: Add credentials to .env
4. Add to Claude Code MCP config

Remember to:
- Store DATABASE_URL in .env (not committed to git)
- Test in development environment first
- Monitor for unusual behavior
```

## Advanced Usage

### Custom Scan Rules

(Planned for future release)

Define custom patterns in `~/.sigil/rules/`:

```yaml
# custom-rules.yaml
patterns:
  - name: "Internal API Access"
    pattern: "api\\.internal\\.company\\.com"
    severity: MEDIUM
    category: network
```

### CI/CD Integration

Use the plugin in automated workflows:

```bash
# In your CI pipeline
claude --plugin-dir ./sigil-security-plugin << EOF
/sigil-security:scan-repo .
EOF
```

### Team Policies

(Sigil Pro feature)

Enforce security policies across your team:

```yaml
# team-policy.yaml
auto_reject:
  - install_hooks: true
  - eval_usage: true

require_review:
  - network_access: true
  - credential_usage: true
```

## More Information

- **Plugin README**: [plugins/claude-code/README.md](../plugins/claude-code/README.md)
- **Sigil Documentation**: [docs/](../)
- **Detection Patterns**: [detection-patterns.md](detection-patterns.md)
- **Threat Intelligence**: [threat-intelligence-2025.md](threat-intelligence-2025.md)
- **Case Studies**: [CASE-STUDY-OPENCLAW-ATTACK.md](CASE-STUDY-OPENCLAW-ATTACK.md)

## Support

- **GitHub Issues**: [github.com/NOMARJ/sigil/issues](https://github.com/NOMARJ/sigil/issues)
- **Website**: [sigilsec.ai](https://sigilsec.ai)
- **Email**: team@sigilsec.ai

---

**SIGIL** by [NOMARK](https://nomark.ai)
*A protective mark for every line of code.*
