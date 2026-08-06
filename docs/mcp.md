# MCP Integration Guide

Connect Sigil to AI agents via the Model Context Protocol (MCP). This gives Claude Code, Cursor, Windsurf, and any MCP-compatible client direct access to security scanning as a tool.

---

## Why AI Agents Need Security Scanning

AI coding agents install packages, clone repositories, and fetch files autonomously. An agent with `npm install` access and no scanning is a supply chain attack waiting to happen — it cannot distinguish a legitimate package from a typosquatted one containing a `postinstall` hook that exfiltrates your API keys.

Sigil's MCP server solves this by giving agents nine tools they can call before taking any action that introduces external code. The agent scans first, checks the verdict, and only proceeds if the code is clean.

---

## Quick Setup

### 1. Install the Sigil CLI

The MCP server wraps the `sigil` CLI. Install it first:

```bash
# Option 1: Quick install
curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
sh install.sh

# Option 2: Homebrew
brew install nomarj/tap/sigil

# Option 3: Build from source (Rust)
cargo install sigil-cli
```

> **Note**: The `sigil` package name on crates.io is occupied by an unrelated project — the Rust CLI is published as `sigil-cli`.

Verify: `sigil help`

### 2. Configure Your Client

> **Note**: `@nomark/sigil-mcp-server` v1.3.0 is not yet published to npm. The `npx`-based configurations below are the target state and will work once the package is published. Until then, build the server from source (`cd plugins/mcp-server && npm install && npm run build`) and point your MCP client at `node /path/to/sigil/plugins/mcp-server/dist/index.js` — see [Building from Source](#building-from-source-current-working-path) below.

#### Claude Code (Plugin — Recommended)

The Sigil Claude Code plugin registers the MCP server automatically — the automatic `npx`-based registration takes effect once `@nomark/sigil-mcp-server` is published to npm. No manual MCP configuration is needed:

```bash
claude plugin marketplace add NOMARJ/sigil
claude plugin install sigil-security@sigil-marketplace
```

#### Claude Code (Manual)

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "npx",
      "args": ["-y", "@nomark/sigil-mcp-server"]
    }
  }
}
```

#### Per-Project Configuration

Add a `.mcp.json` file to your project root:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "npx",
      "args": ["-y", "@nomark/sigil-mcp-server"]
    }
  }
}
```

#### Cursor

Open **Settings > MCP Servers** and add:

```json
{
  "sigil": {
    "command": "npx",
    "args": ["-y", "@nomark/sigil-mcp-server"]
  }
}
```

#### Windsurf

Open **Settings > MCP** and add the same configuration as Cursor.

#### Building from Source (Current Working Path)

Until `@nomark/sigil-mcp-server` is published to npm, this is the working install path (it also works if you simply prefer a local checkout):

```bash
cd plugins/mcp-server
npm install
npm run build
```

Then point your client at the compiled entry point:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["/absolute/path/to/sigil/plugins/mcp-server/dist/index.js"]
    }
  }
}
```

---

## Available Tools

The MCP server exposes nine tools and one resource.

### sigil_scan

Scan a file or directory for security issues.

| Parameter  | Type   | Required | Description                                                                                                                                                                     |
| ---------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`     | string | Yes      | File or directory path to scan                                                                                                                                                  |
| `phases`   | string | No       | Comma-separated phase filter: `install_hooks`, `code_patterns`, `network_exfil`, `credentials`, `obfuscation`, `provenance`, `prompt_injection`, `skill_security` |
| `severity` | string | No       | Minimum severity threshold: `low`, `medium`, `high`, `critical`                                                                                                                 |

**Returns:** Verdict, risk score, findings count, duration, and detailed findings with file paths, line numbers, and matched patterns.

**Example response:**

```
Verdict: MEDIUM_RISK | Score: 12 | 3 findings | 47 files scanned in 850ms

[HIGH] eval_usage — src/parser.py:42
  result = eval(expression)

[MEDIUM] env_access — src/config.py:5
  api_key = os.environ.get('API_KEY')

[LOW] outbound_http — src/api.py:18
  requests.post(endpoint, json=data)
```

---

### sigil_scan_package

Download and scan an npm or pip package in quarantine before installing it.

| Parameter      | Type               | Required | Description              |
| -------------- | ------------------ | -------- | ------------------------ |
| `manager`      | `"npm"` or `"pip"` | Yes      | Package manager          |
| `package_name` | string             | Yes      | Package name to scan     |
| `version`      | string             | No       | Specific version to scan |

**Returns:** Package identifier, verdict, score, and findings.

---

### sigil_clone

Clone a git repository into quarantine and scan it.

| Parameter | Type   | Required | Description              |
| --------- | ------ | -------- | ------------------------ |
| `url`     | string | Yes      | Git repository URL       |
| `branch`  | string | No       | Specific branch to clone |

**Returns:** Repository URL, verdict, score, and findings.

---

### sigil_quarantine

List all items currently in quarantine.

**Parameters:** None.

**Returns:** Count of quarantined items with their status, source, source type, scan score, and quarantine ID.

**Example response:**

```
3 item(s) in quarantine:

[SCANNED] https://github.com/someone/mcp-server (git)  — score: 12
  ID: 20260219_143000_mcp_server

[SCANNED] leftpad (npm) — score: 0
  ID: 20260219_144500_leftpad

[PENDING] some-agent-toolkit (pip)
  ID: 20260219_150000_some_agent_toolkit
```

---

### sigil_approve

Approve a quarantined item and move it to the approved directory.

| Parameter       | Type   | Required | Description                                 |
| --------------- | ------ | -------- | ------------------------------------------- |
| `quarantine_id` | string | Yes      | Quarantine entry ID from `sigil_quarantine` |

---

### sigil_reject

Reject and permanently delete a quarantined item.

| Parameter       | Type   | Required | Description                                 |
| --------------- | ------ | -------- | ------------------------------------------- |
| `quarantine_id` | string | Yes      | Quarantine entry ID from `sigil_quarantine` |

---

### sigil_check_package

Look up a package or skill's risk assessment in the Sigil public scan database. Works without the Sigil CLI installed — it queries the API directly.

| Parameter      | Type                                              | Required | Description                                            |
| -------------- | ------------------------------------------------- | -------- | ------------------------------------------------------ |
| `ecosystem`    | `"clawhub"`, `"pypi"`, `"npm"`, `"github"`, `"mcp"` | Yes      | Package ecosystem                                      |
| `package_name` | string                                            | Yes      | Package name, skill slug, or repo path (e.g. `todoist-cli`) |

**Returns:** Verdict, risk score, findings count, scan date, report/badge URLs, and up to five top findings. If the package has not been scanned, the tool suggests a local scan instead.

---

### sigil_search_database

Search the Sigil public scan database for packages by name or keyword. Also works without the Sigil CLI installed.

| Parameter   | Type                                              | Required | Description                          |
| ----------- | ------------------------------------------------- | -------- | ------------------------------------ |
| `query`     | string                                            | Yes      | Search query (package name or keyword) |
| `ecosystem` | `"clawhub"`, `"pypi"`, `"npm"`, `"github"`, `"mcp"` | No       | Filter by ecosystem                  |

**Returns:** Up to 10 matching packages with their verdicts and risk scores.

---

### sigil_report_threat

Report a malicious file to the Sigil threat intelligence database by its SHA256 hash. Requires the Sigil CLI and an authenticated session (`sigil login`). Reports are reviewed by the security team.

| Parameter     | Type   | Required | Description                                       |
| ------------- | ------ | -------- | ------------------------------------------------- |
| `sha256`      | string | Yes      | SHA256 hash of the malicious file (64 hex chars)  |
| `threat_type` | string | Yes      | Type of threat (e.g. `malware`, `backdoor`, `exfil`) |
| `description` | string | Yes      | Description of the threat                         |

---

### Resource: sigil://docs/phases

A read-only resource that provides documentation about Sigil's eight scan phases. Agents can read this resource to understand what each phase detects and how scoring works.

**URI:** `sigil://docs/phases`

---

## Example Workflows

### "Is this package safe to install?"

Ask your AI agent naturally:

> "Is the `langchain-community` pip package safe to install?"

The agent calls `sigil_scan_package` with `manager: "pip"` and `package_name: "langchain-community"`, reviews the verdict, and tells you whether to proceed.

### "Scan this project before I deploy"

> "Scan this project for security issues before I deploy"

The agent calls `sigil_scan` with `path: "."`, reads the findings, and summarizes any risks.

### "Clone and audit this repo"

> "Audit this repo before I use it: https://github.com/example/agent-tools"

The agent calls `sigil_clone` with the URL, reviews the verdict, and reports findings. If clean, it can call `sigil_approve` to move the code out of quarantine.

### "Clean up quarantine"

> "What's in quarantine? Approve the clean ones and reject anything critical."

The agent calls `sigil_quarantine` to list items, then iterates through them — calling `sigil_approve` for CLEAN/LOW_RISK items and `sigil_reject` for CRITICAL items, asking for confirmation on anything in between.

---

## Building Agents with Sigil as a Guardrail

### Pattern: Auto-scan before every install

Build an agent that intercepts package install requests and scans first:

```
Agent receives: "Install the requests library"
  1. Agent calls sigil_scan_package(manager="pip", package_name="requests")
  2. Verdict: CLEAN → Agent proceeds with pip install
  3. Verdict: HIGH_RISK → Agent warns user, shows findings, asks for confirmation
```

### Pattern: CI security review agent

An agent that runs in CI and reviews scan results:

```
CI pipeline triggers Sigil scan
  1. Agent calls sigil_scan(path=".")
  2. Agent reads findings
  3. For each finding: agent explains the risk in plain English
  4. Agent recommends approve/block based on finding severity
  5. Posts summary as a PR comment
```

### Pattern: Quarantine manager agent

An agent that helps teams manage their quarantine backlog:

```
Agent runs on a schedule or on demand
  1. Agent calls sigil_quarantine to get the list
  2. For each item, agent reviews the scan details
  3. Agent groups items by verdict
  4. Agent auto-approves CLEAN items
  5. Agent creates a summary report for items needing human review
```

---

## Environment Variables

| Variable        | Default                   | Description                                                               |
| --------------- | ------------------------- | ------------------------------------------------------------------------- |
| `SIGIL_BINARY`  | `sigil`                   | Path to the Sigil CLI binary. Set this if `sigil` is not in your `$PATH`. |
| `SIGIL_API_URL` | `https://api.sigilsec.ai` | Base URL for the public scan database used by `sigil_check_package` and `sigil_search_database`. |

**Example:** If Sigil is installed in a custom location:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "npx",
      "args": ["-y", "@nomark/sigil-mcp-server"],
      "env": {
        "SIGIL_BINARY": "/opt/sigil/bin/sigil"
      }
    }
  }
}
```

(Until `@nomark/sigil-mcp-server` v1.3.0 is published to npm, replace the `npx` command/args with `"command": "node", "args": ["/path/to/sigil/plugins/mcp-server/dist/index.js"]`.)

---

## Troubleshooting

### "Sigil CLI was not found"

The server starts and stays usable even when the `sigil` binary is missing — CLI-backed tools return install instructions instead of failing, and the database tools (`sigil_check_package`, `sigil_search_database`) keep working. To restore full functionality:

```bash
# Check if sigil is in PATH
which sigil

# If not, install it — or set the SIGIL_BINARY environment variable in your MCP config
```

### Scans timeout

The MCP server has a 5-minute (300,000ms) timeout per scan. If scanning large repositories:

- Use the `phases` parameter to run only specific phases
- Use the `severity` parameter to filter low-priority findings
- Add a `.sigilignore` file to exclude `node_modules/`, `vendor/`, and other large directories

### No findings returned

If `sigil_scan` returns no findings but you expect some:

1. Verify the path is correct and accessible
2. Check that the file types are supported (`.py`, `.js`, `.ts`, `.sh`, `.yaml`, `.json`, `.toml`)
3. Run `sigil scan <path>` directly in the terminal to compare output

---

## See Also

- [CLI Command Reference](cli.md) — Full reference for the `sigil` CLI
- [IDE Plugin Guide](ide-plugins.md) — VS Code, JetBrains, and GitHub Actions integrations
- [Scan Phases Reference](scan-rules.md) — Detailed patterns and examples for each phase
- [Getting Started](getting-started.md) — Installation and first scan walkthrough
