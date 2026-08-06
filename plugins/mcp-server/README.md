# Sigil MCP Server

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes Sigil security scanning tools to AI agents — Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Tools Provided

| Tool | Description | Requires Sigil CLI |
|------|-------------|--------------------|
| `sigil_scan` | Scan a file or directory for security issues | Yes |
| `sigil_scan_package` | Download and scan an npm/pip package in quarantine | Yes |
| `sigil_clone` | Clone a git repo into quarantine and scan it | Yes |
| `sigil_quarantine` | List all quarantined items | Yes |
| `sigil_approve` | Approve a quarantined item | Yes |
| `sigil_reject` | Reject and delete a quarantined item | Yes |
| `sigil_check_package` | Look up a package's risk assessment in the Sigil public scan database | No (API) |
| `sigil_search_database` | Search the Sigil public scan database by name or keyword | No (API) |
| `sigil_report_threat` | Report a malicious file (by SHA256) to the threat intelligence database | Yes (+ `sigil login`) |

If the Sigil CLI binary is not found, CLI-backed tools return install instructions instead of failing, and the server logs a warning to stderr at startup. Database-backed tools work without the CLI.

## Resources

| Resource | Description |
|----------|-------------|
| `sigil://docs/phases` | Documentation of Sigil's 8 scan phases |

## Installation

### Via npx (recommended)

No install step needed — MCP clients can launch the published package directly:

```bash
npx -y @nomark/sigil-mcp-server
```

### From source

```bash
cd plugins/mcp-server
npm install
npm run build
node dist/index.js
```

### Prerequisites

The Sigil CLI should be installed and on your PATH for scanning tools:

```bash
curl -fsSLO https://www.sigilsec.ai/install.sh && sh install.sh
```

Without it, the server still starts and the database-backed tools still work.

## Configuration

### Claude Code (via the Sigil plugin — automatic)

The `sigil-security` Claude Code plugin registers this MCP server automatically through the `mcpServers` field in its `plugin.json`:

```bash
claude plugin install sigil-security@sigil-marketplace
```

No manual MCP configuration is needed when the plugin is installed.

### Claude Code / any MCP client (manual)

Add to your project's `.mcp.json` (or your client's MCP server settings):

```json
{
  "mcpServers": {
    "sigil": {
      "command": "npx",
      "args": ["-y", "@nomark/sigil-mcp-server"],
      "env": {
        "SIGIL_BINARY": "sigil"
      }
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings (Settings > MCP Servers):

```json
{
  "sigil": {
    "command": "npx",
    "args": ["-y", "@nomark/sigil-mcp-server"]
  }
}
```

### Windsurf

Add to your Windsurf MCP configuration:

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_BINARY` | `sigil` | Path to the sigil CLI binary |
| `SIGIL_API_URL` | `https://api.sigilsec.ai` | Base URL for the Sigil public scan database (used by `sigil_check_package` and `sigil_search_database`) |

## Example Usage

Once configured, AI agents can use Sigil tools naturally:

> "Scan this project for security issues"
> → Agent calls `sigil_scan` with the project path

> "Is the `left-pad` npm package safe to install?"
> → Agent calls `sigil_scan_package` with manager="npm", package_name="left-pad"

> "Audit this GitHub repo before I clone it: https://github.com/example/repo"
> → Agent calls `sigil_clone` with the URL

> "Has anyone scanned the `requests` PyPI package?"
> → Agent calls `sigil_check_package` with ecosystem="pypi", package_name="requests"
