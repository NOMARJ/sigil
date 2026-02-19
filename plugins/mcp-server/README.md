# Sigil MCP Server

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes Sigil security scanning tools to AI agents — Claude Code, Cursor, Windsurf, and any MCP-compatible client.

## Tools Provided

| Tool | Description |
|------|-------------|
| `sigil_scan` | Scan a file or directory for security issues |
| `sigil_scan_package` | Download and scan an npm/pip package in quarantine |
| `sigil_clone` | Clone a git repo into quarantine and scan it |
| `sigil_quarantine` | List all quarantined items |
| `sigil_approve` | Approve a quarantined item |
| `sigil_reject` | Reject and delete a quarantined item |

## Resources

| Resource | Description |
|----------|-------------|
| `sigil://docs/phases` | Documentation of Sigil's 6 scan phases |

## Installation

```bash
cd plugins/mcp-server
npm install
npm run build
```

### Prerequisites
The Sigil CLI must be installed and on your PATH.

## Configuration

### Claude Code

Add to your `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["/path/to/sigil/plugins/mcp-server/dist/index.js"],
      "env": {
        "SIGIL_BINARY": "sigil"
      }
    }
  }
}
```

Or in your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["./plugins/mcp-server/dist/index.js"]
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings (Settings > MCP Servers):

```json
{
  "sigil": {
    "command": "node",
    "args": ["/path/to/sigil/plugins/mcp-server/dist/index.js"]
  }
}
```

### Windsurf

Add to your Windsurf MCP configuration:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "node",
      "args": ["/path/to/sigil/plugins/mcp-server/dist/index.js"]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_BINARY` | `sigil` | Path to the sigil CLI binary |

## Example Usage

Once configured, AI agents can use Sigil tools naturally:

> "Scan this project for security issues"
> → Agent calls `sigil_scan` with the project path

> "Is the `left-pad` npm package safe to install?"
> → Agent calls `sigil_scan_package` with manager="npm", package_name="left-pad"

> "Audit this GitHub repo before I clone it: https://github.com/example/repo"
> → Agent calls `sigil_clone` with the URL
