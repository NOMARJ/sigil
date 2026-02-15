# IDE & Agent Plugin Guide

Sigil provides first-class integrations for editors and AI agents. All plugins call the same `sigil` CLI under the hood, so scan results are identical everywhere.

## Prerequisites

All plugins require the Sigil CLI installed and available on your `$PATH`:

```bash
# Option 1: Install from source (Rust)
cd cli && cargo build --release
sudo cp target/release/sigil /usr/local/bin/

# Option 2: Use the bash script
sudo cp bin/sigil /usr/local/bin/sigil

# Option 3: Homebrew
brew install nomarj/tap/sigil
```

Verify: `sigil --version`

---

## VS Code / Cursor / Windsurf

One extension covers all three editors (they share the VS Code extension API).

### Install

```bash
cd plugins/vscode
npm install
npm run compile
npx vsce package
# Install the .vsix:
code --install-extension sigil-security-0.1.0.vsix
```

### Features

- **Scan Workspace** (`Cmd+Shift+P` > `Sigil: Scan Workspace`) — full project scan
- **Scan File** — right-click a file in explorer or editor
- **Scan Selection** — highlight code, right-click > `Sigil: Scan Selection`
- **Scan Package** — audit npm/pip packages before installing
- **Findings sidebar** — tree view of all findings grouped by severity
- **Quarantine sidebar** — view and manage quarantined items
- **Problems panel** — findings appear as diagnostics with severity-mapped icons
- **Auto-scan on save** — enable in settings

### Settings

Open **Settings > Extensions > Sigil**:

| Setting | Default | Description |
|---------|---------|-------------|
| `sigil.binaryPath` | `sigil` | Path to CLI |
| `sigil.autoScanOnSave` | `false` | Scan on every save |
| `sigil.severityThreshold` | `low` | Min severity to display |
| `sigil.phases` | (all) | Comma-separated phase filter |
| `sigil.apiEndpoint` | (default) | Custom API URL |

---

## JetBrains IDEs

Works with IntelliJ IDEA, WebStorm, PyCharm, GoLand, CLion, Rider, RubyMine, PhpStorm — any JetBrains IDE version 2024.1+.

### Install

```bash
cd plugins/jetbrains
gradle buildPlugin
# Output: build/distributions/sigil-jetbrains-0.1.0.zip
```

Install via **Settings > Plugins > Gear > Install Plugin from Disk...**

### Features

- **Tools > Sigil** menu with Scan Project, Scan File, Scan Package, Clear Cache
- **Right-click context menu** on files in editor and project tree
- **Tool window** at the bottom of the IDE with a findings table
- **Inline annotations** — findings highlighted in the editor (when auto-scan is on)
- **Settings UI** at **Settings > Tools > Sigil**

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Binary path | `sigil` | Path to CLI |
| Auto-scan on save | `false` | Trigger scans on save |
| Minimum severity | `low` | Filter threshold |
| Phases | (all) | Comma-separated phase filter |
| API endpoint | (default) | Custom API URL |

---

## Claude Code / MCP Server

The MCP (Model Context Protocol) server gives AI agents direct access to Sigil scanning tools. Works with Claude Code, Cursor (MCP mode), Windsurf, and any MCP-compatible client.

### Install

```bash
cd plugins/mcp-server
npm install
npm run build
```

### Configure

**Claude Code** — add to `~/.claude/claude_desktop_config.json`:

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

**Per-project** — add to `.mcp.json` in the project root:

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

**Cursor / Windsurf** — add to their MCP settings with the same format.

### Available Tools

| Tool | Description |
|------|-------------|
| `sigil_scan` | Scan a file or directory |
| `sigil_scan_package` | Download + scan an npm/pip package |
| `sigil_clone` | Clone + scan a git repo |
| `sigil_quarantine` | List quarantined items |
| `sigil_approve` | Approve a quarantined item |
| `sigil_reject` | Reject a quarantined item |

### Example Prompts

Once configured, just ask naturally:

- "Scan this project for security issues"
- "Is the `left-pad` npm package safe to install?"
- "Audit this repo before I clone it: https://github.com/example/repo"
- "Show me what's in quarantine"

---

## GitHub Actions

Use Sigil as a CI check on every pull request:

```yaml
- uses: NOMARJ/sigil@main
  with:
    path: .
    threshold: medium
    fail-on-findings: true
```

See [action.yml](../action.yml) for all inputs and outputs.

---

## Building All Plugins

```bash
make plugins-build    # Build all three plugins
make plugins-clean    # Clean all build artifacts
make vscode-build     # Build VS Code extension only
make mcp-build        # Build MCP server only
make jetbrains-build  # Build JetBrains plugin only
```
