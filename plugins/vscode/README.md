# Sigil for VS Code / Cursor / Windsurf

Automated security auditing for AI agent code — right in your editor.

## Features

- **Scan Workspace** — Full project security scan with findings in the Problems panel
- **Scan File** — Right-click any file to scan it individually
- **Scan Selection** — Highlight suspicious code and scan just that snippet
- **Scan Packages** — Audit npm/pip packages before installing them
- **Quarantine View** — Manage quarantined code from the sidebar
- **Auto-Scan on Save** — Optionally scan files every time you save
- **SARIF Support** — Export results in SARIF format for CI integration

## Installation

### From VSIX (local)
```bash
cd plugins/vscode
npm install
npm run compile
npx vsce package
code --install-extension sigil-security-0.1.0.vsix
```

### Prerequisites
The Sigil CLI must be installed and on your PATH:
```bash
# From the repo root
cargo build --release -p sigil
sudo cp cli/target/release/sigil /usr/local/bin/

# Or use the bash version
sudo cp bin/sigil /usr/local/bin/
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `sigil.binaryPath` | `sigil` | Path to the sigil CLI |
| `sigil.autoScanOnSave` | `false` | Scan files automatically on save |
| `sigil.severityThreshold` | `low` | Minimum severity to display |
| `sigil.outputFormat` | `json` | CLI output format |
| `sigil.phases` | `""` | Comma-separated scan phases (empty = all) |
| `sigil.apiEndpoint` | `""` | Custom API endpoint |

## Commands

Open the command palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) and type `Sigil`:

- `Sigil: Scan Workspace` — Scan the entire project
- `Sigil: Scan Current File` — Scan the active file
- `Sigil: Scan Selection` — Scan highlighted code
- `Sigil: Scan Package (npm/pip)` — Download and scan a package
- `Sigil: Show Quarantine` — View quarantined items
- `Sigil: Clear Scan Cache` — Clear cached scan results

## Cursor & Windsurf

This extension is fully compatible with Cursor and Windsurf since they use the VS Code extension API. Install the `.vsix` the same way you would in VS Code.
