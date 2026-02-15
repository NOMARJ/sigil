# Sigil for JetBrains IDEs

Automated security auditing for AI agent code — for IntelliJ IDEA, WebStorm, PyCharm, and all JetBrains IDEs.

## Features

- **Scan Project** — Full project security scan from the Tools menu
- **Scan File** — Right-click any file in the editor or project tree
- **Scan Packages** — Audit npm/pip packages before installing
- **Findings Panel** — Results displayed in a dedicated tool window
- **Inline Annotations** — Security findings highlighted directly in the editor
- **Settings UI** — Configure binary path, severity threshold, and scan phases

## Installation

### Build from source
```bash
cd plugins/jetbrains
./gradlew buildPlugin
# Output: build/distributions/sigil-jetbrains-0.1.0.zip
```

Install the zip via: **Settings > Plugins > Gear icon > Install Plugin from Disk...**

### Prerequisites
The Sigil CLI must be installed and on your PATH:
```bash
cargo build --release -p sigil
sudo cp cli/target/release/sigil /usr/local/bin/
```

## Configuration

Go to **Settings > Tools > Sigil**:

| Setting | Default | Description |
|---------|---------|-------------|
| Binary path | `sigil` | Path to the sigil CLI |
| Auto-scan on save | `false` | Run scans when files are saved |
| Minimum severity | `low` | Minimum severity to show |
| Phases | `""` | Comma-separated phases (empty = all) |
| API endpoint | `""` | Custom Sigil cloud API endpoint |

## Usage

### From the menu
**Tools > Sigil > Scan Project / Scan Current File / Scan Package...**

### From the context menu
Right-click any file in the editor or project tree and select **Sigil: Scan File**.

### Tool window
The **Sigil** tool window at the bottom of the IDE shows a table of all findings with severity, rule, file, line, and snippet.

## Compatibility

Works with all JetBrains IDEs version 2024.1 and later:
- IntelliJ IDEA (Community & Ultimate)
- WebStorm
- PyCharm
- GoLand
- CLion
- Rider
- RubyMine
- PhpStorm
