# Sigil Installation Guide

Complete installation instructions for all platforms and package managers.

---

## 🚀 Current Installation Method

### Manual Install (macOS/Linux)

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil/cli

# Build the Rust CLI (needs Rust 1.89 or newer; see Build from Source below)
cargo build --release

# Copy the binary to /usr/local/bin
sudo ./target/release/sigil install
```

**What it does:**

- Builds the Rust CLI from `cli/`
- `sigil install` copies the running binary to `/usr/local/bin/sigil` (`--path <dir>` installs into another directory, which must already exist)
- Creates nothing under `~/.sigil/`: Sigil creates what it needs there the first time a command uses it (for example `~/.sigil/quarantine/` on the first `sigil clone`)
- Installs no shell aliases: add them with `sigil setup shell` (optional)
- Sets up no git hooks: add a pre-commit scan with `sigil setup git` (optional)

---

## Package Managers & Install Script

### Homebrew (macOS/Linux)

```bash
brew tap nomarj/tap
brew install sigil
```

### npm (macOS/Linux)

```bash
npm install -g @nomarj/sigil
```

### Cargo (Rust)

```bash
cargo install sigil-cli
```

_Note: The `sigil` name on crates.io is occupied by an unrelated Unicode library — the Rust CLI is published as `sigil-cli`._

### pip (Python) — _pending first PyPI publication_

> **Not yet on PyPI.** The package source lives in [`python/`](../python/) and
> is ready, but the project has not been registered or published yet. The
> commands below will work once the first release is pushed to PyPI.

```bash
pip install sigilsec         # the name sigil-cli is taken on PyPI by an unrelated project
sigil scan .
```

The wrapper is pure standard library (Python 3.9+) and mirrors the npm
package: on first run it downloads the prebuilt binary for your platform
(macOS/Linux x64 and arm64, Windows x64) from GitHub Releases, verifies it
against the release's `SHA256SUMS.txt`, caches it under
`~/.sigil/bin/sigil-<version>`, and then forwards every invocation to it.

- `SIGIL_VERSION=v1.3.6 sigil ...` — fetch a specific release (same as `install.sh`)
- `SIGIL_BINARY=/path/to/sigil sigil ...` — use an existing binary, no download
- Upgrade with `pip install --upgrade sigilsec`; remove with `pip uninstall sigilsec`
  (the cached binaries in `~/.sigil/bin/` can be deleted by hand)

### Quick Install Script

```bash
curl -fsSLO https://www.sigilsec.ai/install.sh
sh install.sh
```

---

## 📦 Package Manager Installation

### macOS

**Homebrew:**

```bash
brew tap nomarj/tap
brew install sigil
```

**npm:**

```bash
npm install -g @nomarj/sigil
```

**Manual download:**

```bash
# Apple Silicon (M1/M2/M3)
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/sigil-macos-arm64.tar.gz
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/SHA256SUMS.txt
shasum -a 256 -c --ignore-missing SHA256SUMS.txt
tar -xzf sigil-macos-arm64.tar.gz
sudo mv sigil /usr/local/bin/

# Intel (x64)
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/sigil-macos-x64.tar.gz
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/SHA256SUMS.txt
shasum -a 256 -c --ignore-missing SHA256SUMS.txt
tar -xzf sigil-macos-x64.tar.gz
sudo mv sigil /usr/local/bin/
```

---

### Linux

**Homebrew on Linux:**

```bash
brew tap nomarj/tap
brew install sigil
```

**npm:**

```bash
npm install -g @nomarj/sigil
```

**APT (Debian/Ubuntu)** — _Coming soon_

```bash
curl -fsSL https://apt.sigilsec.ai/key.gpg | sudo apt-key add -
echo "deb https://apt.sigilsec.ai stable main" | sudo tee /etc/apt/sources.list.d/sigil.list
sudo apt update
sudo apt install sigil
```

**RPM (Fedora/RHEL)** — _Coming soon_

```bash
sudo dnf config-manager --add-repo https://rpm.sigilsec.ai/sigil.repo
sudo dnf install sigil
```

**Manual download:**

```bash
# x64
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/sigil-linux-x64.tar.gz
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
tar -xzf sigil-linux-x64.tar.gz
sudo mv sigil /usr/local/bin/

# ARM64
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/sigil-linux-arm64.tar.gz
curl -fsSLO https://github.com/NOMARJ/sigil/releases/latest/download/SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt
tar -xzf sigil-linux-arm64.tar.gz
sudo mv sigil /usr/local/bin/
```

---

### Windows

Windows npm packages are not published yet. Use the GitHub Release zip for Windows x64.

**Chocolatey** — _Coming soon_

```powershell
choco install sigil
```

**WinGet** — _Coming soon_

```powershell
winget install NOMARK.Sigil
```

**Manual download:**

1. Download [`sigil-windows-x64.zip`](https://github.com/NOMARJ/sigil/releases/latest)
2. Extract `sigil.exe`
3. Add to your `PATH` or place in `C:\Windows\System32`

---

## 🐳 Docker

### CLI Only

```bash
docker pull nomark/sigil:1.2.1

# Scan a directory
docker run --rm -v $(pwd):/workspace nomark/sigil:1.2.1 scan .

# Clone and scan a repo
docker run --rm -v ~/.sigil:/home/sigil/.sigil nomark/sigil:1.2.1 clone https://github.com/someone/repo
```

### Full Stack (API + Dashboard + CLI)

```bash
docker pull nomark/sigil-full:1.2.1

# Run the full stack
docker run -p 8000:8000 -p 3000:3000 nomark/sigil-full:1.2.1
```

**Docker Compose:**

```yaml
version: "3.8"
services:
  sigil:
    image: nomark/sigil-full:1.2.1
    ports:
      - "8000:8000" # API
      - "3000:3000" # Dashboard
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/sigil
      - SIGIL_API_URL=http://localhost:8000
    volumes:
      - ./data:/home/sigil/.sigil
```

### Build the CLI image yourself

`Dockerfile.cli` builds a static (musl) binary with the Rust toolchain CI pins
(1.90, `.github/workflows/rust-cli.yml`) and ships it on Alpine with `git` and
CA certificates. Base images are pinned by digest.

```bash
# from the repository root
docker build -f Dockerfile.cli -t sigil .
docker build -f Dockerfile.cli --build-arg CARGO_BUILD_JOBS=2 -t sigil .   # bound build parallelism

docker run --rm -v "$PWD:/workspace:ro" sigil scan /workspace
docker run --rm sigil scan https://github.com/someone/mcp-tool
```

The container runs as the unprivileged user `sigil` (`HOME=/home/sigil`), so
persist quarantine state with `-v ~/.sigil:/home/sigil/.sigil`. `sigil pip`
and `sigil npm` also need `pip` / `npm` in the image (`apk add py3-pip npm` in
a derived image).

---

## 🏗️ Build from Source

### Prerequisites

- **Rust 1.89+** (CI pins 1.90). `cli/Cargo.lock` is not committed, so a build resolves the newest compatible dependency releases and the minimum rises with them: in October 2026 a fresh clone built with 1.89 and failed with 1.88 (`uuid 1.27.0 requires rustc 1.89.0`) — [Install Rust](https://rustup.rs)
- **Git**

### Build the CLI

```bash
git clone https://github.com/NOMARJ/sigil
cd sigil/cli
cargo build --release
sudo ./target/release/sigil install    # copies the binary to /usr/local/bin
```

### Build the Full Stack

**Requirements:**

- Node.js 18+
- Python 3.11+
- Docker (optional, for database)

```bash
# Build Rust CLI
cd cli && cargo build --release && cd ..

# Build Dashboard
cd dashboard && npm install && npm run build && cd ..

# Install API dependencies
cd api && pip install -r requirements.txt && cd ..

# Run with Docker Compose
docker-compose up
```

---

## ⚙️ Post-Installation Setup

### 1. Verify Installation

```bash
sigil --version
```

Expected output (for the 1.3.7 release):

```
sigil 1.3.7
```

### 2. Set Up Shell Aliases

```bash
sigil setup shell
```

This adds three aliases to `~/.bashrc` or `~/.zshrc`, chosen from `$SHELL` (for any other shell it prints the aliases to add by hand):

- `gclone` — Safe git clone with scanning
- `safepip` — `sigil pip`: download a pip package into quarantine and scan it (does not install it)
- `safenpm` — `sigil npm`: download an npm package into quarantine and scan it (does not install it)

**Restart your shell** or run:

```bash
source ~/.bashrc  # or ~/.zshrc
```

### 3. Test with a Scan

```bash
sigil scan .
```

### 4. (Optional) Authenticate for Cloud Threat Intel

```bash
sigil login
```

Enables:

- Hash-based malware lookup
- Auto-updating threat signatures
- Community-reported threats

See [Authentication Guide](./authentication-guide.md) for details.

### 5. (Optional) Stop bad skills and MCP servers before they land

```bash
# Claude Code: gate installs, MCP-server / plugin acquisition and curl|sh
sigil setup claude

# See what agent tooling is already installed, and whether any of it is risky
sigil skills

# Commit-time checks for the repository and its committed agent config
pip install pre-commit    # then add the hooks below to .pre-commit-config.yaml
```

```yaml
repos:
  - repo: https://github.com/NOMARJ/sigil
    rev: v1.3.6
    hooks:
      - id: sigil-scan
      - id: sigil-scan-skills
```

To have the Claude Code gate judge file edits too (an agent rewriting its own
hooks or `.mcp.json`), register `sigil hook pretooluse` for the matcher
`Bash|Write|Edit|MultiEdit` in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash|Write|Edit|MultiEdit",
       "hooks": [{"type": "command", "command": "sigil hook pretooluse"}]}
    ]
  }
}
```

CI templates (GitHub Actions, GitLab, pre-commit) are in [cicd.md](cicd.md).

---

## 🔄 Updating Sigil

### Homebrew

```bash
brew upgrade sigil
```

### npm

```bash
npm update -g @nomarj/sigil
```

### Cargo

```bash
cargo install sigil-cli --force
```

### Docker

```bash
docker pull nomark/sigil:1.2.1
```

### Manual / Script Install

```bash
curl -fsSLO https://www.sigilsec.ai/install.sh
sh install.sh
```

---

## 🗑️ Uninstallation

### Homebrew

```bash
brew uninstall sigil
brew untap nomarj/tap
```

### npm

```bash
npm uninstall -g @nomarj/sigil
```

### Cargo

```bash
cargo uninstall sigil-cli
```

### Manual

```bash
sudo rm /usr/local/bin/sigil
rm -rf ~/.sigil
```

**Remove shell aliases:**
Edit your `~/.bashrc` or `~/.zshrc` and remove the block between:

```bash
# >>> sigil aliases >>>
...
# <<< sigil aliases <<<
```

---

## 🆘 Troubleshooting

### Command not found after install

**Homebrew/Cargo:**
Ensure `/usr/local/bin` or `~/.cargo/bin` is in your `PATH`:

```bash
echo $PATH
export PATH="/usr/local/bin:$PATH"  # Add to ~/.bashrc or ~/.zshrc
```

**npm:**
Find npm global bin directory:

```bash
npm config get prefix
export PATH="$(npm config get prefix)/bin:$PATH"
```

### Permission denied

**macOS/Linux:**

```bash
sudo chmod +x /usr/local/bin/sigil
```

**npm:**

```bash
sudo npm install -g @nomarj/sigil
```

### Download fails / Binary unavailable

The installer fails closed when a platform binary or checksum is unavailable. When it cannot download or run a release binary, it points you to installing from source instead:

```bash
cargo install sigil-cli
```

Or build `cli/` yourself as shown under Build from Source.

### Docker permission issues on Linux

Add your user to the `docker` group:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

---

## 📚 Next Steps

- [**Getting Started Guide**](./getting-started.md) — Your first scan
- [**CLI Reference**](./cli.md) — All commands
- [**Authentication Guide**](./authentication-guide.md) — Enable cloud threat intel
- [**Configuration**](./configuration.md) — Customize Sigil

---

**Need help?** [Open an issue](https://github.com/NOMARJ/sigil/issues) or email support@sigilsec.ai
