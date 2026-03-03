# Sigil Installation Guide

Complete installation instructions for all platforms and package managers.

---

## 🚀 Current Installation Method

### Manual Install (All Platforms)

```bash
# Clone the repository
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Make the CLI executable and install
chmod +x bin/sigil
sudo cp bin/sigil /usr/local/bin/sigil

# Initialize directories and aliases
sigil install
```

**What it does:**
- Downloads the bash-based CLI implementation
- Copies to system PATH for global access
- Creates `~/.sigil/{quarantine,approved,logs,reports}` directories
- Installs helpful shell aliases (optional)
- Sets up git hooks for auto-scanning (optional)

---

## 🔮 Coming Soon

The following installation methods are planned but not yet available:

### Homebrew (macOS/Linux)
```bash
brew tap nomarj/tap
brew install sigil
```
*Status: Tap and formula in development*

### npm (All Platforms)
```bash
npm install -g @nomark/sigil
```
*Status: Package preparation in progress*

### Cargo (Rust)
```bash
cargo install @nomark/sigil
```
*Status: Rust CLI rewrite in progress. Note: The `sigil` name on crates.io is occupied by an unrelated Unicode library.*

### Quick Install Script
```bash
curl -sSL https://sigilsec.ai/install.sh | sh
```
*Status: Install script development in progress*

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
npm install -g @nomark/sigil
```

**Manual download:**
```bash
# Apple Silicon (M1/M2/M3)
curl -sSL https://github.com/NOMARJ/sigil/releases/latest/download/sigil-macos-arm64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/

# Intel (x64)
curl -sSL https://github.com/NOMARJ/sigil/releases/latest/download/sigil-macos-x64.tar.gz | tar xz
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
npm install -g @nomark/sigil
```

**APT (Debian/Ubuntu)** — *Coming soon*
```bash
curl -fsSL https://apt.sigilsec.ai/key.gpg | sudo apt-key add -
echo "deb https://apt.sigilsec.ai stable main" | sudo tee /etc/apt/sources.list.d/sigil.list
sudo apt update
sudo apt install sigil
```

**RPM (Fedora/RHEL)** — *Coming soon*
```bash
sudo dnf config-manager --add-repo https://rpm.sigilsec.ai/sigil.repo
sudo dnf install sigil
```

**Manual download:**
```bash
# x64
curl -sSL https://github.com/NOMARJ/sigil/releases/latest/download/sigil-linux-x64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/

# ARM64
curl -sSL https://github.com/NOMARJ/sigil/releases/latest/download/sigil-linux-aarch64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/
```

---

### Windows

**npm:**
```bash
npm install -g @nomark/sigil
```

**Chocolatey** — *Coming soon*
```powershell
choco install sigil
```

**WinGet** — *Coming soon*
```powershell
winget install NOMARK.Sigil
```

**Manual download:**
1. Download [`sigil-windows-x64.zip`](https://github.com/NOMARJ/sigil/releases/latest)
2. Extract `sigil.exe`
3. Add to your `PATH` or place in `C:\Windows\System32`

---

## 🐳 Docker

### CLI Only (Lightweight ~15MB)

```bash
docker pull nomark/sigil:latest

# Scan a directory
docker run --rm -v $(pwd):/workspace nomark/sigil scan .

# Clone and scan a repo
docker run --rm -v ~/.sigil:/root/.sigil nomark/sigil clone https://github.com/someone/repo
```

### Full Stack (API + Dashboard + CLI)

```bash
docker pull nomark/sigil-full:latest

# Run the full stack
docker run -p 8000:8000 -p 3000:3000 nomark/sigil-full:latest
```

**Docker Compose:**
```yaml
version: '3.8'
services:
  sigil:
    image: nomark/sigil-full:latest
    ports:
      - "8000:8000"  # API
      - "3000:3000"  # Dashboard
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/sigil
      - SIGIL_API_URL=http://localhost:8000
    volumes:
      - ./data:/home/sigil/.sigil
```

---

## 🏗️ Build from Source

### Prerequisites

- **Rust 1.75+** — [Install Rust](https://rustup.rs)
- **Git**

### Build the CLI

```bash
git clone https://github.com/NOMARJ/sigil
cd sigil/cli
cargo build --release
sudo cp target/release/sigil /usr/local/bin/
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
sigil version
```

Expected output:
```
Sigil 1.0.5
Automated Security Auditing for AI Agent Code
https://sigilsec.ai
```

### 2. Set Up Shell Aliases

```bash
sigil install
```

This installs convenient aliases:
- `gclone` — Safe git clone with scanning
- `safepip` — Safe pip install with scanning
- `safenpm` — Safe npm install with scanning
- `audithere` — Scan current directory
- `qls` — List quarantine status

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

---

## 🔄 Updating Sigil

### Homebrew
```bash
brew upgrade sigil
```

### npm
```bash
npm update -g @nomark/sigil
```

### Cargo
```bash
cargo install sigil --force
```

### Docker
```bash
docker pull nomark/sigil:latest
```

### Manual / Script Install
```bash
curl -sSL https://sigilsec.ai/install.sh | sh
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
npm uninstall -g @nomark/sigil
```

### Cargo
```bash
cargo uninstall sigil
```

### Manual
```bash
sudo rm /usr/local/bin/sigil
rm -rf ~/.sigil
```

**Remove shell aliases:**
Edit your `~/.bashrc` or `~/.zshrc` and remove the block between:
```bash
# -- sigil aliases (auto-installed) --
...
# -- end sigil aliases --
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
sudo npm install -g @nomark/sigil
```

### Download fails / Binary unavailable

The installer will automatically fall back to the bash script. You can also manually install:
```bash
curl -sSL https://raw.githubusercontent.com/NOMARJ/sigil/main/bin/sigil -o sigil
chmod +x sigil
sudo mv sigil /usr/local/bin/
```

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
