# Sigil Scripts & Deployment Tools

This directory contains automation scripts and deployment documentation for publishing Sigil to package managers.

---

## 📁 Contents

### Deployment Scripts

| Script | Purpose |
|--------|---------|
| [`bump-version.sh`](./bump-version.sh) | Update version across all package manifests |
| [`install-binary.js`](./install-binary.js) | npm postinstall script - downloads platform binary |
| [`cleanup.js`](./cleanup.js) | npm preuninstall script - removes installed binaries |

### Documentation

| Document | Purpose |
|----------|---------|
| [`DEPLOYMENT_CHECKLIST.md`](./DEPLOYMENT_CHECKLIST.md) | Complete deployment checklist for all package managers |
| [`PUBLISH.md`](./PUBLISH.md) | Quick reference guide for releasing new versions |

---

## 🚀 Quick Start: Publishing a Release

### 1. Bump Version

```bash
./scripts/bump-version.sh 0.2.0
```

This updates:
- `package.json` (root npm package)
- `cli/Cargo.toml` (Rust crates.io)
- `Formula/sigil.rb` (Homebrew)
- `plugins/*/package.json` (IDE extensions)

### 2. Update Changelog

Edit `CHANGELOG.md` with release notes.

### 3. Commit & Tag

```bash
git add .
git commit -m "chore: release v0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main --tags
```

### 4. Wait for CI

GitHub Actions automatically:
- ✅ Builds binaries for all platforms
- ✅ Publishes to **npm** (`@nomark/sigil`)
- ✅ Publishes to **crates.io** (`sigil`)
- ✅ Pushes to **Docker Hub** (`nomark/sigil`)
- ✅ Updates **Homebrew** formula (`nomarj/tap/sigil`)

### 5. Verify

```bash
npm install -g @nomark/sigil
brew install nomarj/tap/sigil
cargo install sigil
docker pull nomark/sigil:latest
```

---

## 📦 Package Manager Matrix

| Platform | Package Name | Auto-Deploy | Workflow |
|----------|--------------|-------------|----------|
| npm | `@nomark/sigil` | ✅ | `.github/workflows/release.yml` |
| crates.io | `sigil` | ✅ | `.github/workflows/release.yml` |
| Docker Hub | `nomark/sigil` | ✅ | `.github/workflows/docker.yml` |
| Docker Hub | `nomark/sigil-full` | ✅ | `.github/workflows/docker.yml` |
| Homebrew | `nomarj/tap/sigil` | ✅ | `.github/workflows/update-homebrew.yml` |

---

## 🔑 Required Secrets

Ensure these are set in **GitHub → Settings → Secrets → Actions**:

- `NPM_TOKEN` — npm automation token
- `CARGO_TOKEN` — crates.io API token
- `DOCKER_USERNAME` — Docker Hub username
- `DOCKER_PASSWORD` — Docker Hub access token
- `HOMEBREW_TAP_TOKEN` — GitHub PAT with repo scope

---

## 🧪 Testing Locally

### Test npm package

```bash
npm pack
npm install -g ./nomark-sigil-0.2.0.tgz
sigil --version
npm uninstall -g @nomark/sigil
```

### Test Cargo build

```bash
cd cli
cargo build --release
./target/release/sigil --version
```

### Test Docker image

```bash
docker build -f Dockerfile.cli -t sigil-test .
docker run --rm sigil-test --version
```

---

## 📚 Full Documentation

- [**Complete Deployment Checklist**](./DEPLOYMENT_CHECKLIST.md) — Detailed step-by-step guide
- [**Quick Publish Guide**](./PUBLISH.md) — TL;DR for maintainers
- [**Installation Guide**](../docs/installation.md) — User-facing install docs

---

## 🚨 Troubleshooting

### npm publish fails

- Check `NPM_TOKEN` is valid
- Verify package name is available
- Check workflow logs

### Cargo publish fails

- Check `CARGO_TOKEN` is valid
- Ensure `cli/Cargo.toml` has complete metadata
- Verify crate name `sigil` is not taken

### Docker push fails

- Check `DOCKER_USERNAME` and `DOCKER_PASSWORD`
- Verify repositories exist on Docker Hub
- Check multi-arch build logs

### Homebrew formula update fails

- Check `HOMEBREW_TAP_TOKEN` has repo access
- Verify `NOMARJ/homebrew-tap` exists
- Check SHA256 hashes match releases

---

## 🔄 Release Cadence

**Recommended:**
- **Patch** (0.1.1) — Hotfixes, as needed
- **Minor** (0.2.0) — Every 2-4 weeks
- **Major** (1.0.0) — Every 6-12 months

---

## 📝 Changelog Template

```markdown
## v0.2.0 — 2026-03-15

### ✨ New Features
- Feature description (#PR)

### 🐛 Bug Fixes
- Fix description (#PR)

### 📚 Documentation
- Doc updates (#PR)

### 🙏 Contributors
Thanks to @user for contributions!
```

---

**Need help?** See [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md) for complete instructions.
