# Sigil v1.0.4 - Deployment Status

**Last Updated:** 2026-02-21 04:16 UTC

---

## ✅ Successfully Deployed

### 1. npm Registry
**Package:** `@nomarj/sigil@1.0.4`
**Status:** ✅ Published
**Installation:**
```bash
npm install -g @nomarj/sigil
sigil --version
```

**Package URL:** https://www.npmjs.com/package/@nomarj/sigil

---

### 2. crates.io (Rust)
**Package:** `sigil-cli@1.0.4`
**Status:** ✅ Published
**Installation:**
```bash
cargo install sigil-cli
sigil --version
```

**Note:** The binary is named `sigil` but the crate is `sigil-cli` because the `sigil` crate name was already taken by another project.

**Package URL:** https://crates.io/crates/sigil-cli

---

### 3. GitHub Releases
**Release:** v1.0.4
**Status:** ✅ Published
**Binaries:**
- sigil-macos-arm64.tar.gz
- sigil-macos-x64.tar.gz
- sigil-linux-x64.tar.gz
- sigil-windows-x64.zip
- SHA256SUMS.txt

**Release URL:** https://github.com/NOMARJ/sigil/releases/tag/v1.0.4

**Manual Installation:**
```bash
# macOS (Apple Silicon)
curl -L https://github.com/NOMARJ/sigil/releases/download/v1.0.4/sigil-macos-arm64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/NOMARJ/sigil/releases/download/v1.0.4/sigil-macos-x64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/

# Linux
curl -L https://github.com/NOMARJ/sigil/releases/download/v1.0.4/sigil-linux-x64.tar.gz | tar xz
sudo mv sigil /usr/local/bin/

# Windows
# Download sigil-windows-x64.zip, extract, and add to PATH
```

---

## ⚠️ Pending Deployment

### 4. Homebrew
**Package:** `nomarj/tap/sigil`
**Status:** ⚠️ Needs Manual Update
**Current Version:** 1.0.1
**Target Version:** 1.0.4

**Action Required:**
The Homebrew formula needs to be manually updated with new SHA256 checksums for v1.0.4 release binaries.

**Steps to Update:**
```bash
# 1. Get SHA256 checksums from GitHub release
curl -L https://github.com/NOMARJ/sigil/releases/download/v1.0.4/SHA256SUMS.txt

# 2. Clone the homebrew-tap repository
git clone https://github.com/NOMARJ/homebrew-tap
cd homebrew-tap

# 3. Update Formula/sigil.rb with:
#    - version "1.0.4"
#    - New SHA256 checksums for each platform
#    - New download URLs (v1.0.1 → v1.0.4)

# 4. Commit and push
git add Formula/sigil.rb
git commit -m "Update sigil to v1.0.4"
git push origin main
```

**Expected Installation (after update):**
```bash
brew install nomarj/tap/sigil
sigil --version
```

---

### 5. Docker Hub
**Packages:** `nomarj/sigil:1.0.4`, `nomarj/sigil-full:1.0.4`
**Status:** ❌ Failed - Authentication Issue
**Error:** `unauthorized: incorrect username or password`

**Action Required:**
1. Verify Docker Hub credentials in GitHub Secrets:
   - `DOCKER_USERNAME` - Should be your Docker Hub username
   - `DOCKER_PASSWORD` - Should be a Docker Hub access token (not your password)

2. Generate a new Docker Hub access token:
   - Go to https://hub.docker.com/settings/security
   - Click "New Access Token"
   - Name: "GitHub Actions - Sigil"
   - Permissions: Read, Write, Delete
   - Copy the token

3. Update GitHub Secret:
   - Go to https://github.com/NOMARJ/sigil/settings/secrets/actions
   - Update `DOCKER_PASSWORD` with the new token

4. Re-run the workflow:
   - Go to https://github.com/NOMARJ/sigil/actions
   - Find the failed "Docker Build and Push" workflow for v1.0.4
   - Click "Re-run all jobs"

**Expected Installation (after fix):**
```bash
# CLI only
docker pull nomarj/sigil:1.0.4
docker run --rm nomarj/sigil:1.0.4 --version

# Full stack (API + Dashboard + CLI)
docker pull nomarj/sigil-full:1.0.4
docker-compose up
```

---

## 📊 Deployment Summary

| Platform | Package | Version | Status |
|----------|---------|---------|--------|
| npm | @nomarj/sigil | 1.0.4 | ✅ Published |
| crates.io | sigil-cli | 1.0.4 | ✅ Published |
| GitHub Releases | sigil binaries | 1.0.4 | ✅ Published |
| Homebrew | nomarj/tap/sigil | 1.0.1 | ⚠️ Needs Update |
| Docker Hub | nomarj/sigil | - | ❌ Auth Failed |
| Docker Hub | nomarj/sigil-full | - | ❌ Auth Failed |

---

## 🎯 Next Steps

1. **Update Homebrew Formula** (Manual)
   - Update Formula/sigil.rb in NOMARJ/homebrew-tap
   - Change version to 1.0.4
   - Update SHA256 checksums from v1.0.4 release

2. **Fix Docker Hub Authentication** (GitHub Secrets)
   - Generate new Docker Hub access token
   - Update DOCKER_PASSWORD secret
   - Re-run failed Docker workflow

3. **Verify All Installations** (Testing)
   - Test npm: `npm install -g @nomarj/sigil`
   - Test cargo: `cargo install sigil-cli`
   - Test Homebrew: `brew install nomarj/tap/sigil` (after update)
   - Test Docker: `docker pull nomarj/sigil:1.0.4` (after fix)

4. **Update Documentation**
   - Update README.md installation instructions
   - Add crates.io badge for sigil-cli
   - Document the npm → @nomarj/sigil change
   - Document the cargo → sigil-cli change

---

## 📝 Release Notes - v1.0.4

### Changed
- **npm:** Package scope changed from unscoped to `@nomarj/sigil`
- **crates.io:** Crate name changed to `sigil-cli` (binary still named `sigil`)
- **All platforms:** Version bumped to 1.0.4 for consistency

### Fixed
- crates.io publication now works with verified email
- Resolved crate name conflict with existing `sigil` package

### Known Issues
- Homebrew formula still at v1.0.1 (manual update required)
- Docker Hub publication blocked by auth issue (credentials need refresh)

---

## 🔧 Troubleshooting

### "command not found: sigil" after npm install
```bash
# Check npm global bin path
npm config get prefix

# Add to PATH (macOS/Linux)
echo 'export PATH="$PATH:$(npm config get prefix)/bin"' >> ~/.zshrc
source ~/.zshrc
```

### "cargo: command not found" when installing from crates.io
```bash
# Install Rust toolchain first
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Then install sigil-cli
cargo install sigil-cli
```

### Docker Hub authentication failing
- Use an **access token**, not your password
- Token needs Read + Write + Delete permissions
- Update `DOCKER_PASSWORD` GitHub secret with token
- Username should be lowercase

---

**Deployment Lead:** Claude Sonnet 4.5
**Repository:** https://github.com/NOMARJ/sigil
**Support:** https://github.com/NOMARJ/sigil/issues
