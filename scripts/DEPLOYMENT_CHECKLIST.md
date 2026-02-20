# Package Manager Deployment Checklist

This checklist covers all steps needed to publish Sigil to npm, Homebrew, Cargo, and Docker registries.

---

## 📋 Pre-Deployment Requirements

### Required Secrets (GitHub Repository Settings)

Add these to **Settings → Secrets and variables → Actions**:

- [ ] `NPM_TOKEN` — npm access token ([Create here](https://www.npmjs.com/settings/~/tokens))
- [ ] `CARGO_TOKEN` — crates.io API token ([Create here](https://crates.io/settings/tokens))
- [ ] `DOCKER_USERNAME` — Docker Hub username
- [ ] `DOCKER_PASSWORD` — Docker Hub access token ([Create here](https://hub.docker.com/settings/security))
- [ ] `HOMEBREW_TAP_TOKEN` — GitHub personal access token with repo scope ([Create here](https://github.com/settings/tokens))

### Required Repositories

- [ ] Create `NOMARJ/homebrew-tap` repository (for Homebrew formula)
  ```bash
  # On GitHub, create a new public repository: NOMARJ/homebrew-tap
  # Clone locally and add Formula/ directory
  mkdir -p Formula
  git add Formula
  git commit -m "Initial commit"
  git push
  ```

### Package Registries

- [ ] **npm** — Sign up at [npmjs.com](https://www.npmjs.com)
  - Create organization `@nomark` or use personal scope
  - Verify email address
  - Enable 2FA (recommended)

- [ ] **crates.io** — Sign up at [crates.io](https://crates.io)
  - Link GitHub account
  - Verify email

- [ ] **Docker Hub** — Sign up at [hub.docker.com](https://hub.docker.com)
  - Create repositories:
    - `nomark/sigil` (CLI only)
    - `nomark/sigil-full` (full stack)

### Local Testing

- [ ] Test npm package locally:
  ```bash
  cd /path/to/sigil
  npm pack
  npm install -g ./nomark-sigil-0.1.0.tgz
  sigil --version
  npm uninstall -g @nomark/sigil
  ```

- [ ] Test Homebrew formula locally:
  ```bash
  brew install --build-from-source ./Formula/sigil.rb
  sigil --version
  brew uninstall sigil
  ```

- [ ] Test Docker build:
  ```bash
  docker build -f Dockerfile.cli -t sigil-test .
  docker run --rm sigil-test --version
  ```

---

## 🚀 Deployment Steps

### 1. Version Bump

- [ ] Update version in all files:
  - [ ] `package.json` → `"version": "0.1.0"`
  - [ ] `cli/Cargo.toml` → `version = "0.1.0"`
  - [ ] `Formula/sigil.rb` → `version "0.1.0"`
  - [ ] `README.md` → Update version badges if present

- [ ] Update `CHANGELOG.md` with release notes

- [ ] Commit version changes:
  ```bash
  git add .
  git commit -m "chore: bump version to 0.1.0"
  git push
  ```

### 2. Create Git Tag

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

**This triggers:**
- `.github/workflows/release.yml` — Builds binaries, publishes to npm & crates.io
- `.github/workflows/docker.yml` — Builds and pushes Docker images
- `.github/workflows/update-homebrew.yml` — Updates Homebrew formula

### 3. Verify GitHub Actions

- [ ] Check [Actions tab](https://github.com/NOMARJ/sigil/actions)
- [ ] Wait for all workflows to complete (typically 5-10 minutes)
- [ ] Verify no errors in build logs

### 4. Verify npm Publication

```bash
npm view @nomark/sigil
npm install -g @nomark/sigil
sigil --version
```

**If failed:**
- Check NPM_TOKEN is valid
- Verify package name `@nomark/sigil` is available
- Check npm publish logs in GitHub Actions

### 5. Verify crates.io Publication

```bash
cargo search sigil
cargo install sigil
sigil --version
```

**If failed:**
- Check CARGO_TOKEN is valid
- Verify `cli/Cargo.toml` metadata is complete
- Ensure crate name `sigil` is available

### 6. Verify Docker Hub Publication

```bash
docker pull nomark/sigil:latest
docker pull nomark/sigil:0.1.0
docker run --rm nomark/sigil:latest --version
```

**If failed:**
- Check DOCKER_USERNAME and DOCKER_PASSWORD
- Verify repositories exist on Docker Hub
- Check multi-platform build logs

### 7. Verify Homebrew Formula

```bash
brew tap nomarj/tap
brew install sigil
sigil --version
```

**If failed:**
- Check HOMEBREW_TAP_TOKEN has repo permissions
- Verify `NOMARJ/homebrew-tap` repository exists
- Check SHA256 hashes in formula match releases
- Manually update formula if workflow failed

### 8. Test Installation on Clean Systems

Test on VMs or CI runners:

- [ ] **macOS** (Apple Silicon):
  ```bash
  brew install nomarj/tap/sigil
  sigil --version
  ```

- [ ] **macOS** (Intel):
  ```bash
  npm install -g @nomark/sigil
  sigil --version
  ```

- [ ] **Ubuntu 22.04**:
  ```bash
  cargo install sigil
  sigil --version
  ```

- [ ] **Windows 11**:
  ```powershell
  npm install -g @nomark/sigil
  sigil --version
  ```

---

## 📝 Post-Deployment

### Update Documentation

- [ ] Update [docs/installation.md](../docs/installation.md) with verified install commands
- [ ] Update [README.md](../README.md) badges (if using shields.io)
- [ ] Add release notes to GitHub Release page
- [ ] Update [ROADMAP.md](../ROADMAP.md) — mark items as complete

### Announce Release

- [ ] Tweet/social media announcement
- [ ] Post to relevant communities:
  - Hacker News
  - Reddit (r/programming, r/rust, r/nodejs)
  - Dev.to / Hashnode blog post
  - Discord/Slack communities (AI agent, security)

- [ ] Update website (sigilsec.ai) with new version
- [ ] Send update email to users (if email list exists)

### Monitor

- [ ] Check npm download stats: `npm info @nomark/sigil`
- [ ] Monitor Docker Hub pulls
- [ ] Watch GitHub Issues for installation problems
- [ ] Monitor Sentry/error tracking for runtime issues

---

## 🔄 Subsequent Releases

For version `0.2.0` and beyond:

1. **Repeat steps 1-8** above
2. **Additional checks:**
   - [ ] Migration notes for breaking changes
   - [ ] Deprecation warnings in previous version
   - [ ] Backward compatibility tested
   - [ ] Update install.sh to handle version selection

---

## ❌ Rollback Procedure

If critical bug found after release:

### npm
```bash
npm unpublish @nomark/sigil@0.1.0  # Within 72 hours
# Or deprecate:
npm deprecate @nomark/sigil@0.1.0 "Critical bug, use 0.1.1"
```

### crates.io
```bash
cargo yank --version 0.1.0 sigil
```

### Docker Hub
- Delete tags via Docker Hub UI
- Or push a new `:latest` tag pointing to stable version

### Homebrew
```bash
# Revert commit in homebrew-tap
cd homebrew-tap
git revert HEAD
git push
```

### GitHub Release
- Edit release on GitHub
- Mark as "pre-release"
- Add warning to release notes

---

## 🆘 Troubleshooting

### npm publish fails with 403

**Cause:** Token expired or insufficient permissions

**Fix:**
1. Generate new token at npmjs.com
2. Update NPM_TOKEN secret in GitHub
3. Re-run workflow

### Homebrew formula SHA256 mismatch

**Cause:** Asset not fully uploaded before formula update

**Fix:**
1. Wait for release.yml to complete
2. Manually download asset and verify hash:
   ```bash
   curl -sL https://github.com/NOMARJ/sigil/releases/download/v0.1.0/sigil-macos-arm64.tar.gz | sha256sum
   ```
3. Update formula in homebrew-tap with correct hash

### Docker build timeout

**Cause:** Large dependencies or slow network

**Fix:**
1. Enable Docker layer caching (already in workflow)
2. Reduce image size by cleaning apt cache
3. Split into multiple jobs if needed

### Binary not executable after npm install

**Cause:** Permissions not set in install-binary.js

**Fix:**
1. Verify `chmod 0o755` is called in install script
2. Test with: `npm pack && tar -xzf *.tgz && ls -la package/bin/`

---

## 📊 Success Metrics

After deployment, track:

- [ ] **Downloads:**
  - npm: `npm info @nomark/sigil`
  - crates.io: [https://crates.io/crates/sigil](https://crates.io/crates/sigil)
  - Docker: Docker Hub dashboard
  - Homebrew: `brew info nomarj/tap/sigil`

- [ ] **GitHub:**
  - Stars, forks, watchers
  - Issue velocity
  - PR contributions

- [ ] **User Feedback:**
  - Twitter/social mentions
  - Issue reports
  - Community discussions

---

**Last Updated:** 2026-02-21
