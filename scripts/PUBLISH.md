# Publishing Sigil — Quick Reference

**TL;DR for releasing a new version:**

```bash
# 1. Update versions
./scripts/bump-version.sh 0.2.0

# 2. Commit and tag
git add .
git commit -m "chore: release v0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main --tags

# 3. Wait for CI (automatic)
# - Builds binaries for all platforms
# - Publishes to npm, crates.io, Docker Hub
# - Updates Homebrew formula

# 4. Verify installations work
npm install -g @nomark/sigil
brew install nomarj/tap/sigil
cargo install sigil
```

---

## 🏷️ Version Bumping

Create `scripts/bump-version.sh`:

```bash
#!/usr/bin/env bash
# Usage: ./scripts/bump-version.sh 0.2.0

set -e

NEW_VERSION="$1"

if [ -z "$NEW_VERSION" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.2.0"
  exit 1
fi

echo "Bumping version to $NEW_VERSION..."

# Update package.json
sed -i.bak "s/\"version\": \".*\"/\"version\": \"$NEW_VERSION\"/" package.json

# Update Cargo.toml
sed -i.bak "s/version = \".*\"/version = \"$NEW_VERSION\"/" cli/Cargo.toml

# Update Formula
sed -i.bak "s/version \".*\"/version \"$NEW_VERSION\"/" Formula/sigil.rb

# Clean up backup files
find . -name "*.bak" -delete

echo "✅ Version bumped to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  git add ."
echo "  git commit -m 'chore: release v$NEW_VERSION'"
echo "  git tag -a v$NEW_VERSION -m 'Release v$NEW_VERSION'"
echo "  git push origin main --tags"
```

Make it executable:
```bash
chmod +x scripts/bump-version.sh
```

---

## 📦 What Gets Published Where

| Package Manager | Package Name | Auto-Published? | Workflow |
|----------------|--------------|-----------------|----------|
| **npm** | `@nomark/sigil` | ✅ Yes | `.github/workflows/release.yml` |
| **crates.io** | `sigil` | ✅ Yes | `.github/workflows/release.yml` |
| **Docker Hub** | `nomark/sigil` | ✅ Yes | `.github/workflows/docker.yml` |
| **Docker Hub** | `nomark/sigil-full` | ✅ Yes | `.github/workflows/docker.yml` |
| **Homebrew** | `nomarj/tap/sigil` | ✅ Yes | `.github/workflows/update-homebrew.yml` |

---

## 🔑 Required Secrets

Ensure these are set in **GitHub → Settings → Secrets**:

- `NPM_TOKEN` — npm automation token
- `CARGO_TOKEN` — crates.io API token
- `DOCKER_USERNAME` — Docker Hub username
- `DOCKER_PASSWORD` — Docker Hub access token
- `HOMEBREW_TAP_TOKEN` — GitHub PAT with repo scope

---

## 🧪 Testing Before Release

```bash
# Test local npm package
npm pack
npm install -g ./nomark-sigil-*.tgz
sigil --version
npm uninstall -g @nomark/sigil

# Test Cargo build
cd cli
cargo build --release
./target/release/sigil --version

# Test Docker build
docker build -f Dockerfile.cli -t sigil-test .
docker run --rm sigil-test --version
```

---

## 🚨 Emergency Rollback

### If npm package is broken:

```bash
# Deprecate (preferred)
npm deprecate @nomark/sigil@0.2.0 "Critical bug, use 0.2.1 instead"

# Or unpublish (only within 72 hours)
npm unpublish @nomark/sigil@0.2.0
```

### If crates.io version is broken:

```bash
cargo yank --version 0.2.0 sigil
```

### If Docker image is broken:

1. Delete tag from Docker Hub UI
2. Push new `:latest` tag:
   ```bash
   docker tag nomark/sigil:0.1.9 nomark/sigil:latest
   docker push nomark/sigil:latest
   ```

### If Homebrew formula is broken:

```bash
cd homebrew-tap
git revert HEAD
git push
```

---

## 📊 Post-Release Checklist

- [ ] Test installations:
  ```bash
  npm install -g @nomark/sigil
  brew install nomarj/tap/sigil
  cargo install sigil
  docker pull nomark/sigil:latest
  ```

- [ ] Update website (sigilsec.ai)
- [ ] Announce on social media
- [ ] Monitor GitHub Issues for problems
- [ ] Check download stats after 24h

---

## 🔄 Release Cadence

**Semantic Versioning (semver):**

- **Major** (1.0.0 → 2.0.0) — Breaking changes
- **Minor** (0.1.0 → 0.2.0) — New features, backward compatible
- **Patch** (0.1.0 → 0.1.1) — Bug fixes

**Suggested cadence:**
- **Patch releases:** As needed (hotfixes)
- **Minor releases:** Every 2-4 weeks
- **Major releases:** Every 6-12 months

---

## 📝 Release Notes Template

```markdown
## v0.2.0 — 2026-03-15

### ✨ New Features
- Added Docker image scanning (#123)
- New `sigil diff` command for comparing scans (#145)

### 🐛 Bug Fixes
- Fixed false positives in base64 detection (#156)
- Resolved Windows path handling issue (#167)

### 📚 Documentation
- Added comprehensive installation guide (#178)
- Updated API reference with new endpoints (#189)

### 🔧 Maintenance
- Upgraded dependencies (Rust 1.76, Node 20)
- Improved CI build times by 40%

### 🙏 Contributors
Thanks to @username1, @username2 for their contributions!

**Full Changelog**: https://github.com/NOMARJ/sigil/compare/v0.1.0...v0.2.0
```

---

**Quick Links:**
- [Full Deployment Checklist](./DEPLOYMENT_CHECKLIST.md)
- [npm Package](https://www.npmjs.com/package/@nomark/sigil)
- [crates.io Package](https://crates.io/crates/sigil)
- [Docker Hub](https://hub.docker.com/r/nomark/sigil)
- [Homebrew Tap](https://github.com/NOMARJ/homebrew-tap)
