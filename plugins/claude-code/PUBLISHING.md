# Publishing Guide for Sigil Security Plugin

This guide explains how to publish new versions of the Sigil Security plugin for Claude Code.

## Release Process Overview

1. Update version numbers
2. Update CHANGELOG.md
3. Test locally
4. Create git tag
5. Push tag to trigger GitHub Actions
6. Verify release artifacts
7. Announce release

## Prerequisites

- Write access to the repository
- Git configured with commit signing (recommended)
- Claude Code installed for testing

## Step-by-Step Release

### 1. Update Version Numbers

Update the version in both plugin manifests:

**`plugins/claude-code/.claude-plugin/plugin.json`:**
```json
{
  "name": "sigil-security",
  "version": "1.1.0",  // ← Update this
  ...
}
```

**`plugins/claude-code/.claude-plugin/marketplace.json`:**
```json
{
  ...
  "plugins": [
    {
      "name": "sigil-security",
      "version": "1.1.0",  // ← Update this
      ...
    }
  ]
}
```

Use [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH` (e.g., 1.0.0)
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### 2. Update CHANGELOG.md

Add a new section for the release:

```markdown
## [1.1.0] - 2026-03-15

### Added
- New skill for scanning git diffs
- Support for custom scan rules

### Changed
- Improved security-auditor agent analysis
- Updated hook patterns for better detection

### Fixed
- False positive in base64 detection
- Quarantine manager approval bug

### Security
- Enhanced credential detection patterns
```

Use these categories:
- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security improvements

### 3. Test Locally

Before releasing, test the plugin thoroughly:

```bash
# Test from local directory
cd /path/to/sigil
claude --plugin-dir ./plugins/claude-code

# In Claude Code session, test all skills:
/sigil-security:scan-repo .
/sigil-security:scan-package lodash
/sigil-security:scan-file bin/sigil
/sigil-security:quarantine-review

# Test agents:
@security-auditor analyze this code
@quarantine-manager show status

# Test hooks by mentioning trigger words:
"I want to clone a repository"
"Let me install this package"
```

Verify:
- [ ] All skills execute without errors
- [ ] Agents respond appropriately
- [ ] Hooks trigger suggestions
- [ ] Sigil CLI integration works
- [ ] Version displays correctly

### 4. Commit Changes

```bash
# Stage changes
git add plugins/claude-code/.claude-plugin/plugin.json
git add plugins/claude-code/.claude-plugin/marketplace.json
git add plugins/claude-code/CHANGELOG.md

# Commit
git commit -m "chore: prepare plugin release v1.1.0"

# Push to main
git push origin main
```

### 5. Create Git Tag

Create a tag in the format `plugin-vX.Y.Z`:

```bash
# Create annotated tag
git tag -a plugin-v1.1.0 -m "Release Sigil Security plugin v1.1.0"

# Push tag to trigger GitHub Actions
git push origin plugin-v1.1.0
```

This will automatically trigger the `.github/workflows/publish-plugin.yml` workflow.

### 6. Monitor GitHub Actions

Watch the workflow at: `https://github.com/NOMARJ/sigil/actions`

The workflow will:
1. ✅ Validate plugin structure (JSON, skills, agents)
2. 📦 Create release archive (`.tar.gz`)
3. 🚀 Publish GitHub Release
4. 📝 Update marketplace version on main branch
5. 📣 Notify success

### 7. Verify Release

After the workflow completes:

**Check GitHub Release:**
1. Go to: `https://github.com/NOMARJ/sigil/releases`
2. Verify release `plugin-v1.1.0` exists
3. Check release notes are correct
4. Download and verify the `.tar.gz` artifact

**Test Installation:**
```bash
# Install from marketplace
claude plugin marketplace add https://github.com/NOMARJ/sigil.git
claude plugin install sigil-security@sigil

# Verify version
claude plugin list | grep sigil-security
# Should show: sigil-security@1.1.0 (enabled)

# Test functionality
claude
/sigil-security:scan-repo .
```

### 8. Announce Release

**Update documentation:**
- [ ] Update README.md if needed
- [ ] Update docs/claude-code-plugin.md with new features
- [ ] Add migration guide if breaking changes

**Announce:**
- [ ] Post on GitHub Discussions
- [ ] Update website (sigilsec.ai)
- [ ] Tweet from @nomark_ai (if applicable)
- [ ] Notify users on Discord/Slack

**Example announcement:**
```markdown
## 🎉 Sigil Security Plugin v1.1.0 Released

We've just released v1.1.0 of the Sigil Security plugin for Claude Code!

### What's New
- New skill for scanning git diffs
- Enhanced security analysis with improved agents
- Better false positive detection

### Upgrade
```bash
claude plugin update sigil-security
```

### Learn More
- [Release Notes](https://github.com/NOMARJ/sigil/releases/tag/plugin-v1.1.0)
- [Documentation](https://github.com/NOMARJ/sigil/blob/main/docs/claude-code-plugin.md)
```

## Manual Publishing (Fallback)

If GitHub Actions fails, you can publish manually:

### 1. Create Archive

```bash
cd plugins/claude-code
tar -czf ../../sigil-security-plugin-1.1.0.tar.gz \
  .claude-plugin/ \
  skills/ \
  agents/ \
  hooks/ \
  README.md \
  CHANGELOG.md
cd ../..
```

### 2. Create GitHub Release

```bash
# Install gh CLI if needed
brew install gh

# Create release
gh release create plugin-v1.1.0 \
  --title "Sigil Security Plugin v1.1.0" \
  --notes-file plugins/claude-code/CHANGELOG.md \
  sigil-security-plugin-1.1.0.tar.gz
```

### 3. Update Marketplace

Manually update `plugins/claude-code/.claude-plugin/marketplace.json` and push to main:

```bash
# Update version in marketplace.json
jq '.plugins[0].version = "1.1.0"' \
  plugins/claude-code/.claude-plugin/marketplace.json > tmp.json
mv tmp.json plugins/claude-code/.claude-plugin/marketplace.json

# Commit and push
git add plugins/claude-code/.claude-plugin/marketplace.json
git commit -m "chore: update plugin marketplace to v1.1.0"
git push origin main
```

## Hotfix Releases

For urgent bug fixes:

1. Create a hotfix branch from the release tag:
   ```bash
   git checkout -b hotfix/1.1.1 plugin-v1.1.0
   ```

2. Make the fix and update version to `1.1.1`

3. Commit and create tag:
   ```bash
   git commit -m "fix: critical security patch"
   git tag -a plugin-v1.1.1 -m "Hotfix v1.1.1"
   ```

4. Push to main and tag:
   ```bash
   git checkout main
   git merge hotfix/1.1.1
   git push origin main
   git push origin plugin-v1.1.1
   ```

## Pre-release Testing

For beta releases:

```bash
# Create pre-release tag
git tag -a plugin-v1.2.0-beta.1 -m "Beta release v1.2.0-beta.1"
git push origin plugin-v1.2.0-beta.1
```

GitHub Actions will create a pre-release. Users can test with:

```bash
# Install specific version
claude plugin install sigil-security@sigil#plugin-v1.2.0-beta.1
```

## Rollback

If a release has critical issues:

1. **Delete the release:**
   ```bash
   gh release delete plugin-v1.1.0 --yes
   git tag -d plugin-v1.1.0
   git push origin :refs/tags/plugin-v1.1.0
   ```

2. **Revert marketplace:**
   ```bash
   # Update marketplace.json to previous version
   jq '.plugins[0].version = "1.0.0"' \
     plugins/claude-code/.claude-plugin/marketplace.json > tmp.json
   mv tmp.json plugins/claude-code/.claude-plugin/marketplace.json

   git add plugins/claude-code/.claude-plugin/marketplace.json
   git commit -m "chore: rollback plugin to v1.0.0"
   git push origin main
   ```

3. **Notify users:**
   - Post on GitHub Discussions
   - Update release notes with rollback notice

## Troubleshooting

### GitHub Actions workflow fails

**Check logs:**
```bash
gh run list --workflow=publish-plugin.yml
gh run view <run-id> --log
```

**Common issues:**
- Invalid JSON in plugin.json → Run `jq empty <file>` to validate
- Missing SKILL.md files → Check all skills have SKILL.md
- Permission errors → Verify GitHub token has write access

### Version mismatch errors

**Cause:** Version in plugin.json doesn't match tag.

**Fix:**
```bash
# Ensure versions match
TAG_VERSION=$(git describe --tags --abbrev=0 | sed 's/plugin-v//')
PLUGIN_VERSION=$(jq -r '.version' plugins/claude-code/.claude-plugin/plugin.json)

if [ "$TAG_VERSION" != "$PLUGIN_VERSION" ]; then
  echo "Version mismatch: tag=$TAG_VERSION, plugin=$PLUGIN_VERSION"
fi
```

### Installation fails for users

**Cause:** Marketplace cache.

**Ask users to:**
```bash
# Clear plugin cache
rm -rf ~/.claude/cache/plugins/sigil-security

# Reinstall
claude plugin install sigil-security@sigil
```

## Release Checklist

Use this checklist for each release:

- [ ] Updated version in `plugin.json`
- [ ] Updated version in `marketplace.json`
- [ ] Updated `CHANGELOG.md` with changes
- [ ] Tested all skills locally
- [ ] Tested all agents locally
- [ ] Tested hooks trigger correctly
- [ ] Committed changes to main
- [ ] Created and pushed git tag
- [ ] GitHub Actions workflow succeeded
- [ ] GitHub Release created
- [ ] Verified installation from marketplace
- [ ] Updated documentation if needed
- [ ] Announced release

## Support

For publishing issues:
- **GitHub Actions**: Check workflow logs
- **Marketplace**: Verify `marketplace.json` format
- **Support**: team@sigilsec.ai
