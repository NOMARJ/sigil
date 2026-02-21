#!/usr/bin/env bash
# Bump version across all package manifests
# Usage: ./scripts/bump-version.sh 0.2.0

set -e

NEW_VERSION="$1"

if [ -z "$NEW_VERSION" ]; then
  echo "❌ Version required"
  echo ""
  echo "Usage: $0 <version>"
  echo "Example: $0 0.2.0"
  exit 1
fi

# Validate semver format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
  echo "❌ Invalid version format: $NEW_VERSION"
  echo "Expected format: X.Y.Z or X.Y.Z-beta.1"
  exit 1
fi

echo "🔄 Bumping version to $NEW_VERSION..."
echo ""

# Update package.json (root npm package)
if [ -f "package.json" ]; then
  sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" package.json
  echo "✅ package.json → $NEW_VERSION"
fi

# Update Cargo.toml (Rust CLI)
if [ -f "cli/Cargo.toml" ]; then
  sed -i.bak "s/^version = \"[^\"]*\"/version = \"$NEW_VERSION\"/" cli/Cargo.toml
  echo "✅ cli/Cargo.toml → $NEW_VERSION"
fi

# Update Homebrew Formula
if [ -f "Formula/sigil.rb" ]; then
  sed -i.bak "s/version \"[^\"]*\"/version \"$NEW_VERSION\"/" Formula/sigil.rb
  echo "✅ Formula/sigil.rb → $NEW_VERSION"
fi

# Update MCP server package
if [ -f "plugins/mcp-server/package.json" ]; then
  sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" plugins/mcp-server/package.json
  echo "✅ plugins/mcp-server/package.json → $NEW_VERSION"
fi

# Update VS Code extension
if [ -f "plugins/vscode/package.json" ]; then
  sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" plugins/vscode/package.json
  echo "✅ plugins/vscode/package.json → $NEW_VERSION"
fi

# Clean up backup files
find . -name "*.bak" -delete

echo ""
echo "✅ Version bumped to $NEW_VERSION across all packages"
echo ""
echo "📝 Next steps:"
echo ""
echo "  1. Update CHANGELOG.md with release notes"
echo "  2. Commit changes:"
echo "     git add ."
echo "     git commit -m 'chore: release v$NEW_VERSION'"
echo ""
echo "  3. Create and push tag:"
echo "     git tag -a v$NEW_VERSION -m 'Release v$NEW_VERSION'"
echo "     git push origin main --tags"
echo ""
echo "  4. Wait for CI to publish to:"
echo "     - npm: @nomark/sigil"
echo "     - crates.io: sigil"
echo "     - Docker Hub: nomark/sigil"
echo "     - Homebrew: nomarj/tap/sigil"
echo ""
