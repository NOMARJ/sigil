# Troubleshooting & FAQ

Common issues and their solutions.

---

## Installation

### `sigil: command not found`

The `sigil` binary is not in your `$PATH`.

**Fix:**

```bash
# Check where sigil is installed
ls /usr/local/bin/sigil

# If it's not there, copy it
sudo cp bin/sigil /usr/local/bin/sigil
chmod +x /usr/local/bin/sigil

# Or add the bin directory to your PATH
export PATH="/path/to/sigil/bin:$PATH"
```

If you installed via Homebrew, ensure your Homebrew bin directory is in your PATH:

```bash
eval "$(brew shellenv)"
```

### Permission denied on install

`sigil install` copies the binary to `/usr/local/bin/`, which requires elevated permissions.

**Fix:**

```bash
# Option 1: Use sudo
sudo sigil install

# Option 2: Install to a user-writable directory
mkdir -p ~/bin
cp bin/sigil ~/bin/sigil
chmod +x ~/bin/sigil
export PATH="$HOME/bin:$PATH"
```

### Shell aliases not loading after `sigil aliases`

Aliases are written to your shell config file but only take effect in new sessions.

**Fix:**

```bash
# Reload your shell config
source ~/.bashrc   # if using Bash
source ~/.zshrc    # if using Zsh

# Verify aliases are defined
alias gclone
```

If aliases still don't work, check that the alias block was added to the correct file:

```bash
grep -n "SIGIL ALIASES" ~/.bashrc ~/.zshrc 2>/dev/null
```

### Homebrew formula not found

```
Error: No available formula with the name "sigil"
```

**Fix:** Tap the repository first:

```bash
brew tap nomarj/tap
brew install sigil
```

---

## Scanning

### False positives

Sigil reports a finding, but the code is legitimate.

**Understand the finding:** Every finding shows the file, line number, and pattern that triggered it. Many legitimate applications use `eval()`, `requests.post`, or `os.environ` — these are not inherently malicious, but they are behaviors that Sigil flags for review.

**Suppress specific files:** Add patterns to `.sigilignore`:

```bash
# .sigilignore
tests/
examples/
docs/
*.test.js
*.spec.py
```

**Report false positives:** If you believe a pattern should not be flagged, file an issue at [github.com/NOMARJ/sigil/issues](https://github.com/NOMARJ/sigil/issues) with the label `false-positive`.

### Scan takes too long

Large directories with many files slow down scanning.

**Fix:**

1. Add a `.sigilignore` file to skip large directories:

```bash
# .sigilignore
node_modules/
vendor/
dist/
build/
.next/
__pycache__/
```

2. Scan only specific phases:

```bash
sigil scan . --phases install_hooks,code_patterns
```

3. Raise the severity threshold:

```bash
sigil scan . --severity high
```

### `sigil scan` exits with an error

**Check required tools:**

```bash
# These are required
which grep find file

# Run config to check scanner status
sigil config
```

**Check the path exists:**

```bash
ls -la /path/you/are/scanning
```

### External scanner not detected

Sigil reports "semgrep not found" or similar.

**Fix:** Install the missing scanner:

```bash
pip install semgrep          # Advanced pattern matching
pip install bandit           # Python security linting
pip install safety           # Python CVE scanning
brew install trufflehog      # Secret detection (macOS)
```

Verify installation:

```bash
sigil config    # Shows scanner status
```

External scanners are optional. All six core scan phases run without them.

### Scan shows no findings but I expect some

1. **Check file types:** Sigil scans `.py`, `.js`, `.mjs`, `.ts`, `.tsx`, `.jsx`, `.sh`, `.yaml`, `.yml`, `.json`, `.toml`. Other file types are not scanned.

2. **Check .sigilignore:** Your ignore file may be excluding the relevant files.

3. **Run with lower severity:**

```bash
sigil scan . --severity low
```

4. **Compare with direct terminal output:**

```bash
sigil scan /full/path/to/directory
```

---

## Authentication

### `sigil login` fails

**Check network connectivity:**

```bash
curl -s https://api.sigilsec.ai/health
```

**Check API URL:** If using a custom API URL, verify it:

```bash
echo $SIGIL_API_URL
curl -s "$SIGIL_API_URL/health"
```

**Check credentials:** Ensure you are using the correct email and password.

### Token expired

JWT tokens have an expiration time. When the token expires, Sigil falls back to offline mode silently.

**Fix:** Re-authenticate:

```bash
sigil login
```

### Threat intelligence not loading

After login, scans should show a "Cloud threat enrichment" section. If missing:

1. **Check authentication status:**

```bash
sigil config    # Shows whether a token is stored
```

2. **Check token is valid:**

```bash
cat ~/.sigil/token    # Should contain a JWT string
```

3. **Re-authenticate:**

```bash
sigil logout
sigil login
```

---

## CI/CD

### GitHub Action fails to install

**Check action version:**

```yaml
# Use the main branch
- uses: NOMARJ/sigil@main

# Or pin to a specific version
- uses: NOMARJ/sigil@v0.9.0
```

**Check runner has required tools:**

The action runs on `ubuntu-latest` which includes all required tools. If using a custom runner, ensure `grep`, `find`, `file`, `git`, and `curl` are available.

### SARIF upload rejected by GitHub

**Validate the SARIF output:**

```bash
sigil scan . --format sarif > results.sarif
cat results.sarif | python -m json.tool    # Check it's valid JSON
```

**Check file size:** GitHub limits SARIF files to 10MB. For large repositories, scan specific directories or raise the severity threshold.

### Exit code mapping in CI

| Exit Code | Verdict | Suggested CI Action |
|-----------|---------|-------------------|
| `0` | CLEAN | Pass |
| `4` | LOW_RISK | Pass (with optional warning) |
| `3` | MEDIUM_RISK | Pass or fail (configurable) |
| `2` | HIGH_RISK | Fail |
| `1` | CRITICAL / Error | Fail |

**Example gate script:**

```bash
sigil scan .
case $? in
  0) echo "CLEAN — pipeline passes" ;;
  4) echo "LOW RISK — review recommended" ;;
  3) echo "MEDIUM RISK — manual review required"; exit 1 ;;
  2) echo "HIGH RISK — blocking"; exit 1 ;;
  1) echo "CRITICAL — blocking"; exit 1 ;;
esac
```

---

## IDE Plugins

### VS Code: Extension not activating

1. Check that `sigil` is in your PATH:

```bash
which sigil
```

2. Or set the binary path in VS Code settings:

**Settings > Extensions > Sigil > Binary Path:** `/usr/local/bin/sigil`

3. Reload the window: **Cmd+Shift+P > Developer: Reload Window**

### JetBrains: Plugin compatibility

The Sigil plugin requires JetBrains IDE version 2024.1 or later. Check your IDE version in **Help > About**.

### MCP: Server not connecting

1. **Check the config file path:**

```bash
# Claude Code
cat ~/.claude/claude_desktop_config.json

# Verify the path to index.js exists
ls /path/to/sigil/plugins/mcp-server/dist/index.js
```

2. **Build the MCP server if not already built:**

```bash
cd plugins/mcp-server
npm install
npm run build
ls dist/index.js    # Should exist
```

3. **Check the sigil binary is accessible:**

```bash
# The MCP server calls the sigil binary
which sigil

# Or set SIGIL_BINARY in your MCP config
```

See the [MCP Integration Guide](mcp.md) for detailed setup instructions.

---

## FAQ

### Does Sigil send my source code to the cloud?

No. Sigil never transmits source code. When authenticated, it sends only metadata: which scan rules triggered, file type distribution, risk scores, and package identifiers. See [Configuration Guide — Authentication](configuration.md#authentication) for details.

### Can I use Sigil without an internet connection?

Yes. All six scan phases run locally with no network calls. The CLI is fully functional offline. Cloud features (threat intelligence, scan history, team management) require authentication and network access.

### Does Sigil replace Snyk or Dependabot?

No. Sigil and dependency scanners are complementary. Snyk and Dependabot check dependency trees for known CVEs. Sigil scans source code for intentionally malicious patterns — install hooks, credential exfiltration, obfuscated payloads. Use both.

### What happens if I approve something that's actually malicious?

Approved code is moved to `~/.sigil/approved/`. It is not installed or executed automatically. You still need to manually copy or use the code. Approval means "I reviewed it and accept the risk."

### Can I undo an approval?

There is no built-in "unapprove" command. Approved code lives in `~/.sigil/approved/<id>/`. You can delete it manually:

```bash
rm -rf ~/.sigil/approved/<quarantine-id>
```

### How do I reset Sigil completely?

```bash
rm -rf ~/.sigil
sigil config --init
```

This removes all quarantined code, approved code, reports, logs, tokens, and configuration.

### What languages does Sigil scan?

Sigil scans Python (`.py`), JavaScript (`.js`, `.mjs`, `.jsx`), TypeScript (`.ts`, `.tsx`), Shell (`.sh`), and config files (`.yaml`, `.yml`, `.json`, `.toml`). Support for Go, Rust, and Ruby is planned.

### How is the risk score calculated?

The score is the sum of `(findings_in_phase * phase_weight)` across all phases. Phase weights range from 2x (credentials) to 10x (install hooks). See [Scan Phases Reference](scan-rules.md) for the full breakdown.

---

## See Also

- [Getting Started](getting-started.md) — Installation and first scan
- [CLI Command Reference](cli.md) — All commands, flags, and exit codes
- [Configuration Guide](configuration.md) — Environment variables and settings
- [MCP Integration Guide](mcp.md) — AI agent integration
