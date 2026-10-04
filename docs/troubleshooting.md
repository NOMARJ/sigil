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

# If it's not there, install it (see the Installation Guide); from a source build in cli/:
sudo ./target/release/sigil install

# Or add the directory that holds the binary to your PATH
export PATH="/path/to/sigil/cli/target/release:$PATH"
```

If you installed via Homebrew, ensure your Homebrew bin directory is in your PATH:

```bash
eval "$(brew shellenv)"
```

### Permission denied on install

`sigil install` copies the binary to `/usr/local/bin/`, which requires elevated permissions.

**Fix:**

```bash
# Option 1: Use sudo, naming this sigil by its full path so root runs the same build
sudo "$(command -v sigil)" install

# Option 2: Install to a user-writable directory (it must already exist)
mkdir -p ~/bin
sigil install --path ~/bin
export PATH="$HOME/bin:$PATH"
```

### Shell aliases not loading after `sigil setup shell`

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
grep -n ">>> sigil aliases >>>" ~/.bashrc ~/.zshrc 2>/dev/null
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

**Run it verbosely** to see which step failed (`grep`, `find`, `file`, `semgrep`, `bandit`, `trufflehog` and `safety` are not needed):

```bash
sigil -v scan /path/you/are/scanning
```

**Check the path exists:**

```bash
ls -la /path/you/are/scanning
```

**YARA rules that use modules:** a YARA file given with `--rules` or a policy that imports a module (`import "pe"`, for example) needs YARA-X (`yr`) or YARA (`yara`) on your PATH. Without either, the scan exits `2` and says so. Install one, or pass `--yara-engine best-effort` to load those rules unevaluated (the scan then reports incomplete coverage).

### External scanner not detected

A "semgrep not found" message came from the legacy bash CLI (`bin/sigil`). The current CLI does not call `semgrep`, `bandit`, `trufflehog` or `safety` and never reports them missing: all eight scan phases are built in, so there is nothing to install.

### Scan shows no findings but I expect some

1. **Check file types:** every text file is content-scanned, whatever its extension. Binary files get only the structural checks, and `node_modules/`, `.git/`, `target/`, `.next/`, `__pycache__/`, virtualenvs and tool caches are never content-scanned (see [File Types Scanned](cli.md#file-types-scanned)).

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

**Check the endpoint:** `sigil login` uses `https://api.sigilsec.ai` unless you pass `--endpoint <url>` (the CLI does not read `SIGIL_API_URL`). If you pass one, check that URL instead:

```bash
curl -s "https://api.yourcompany.com/health"
```

**Check how you log in:** `sigil login` has no email or password option. Without flags it opens a browser sign-in (it prints a URL and a code to confirm); `sigil login --token <token>` checks a token you already have against the API before storing it.

### Token expired

JWT tokens have an expiration time. When the token expires, Sigil falls back to offline mode silently.

**Fix:** Re-authenticate:

```bash
sigil login
```

### Threat intelligence not loading

Logging in does not change a plain `sigil scan`. The hash lookup runs only with `sigil scan --enrich`, which prints `THREAT INTEL: <path> is a known threat` on a match and nothing otherwise; with `-v` it prints `no threat intel match for this target`, or why the lookup failed. If it fails:

1. **Check authentication status:**

```bash
ls -l ~/.sigil/token    # Exists once sigil login has succeeded
```

2. **Check token is valid:**

```bash
cat ~/.sigil/token    # Should contain a JWT string
```

3. **Re-authenticate** (there is no `sigil logout`; delete the token file instead):

```bash
rm ~/.sigil/token
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
- uses: NOMARJ/sigil@v1.3.7
```

**Check runner has required tools:**

The action runs on `ubuntu-latest` which includes all required tools. If using a custom runner, ensure `curl`, `tar`, `sha256sum` (or `shasum`) and `jq` are available: the action installs the release binary with `install.sh` and reads the JSON report with `jq`.

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

Yes, for local scans. All eight scan phases run locally. When a scanned directory has a `requirements.txt`, `package-lock.json`, `Cargo.lock` or `go.mod`, `sigil scan` also looks the listed dependencies up in OSV (and npm/PyPI packages on their registry); offline, those lookups are skipped and the scan still completes. `sigil clone`, `sigil pip` and `sigil npm` need the network to fetch what they scan. Cloud features (threat intelligence, scan history, team management) require authentication and network access.

### Does Sigil replace Snyk or Dependabot?

No. Sigil and dependency scanners are complementary. Snyk and Dependabot check dependency trees for known CVEs. Sigil scans source code for intentionally malicious patterns — install hooks, credential exfiltration, obfuscated payloads. Use both.

### What happens if I approve something that's actually malicious?

Approved code stays in `~/.sigil/quarantine/<id>/`. It is not installed or executed automatically. You still need to manually copy or use the code. Approval means "I reviewed it and accept the risk." It also pins the code's content digest in `~/.sigil/ledger/index.json`, so later scans of identical content suppress its findings (`sigil scan --ignore-ledger` reports them anyway).

### Can I undo an approval?

There is no built-in "unapprove" command, and `sigil reject` refuses an item that is already approved. Approved code lives in `~/.sigil/quarantine/<id>/`. You can delete it manually, and remove the pin by deleting the entry with that `"id"` from `~/.sigil/ledger/index.json` (`sigil ledger show <id>` prints it until then):

```bash
rm -rf ~/.sigil/quarantine/<quarantine-id>
```

### How do I reset Sigil completely?

```bash
rm -rf ~/.sigil
```

This removes all quarantined and approved code, the trust ledger, cached results, the stored token and `sigil config` values. There is no initialization step: Sigil recreates what it needs the first time a command uses it. (If you set `SIGIL_QUARANTINE_DIR`, quarantined code lives there instead.)

### What languages does Sigil scan?

Sigil scans Python (`.py`), JavaScript (`.js`, `.mjs`, `.jsx`), TypeScript (`.ts`, `.tsx`), Shell (`.sh`), and config files (`.yaml`, `.yml`, `.json`, `.toml`). Support for Go, Rust, and Ruby is planned.

### How is the risk score calculated?

The score is the sum of `(findings_in_phase * phase_weight)` across all phases. Phase weights range from 2x (credentials) to 10x (install hooks). See [Scan Phases](cli.md#scan-phases) for the full breakdown.

---

## See Also

- [Getting Started](getting-started.md) — Installation and first scan
- [CLI Command Reference](cli.md) — All commands, flags, and exit codes
- [Configuration Guide](configuration.md) — Environment variables and settings
- [MCP Integration Guide](mcp.md) — AI agent integration
