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

**Hide lower-severity findings:** `--severity` drops findings below a level from the report, the score, the verdict and the exit code, so it can turn a failing `--fail-on` or `--fail-on-verdict` gate into a pass:

```bash
sigil scan . --severity high
```

**Report false positives:** If you believe a pattern should not be flagged, file an issue at [github.com/NOMARJ/sigil/issues](https://github.com/NOMARJ/sigil/issues) with the label `false-positive`.

### Scan takes too long

Large directories with many files slow down scanning.

**Fix:**

1. Add a `.sigilignore` file to skip large directories (`node_modules/`, `.next/`, `__pycache__/` and virtualenvs are already skipped):

```bash
# .sigilignore
vendor/
dist/
build/
```

2. Scan only specific phases:

```bash
sigil scan . --phases install_hooks,code_patterns
```

`--severity` does not make a scan faster: it drops findings below that level from the report, the score, the verdict and the exit code, so it can turn a failing gate into a pass (see [False positives](#false-positives)).

### `sigil pip` or `sigil npm` refuses a package or fails to download it

By default `sigil pip` and `sigil npm` fetch only what needs no build, so the package's own code cannot run before the scan. The error says which case you hit:

- **`will not download …: it is a local path` (or an archive or tarball file path)**: Sigil fetches registry packages by name. To check a file or directory you already have, scan it where it is with `sigil scan <path>` (archives are opened and read), which runs nothing from it. `--allow-build-scripts` is not the way to scan a project directory: pip would run its build backend and then save nothing to quarantine (the command fails).
- **`will not download …: it is a URL` (or a VCS reference, git spec, `owner/repo` shorthand)**: pip builds these and npm runs their `prepare` script while fetching them. Name a registry package instead (`sigil pip requests`, `sigil npm left-pad`). For code you already trust, `--allow-build-scripts` accepts them, with a warning.
- **`… is the release pip install … would install here, and pip found no prebuilt wheel of it`**: that release is published only as a source distribution (or has no wheel for your platform and Python). Sigil does not scan an older release in its place, because `pip install` would not install that one. Pin a version that has a wheel (`sigil pip <name>==<version>`) and install that same version. To read the source distribution without building it, scan its file from the index: `sigil scan <URL of the .tar.gz>` (the link is on the project's PyPI download page) unpacks it and runs nothing from it. `--allow-build-scripts` would build it, which runs its setup code.
- **`will not run pip with this configuration: download.requirement …`** (or `global.constraint`, `global.global-option`): a pip config file adds requirements to every `pip download`, or makes pip build source distributions. A requirement, constraint or editable entry that names a path or URL is built by pip, and a `global-option`, `build-option` or `install-option` makes pip drop `--only-binary=:all:` (it logs `Implying --no-binary=:all:`) and build source distributions by running their setup code. Sigil does not read the files these settings name, so a constraints file that only pins versions is refused too. Remove the setting, or run with `PIP_CONFIG_FILE=/dev/null`, which skips every pip config file, index settings included: give your index in the environment for that command (`PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.example.com/simple sigil pip requests`, plus `PIP_EXTRA_INDEX_URL` or `PIP_CERT` if you use them). An empty `PIP_CONSTRAINT` does not override a config file's constraint. `PIP_REQUIREMENT`, `PIP_CONSTRAINT`, `PIP_EDITABLE`, `PIP_GLOBAL_OPTION`, `PIP_BUILD_OPTION` and `PIP_INSTALL_OPTION` in the environment are left out of pip's environment for the download, with a note.
- **`pip listed no release of …`**, or **`unknown command "index"`**: unpinned and ranged specs are resolved with `pip index versions`, which needs pip 21.2 or later. With an older pip, upgrade it or pin a version with `==`. If pip said `No matching distribution found`, the name is not on the index (check the spelling) or no release matches.
- **`… so it needs a person to confirm, and there is no terminal to ask on`**: `--allow-build-scripts` runs the package's own code on your machine before the scan, so Sigil asks you to type `yes` at a terminal and refuses (exit 2, nothing downloaded or run) when stdin or stderr is not one: a pipe, a CI job, a shell that has no terminal. A script or job that has decided to trust the code sets `SIGIL_ALLOW_BUILD_SCRIPTS=1` for the command. This confirmation stops accidental and unattended use. It cannot tell a person from a program: anything that opens a pseudo-terminal and types `yes`, or sets the variable, passes it. The Claude Code hook asks before it runs a command that carries the flag, but that is a reading of the command's text, not a boundary either.
- **`will not scan name@version: you asked for … but the registry's description of that release says the package is named …`**: you asked for one package name and the registry's metadata for the release it resolved gives another. A scan of one package says nothing about another, so Sigil stops (exit 2, nothing downloaded). Check the spelling and `npm config get registry`.
- **`could not read what npm resolves <spec> to: the registry gives … as a package name`** (or **`… as the version of …`**): the registry's manifest gives the package a name or version with a path separator or a control character, which Sigil would make into the file name it writes and print, so it stops (exit 2, nothing downloaded). Check `npm config get registry` and the package.
- **`will not download name@version: the registry gives … as the tarball`**: the npm registry you use points that release at a git repository, a local path or a string npm would read as one, which `npm install` would clone or pack by running its `prepare` script. Check `npm config get registry`.
- **`… is not the host of the registry npm resolved the package from`** (or **`… a URL with a user name or password in it`**): Sigil downloads the tarball itself, from the host of the registry npm resolved the package from (`npm config get registry`, or `@scope:registry` for a scoped name) and without credentials, so a tarball URL on another host is refused (exit 2). That includes a mirror whose metadata still names `registry.npmjs.org` (see `npm config get replace-registry-host`), and a CDN. Point npm at a registry that names its own host, or, for code you already trust, use `--allow-build-scripts`.
- **`could not download the tarball of name@version: … HTTP 401`** (or `403`): the registry wants credentials for the tarball. Sigil sends none, so that no token of npm's goes anywhere but through npm itself. Download the tarball yourself with your own tool (its URL is the `dist.tarball` of `npm view <name>@<version> --json`) and scan the file with `sigil scan <file>.tgz`. A proxy that is set only in npm's config (`proxy`, `https-proxy`) is not used by that download: set `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` in the environment. A registry on a private network address works because you configured it; a redirect to another private address is refused unless `SIGIL_ALLOW_PRIVATE_URLS=1`.
- **`will not scan name@version: the tarball Sigil downloaded hashes to …`** (or `the registry gives no integrity or shasum`): the tarball does not match the registry's `dist.integrity` (or `dist.shasum`), so `npm install` would refuse it too (`EINTEGRITY`), or the registry gives nothing to check it against. Try again later, and check which registry or proxy npm uses here.
- **`sigil pip was given a version twice`** (or `sigil npm …`): the package already names a version (`wheelok>=1`, `left-pad@1`) and `-V` names another. Give the version in the spec or with `-V`, not both.
- **`could not run pip config list: … (is pip installed and on PATH?)`** (or `npm view`): pip or npm is not installed or not on PATH. Sigil runs them to read your configuration and to look up the release.
- **`pip saved nothing into quarantine`**: pip finished without a file to scan, as it does for a local project directory with `--allow-build-scripts` (pip builds its metadata but does not copy a directory). Scan the directory where it is: `sigil scan <path>`.
- **A relative `PIP_FIND_LINKS` or `find-links`**: `sigil pip` runs pip from your current directory, as `pip install` does, so a relative setting means the same to both.

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

1. **Check file types:** every text file is content-scanned, whatever its extension. Binary files get only the structural checks, and `node_modules/`, `.git/`, `target/`, `.next/`, `__pycache__/`, virtualenvs and tool caches are never content-scanned (see [File Types Scanned](cli.md#file-types-scanned)). When you scan a git repository from its root, files its `.gitignore` excludes are not scanned (scanning a subdirectory does not apply the root `.gitignore`): check with `git check-ignore -v <file>`, or scan a copy outside the repository.

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

The endpoint applies to that login only and is not saved: `sigil fetch`, `sigil report` and the cloud options of `sigil scan` always use `https://api.sigilsec.ai`.

**Check how you log in:** `sigil login` has no email or password option. Without flags it runs a browser sign-in: it prints a URL and a code for you to open and confirm; `sigil login --token <token>` checks a token you already have against the API before storing it.

### Token expired

The access token the `sigil login` browser sign-in stores expires, and the CLI neither checks nor refreshes it. Once the API rejects it, `sigil fetch`, `sigil report` and `sigil explain` fail with an API error, `sigil scan --submit` and `--enhanced` print a warning and keep the local result, and `--enrich` reports the failure only with `-v`.

**Fix:** Re-authenticate:

```bash
sigil login
```

### Threat intelligence not loading

Logging in does not change a plain `sigil scan`. The hash lookup runs only with `sigil scan --enrich`, and only on a fresh scan: when the scan reuses a cached result (it prints `sigil: using cached result`, the default when you re-scan an unchanged directory or a copy of content scanned before), `--enrich`, `--submit` and `--enhanced` are skipped without a message, so add `--no-cache`:

```bash
sigil -v scan . --enrich --no-cache
```

`--enrich` prints `THREAT INTEL: <path> is a known threat` when the API reports a match and nothing otherwise; with `-v` it prints `no threat intel match for this target`, or why the lookup failed. The current API answers a match in a format the CLI cannot parse, so a match is not shown: it appears only with `-v`, as `cloud enrichment unavailable: failed to parse response`. No output therefore does not mean the target is not a known threat. The threat database needs a Pro plan; the API refuses the lookup otherwise. If it fails:

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

For `sigil scan`:

| Exit Code | Meaning | Suggested CI Action |
|-----------|---------|-------------------|
| `0` | No finding at or above `--fail-on` (default `high`), and neither `--fail-on-verdict` nor `--fail-on-incomplete` applies | Pass |
| `1` | A finding at or above `--fail-on`, a verdict at or above `--fail-on-verdict`, or, with `--fail-on-incomplete`, part of the target not fully inspected | Fail |
| `2` | Scan error: invalid path or flags, or the scan could not run | Fail, and fix the job |

The exit code follows the findings, not the verdict: with the default `--fail-on high`, a MEDIUM RISK result exits `0` when none of its findings is High or Critical, and `1` when one is. To gate on the verdict as well, add `--fail-on-verdict` (see [Exit Codes](cli.md#exit-codes)). `sigil scan` of a repository URL runs the `sigil clone` workflow instead: it exits `1` for any verdict above LOW RISK and ignores `--fail-on`, `--fail-on-verdict` and `--fail-on-incomplete`, so in CI clone first (allowing the clone step's own exit `1`), find the id with `sigil list`, and scan `~/.sigil/quarantine/<id>`.

`sigil clone`, `sigil pip` and `sigil npm` have no `--fail-on`: they exit `0` for a LOW RISK verdict, `1` for any other verdict (MEDIUM RISK included), and `2` when the command itself fails.

**Example gate script:**

```bash
sigil scan . --fail-on-verdict medium
case $? in
  0) echo "Verdict below MEDIUM RISK, no High or Critical finding — pipeline passes" ;;
  1) echo "MEDIUM RISK or worse, or a High or Critical finding — blocking"; exit 1 ;;
  *) echo "Scan error — fix the job"; exit 2 ;;
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
# Claude Code: list the servers it has registered. It keeps user- and
# local-scope servers in ~/.claude.json and project servers in .mcp.json
claude mcp list

# Claude Desktop (not Claude Code) reads claude_desktop_config.json, in
# ~/Library/Application Support/Claude/ (macOS), ~/.config/Claude/ (Linux)
# or %APPDATA%\Claude\ (Windows)

# Verify the path to index.js exists
ls /path/to/sigil/plugins/mcp-server/dist/index.js
```

The `sigil` binary also has a built-in MCP server that needs no Node.js build: `claude mcp add sigil -- sigil mcp` (see the [MCP Integration Guide](mcp.md#built-in-server-no-nodejs-nothing-else-to-install)).

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

Not unless you, or your organisation's scan policy, ask it to. Without a policy that turns on LLM review, a plain `sigil scan` sends no code anywhere; the only thing it sends by default is the names and versions of the dependencies listed in a lockfile, for the OSV and npm/PyPI lookups, and, for CVE-numbered advisories, those CVE IDs to FIRST EPSS (plus a download of the CISA KEV catalogue). Logging in does not change that. The options that do send code are these: `sigil scan --submit` sends the scan result, including each finding's file path and the flagged source line; `sigil explain scan.json` sends every finding in that report, flagged source lines included, to the Sigil API for AI adjudication; `--enhanced` (Pro) uploads the contents of up to 50 eligible text files under the target directory, collected independently of scan exclusions, plus the scan result: every finding with its flagged source line, including findings in files outside those 50 (a secret flagged in `.env`, for example); and `--llm-review`, or `llm_review: true` in your organisation policy (`SIGIL_POLICY_FILE`) or a `--config` file, sends masked excerpts to the configured model endpoint (`sigil config --policy`, given the same `--config`, shows whether it is on). See [Data Handling](data-handling.md) for details.

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

This removes all quarantined and approved code, the trust ledger, cached results, the stored token and `sigil config` values. It also deletes residue backups (`~/.sigil/backups/`, so `sigil residue rollback` can no longer undo a `sigil residue apply`), fetched signatures, provider configs, known-good indexes, provenance baselines, any rule packs in `packs/` and the binary the PyPI package caches in `bin/`, along with everything else under `~/.sigil`; copy out what you need first. There is no initialization step: Sigil recreates what it needs the first time a command uses it. (If you set `SIGIL_QUARANTINE_DIR`, quarantined code lives there instead.)

### What languages does Sigil scan?

Every text file is content-scanned, whatever its language or extension, including markdown, agent instruction files, manifests and configuration (when you scan a git repository from its root, files its `.gitignore` excludes are not scanned; scanning a subdirectory does not apply the root `.gitignore`). Some rules apply only to certain file names or extensions (install hooks key on `setup.py` and `package.json`, for example), and more of them cover Python and JavaScript than Go or Ruby. See [File Types Scanned](cli.md#file-types-scanned).

### How is the risk score calculated?

Each finding scores its severity (Low 1, Medium 2, High 3, Critical 5) times its weight, which is its phase's weight unless the rule sets its own, and the score is the sum, counting at most three findings per (rule, file) pair. Phase weights run from 1x (provenance) to 10x (install hooks, prompt injection). The [Getting Started](getting-started.md#scanning-a-git-repository) example scores 3×5 (a High code pattern) + 1×3 (a Low network call) + 1×2 (a Low credential read) = 20. The verdict is not a score threshold: see [Verdicts and Scoring](cli.md#verdicts-and-scoring).

---

## See Also

- [Getting Started](getting-started.md) — Installation and first scan
- [CLI Command Reference](cli.md) — All commands, flags, and exit codes
- [Configuration Guide](configuration.md) — Environment variables and settings
- [MCP Integration Guide](mcp.md) — AI agent integration
