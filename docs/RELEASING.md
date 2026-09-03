# Releasing Sigil

Sigil ships the same scanner through a lot of front doors. This is the order to
push them in, what publishes what, and the one-time owner setup each channel
needs.

Related: [`docs/benchmarks.md`](benchmarks.md) (how the numbers are produced),
[`evaluation_results/HISTORY.md`](../evaluation_results/HISTORY.md) (every
published measurement), [`CONTRIBUTING.md`](../CONTRIBUTING.md) (day-to-day
development).

## The one rule

**Never publish a release from the GitHub web UI.** This repository uses
immutable releases: a release published before `release.yml` runs can never
receive assets, which is how v1.3.0–v1.3.4 all shipped empty. `release.yml`
creates the release itself, as a draft with every binary attached, then flips it
to published. The human flow is: push the version tag, nothing else.
`release.yml`'s `preflight` job fails fast if a published release already exists
for the tag.

## Channels at a glance

| Channel | Artifact | Trigger | Workflow | Credential |
|---|---|---|---|---|
| GitHub Release + crates.io | `sigil-cli`, 5 platform binaries, `SHA256SUMS.txt` | push tag `vX.Y.Z` | `release.yml` | `CARGO_TOKEN` (crates.io only) |
| npm wrapper | `@nomarj/sigil` | `workflow_dispatch` with `tag` (dispatched by `release.yml`) | `publish-npm.yml` | none — npm Trusted Publishing (OIDC) |
| PyPI wrapper | `sigilsec` | `workflow_dispatch` with `tag` | `publish-pypi.yml` | none — PyPI Trusted Publishing (OIDC) |
| Homebrew | `nomarj/tap` formula | release published, or `workflow_dispatch` | `update-homebrew.yml` | `HOMEBREW_TAP_TOKEN` |
| Docker | `nomark/sigil`, `nomark/sigil-full` | push tag `vX.Y.Z` | `docker.yml` | Docker Hub creds |
| MCP server | `@nomark/sigil-mcp-server` | push tag `mcp-vX.Y.Z` | `publish-mcp.yml` | `NPM_TOKEN` |
| MCP registry | `plugins/mcp-server/server.json` | manual, `mcp-publisher` | — | GitHub identity for `io.github.nomarj` |
| VS Code | `nomark.sigil-security` | push tag `vscode-vX.Y.Z` | `publish-vscode.yml` | `VSCE_PAT` |
| JetBrains | `dev.nomark.sigil` | push tag `jetbrains-vX.Y.Z` | `publish-jetbrains.yml` | JetBrains Marketplace token |
| Claude Code plugin | `sigil-security` | push tag `plugin-vX.Y.Z` | `publish-plugin.yml` | — |
| GitHub Action | `action.yml` at the repo root | nothing publishes it; callers pin `@main` or a `vX.Y.Z` tag | — | — |
| Skill listing | `sigil-skill/` | manual (`npx skills add …`) | — | — |

Tag formats, in one place:

```
vX.Y.Z             CLI: binaries, crates.io, npm wrapper, Docker, Homebrew
mcp-vX.Y.Z         MCP server npm package
vscode-vX.Y.Z      VS Code extension
jetbrains-vX.Y.Z   JetBrains plugin
plugin-vX.Y.Z      Claude Code plugin
```

The PyPI wrapper has no tag of its own — it is dispatched against an existing
`vX.Y.Z` tag, because it downloads that release's binaries.

## Version bump points

Three versions are **one unit** and must move together. They decide which binary
a user ends up running:

- `cli/Cargo.toml` → `[package] version`
- `python/src/sigil_cli/__init__.py` → `__version__`
- `python/pyproject.toml` → resolves its version from `sigil_cli.__version__`
  (dynamic), so it needs no edit — but the check verifies it still points there

(`Cargo.lock` is gitignored in this repository, so there is nothing to commit
alongside the bump.)

Everything else versions independently. Three of them are internally paired —
two files that must carry the same number or a registry rejects the publish:

- `plugins/mcp-server/package.json` **with** `plugins/mcp-server/server.json`
  (top-level `version` *and* `packages[0].version` — the registry rejects a
  package version that is not on npm)
- `plugins/claude-code/.claude-plugin/plugin.json` **with**
  `.claude-plugin/marketplace.json`
- `sigil-skill/skill.json` **with** the `metadata.version` in
  `sigil-skill/sigil-scan/SKILL.md`

The rest stand alone:

- `plugins/vscode/package.json` (also set from the tag by the workflow)
- JetBrains `pluginVersion` — from `plugins/jetbrains/gradle.properties` if that
  file exists, otherwise the `orElse(...)` default in `build.gradle.kts`
- the root `package.json` (`@nomarj/sigil`) — `publish-npm.yml` overwrites this
  with the tag version at publish time, so drift here is cosmetic

Verify the lot with:

```bash
make check-versions
```

It fails (exit 1) if the three release-critical versions disagree, prints every
other channel's version as information, and warns on the paired mismatches.
`publish-pypi.yml` runs the same script with `--expect <tag>` so a release can
never publish a wheel whose version nobody checked.

## Release checklist

### 1. Prepare

```bash
# 1. Bump the release-critical versions together
$EDITOR cli/Cargo.toml python/src/sigil_cli/__init__.py
cd cli && cargo build --release && cd ..

# 2. Confirm alignment
make check-versions

# 3. Local gates — the same ones CI runs
cd cli
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
cd ..

# 4. Self-scan gate (a required CI check)
cli/target/release/sigil scan . --no-cache --fail-on high

# 5. Python wrapper tests
python3 -m pytest python/tests -q
```

### 2. Benchmark

Re-run the detection benchmark whenever the release changes rules, scoring or
the walker, and publish the result with the release:

```bash
make benchmark \
    SIGIL_EVAL_DATASET=/path/to/malicious-software-packages-dataset \
    SIGIL_EVAL_CONTROL=/path/to/clean-control-packages
```

Then:

- commit the regenerated `evaluation_results/honest_detection_eval.{json,md}`
- add a row to [`evaluation_results/HISTORY.md`](../evaluation_results/HISTORY.md),
  transcribed verbatim from that report
- update the README accuracy table **only** with numbers that appear in the
  regenerated report, and keep its Data Source / Sample Size / Limitations block
  truthful

Method and caveats: [`docs/benchmarks.md`](benchmarks.md). Never publish a number
that was not produced by a run you actually executed.

### 3. CHANGELOG

Add the version's section to `CHANGELOG.md`: what changed, what broke, which
rules were added or narrowed, and any measurement movement (with a pointer to
the report, not a re-typed claim).

### 4. Tag and push the CLI

```bash
git tag vX.Y.Z
git push origin vX.Y.Z          # push the tag from git ONLY — never the web UI
```

`release.yml` then builds five targets (macOS arm64/x64, Linux x64/arm64,
Windows x64), attaches them plus `SHA256SUMS.txt` to a draft release, publishes
it, pushes to crates.io, dispatches `publish-npm.yml`, and triggers the Homebrew
formula update. `docker.yml` fires on the same tag.

### 5. Publish the PyPI wrapper

Wait until the GitHub release is published **with assets** — the wrapper
downloads them on first run, so publishing earlier ships a package that 404s.

Actions → **Publish PyPI Package** → Run workflow → `tag: vX.Y.Z`.

The job: checks out that tag, resolves the distribution name from
`python/pyproject.toml`, runs `scripts/check_versions.py --expect <version>`,
skips cleanly if that version is already on PyPI, builds an sdist and a wheel in
`python/`, verifies both filenames carry the expected version, and publishes with
`pypa/gh-action-pypi-publish` over OIDC.

> The alignment step runs the copy of `scripts/check_versions.py` **at the tag**.
> Tags cut before that script existed cannot be published by this workflow —
> which is the correct failure: the check is the point.

### 6. Publish the other channels, as needed

Each is independent of the CLI release and only needs a tag when that component
changed:

```bash
git tag mcp-vX.Y.Z       && git push origin mcp-vX.Y.Z         # MCP server → npm
git tag vscode-vX.Y.Z    && git push origin vscode-vX.Y.Z      # VS Code Marketplace
git tag jetbrains-vX.Y.Z && git push origin jetbrains-vX.Y.Z   # JetBrains Marketplace
git tag plugin-vX.Y.Z    && git push origin plugin-vX.Y.Z      # Claude Code plugin
```

`publish-mcp.yml` fails the run if the tag and `plugins/mcp-server/package.json`
disagree. `publish-vscode.yml` sets the version from the tag and also creates a
GitHub release for the `.vsix`.

### 7. MCP registry (after the npm package is live)

The registry hosts no packages: it validates that the npm package named in
`server.json` exists and that its `package.json` carries an `mcpName` equal to
the `server.json` `name` (`io.github.nomarj/sigil`, already set). So npm first,
registry second.

```bash
brew install mcp-publisher            # or see the registry's releases page
cd plugins/mcp-server
mcp-publisher login github            # the identity owning io.github.nomarj
mcp-publisher publish                 # validates and publishes server.json
curl "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.nomarj/sigil"
```

`server.json` is written against the
`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`
schema. Keep its two `version` fields in lockstep with the MCP server's
`package.json`; `make check-versions` warns when they drift.

### 8. Skill listing (skills.sh / ClawHub) — manual, and incomplete

`sigil-skill/` holds the agent skill: `skill.json` (the hub discovery manifest),
`sigil-scan/SKILL.md` (front matter the agent reads), reference docs, scripts and
fixtures. `skill.json` declares the install as npm `@nomarj/sigil`, so a CLI
release is enough to keep an installed skill current.

This is the one channel with no automation, and it has open gaps a maintainer
should close before treating it as a shipped product:

- **No workflow publishes or mirrors it.** Every other channel has one; this one
  is entirely manual.
- **The documented install command names a different repository.**
  `sigil-skill/README.md` says
  `npx skills add nomarj/sigil-skill --skill sigil-scan`, but the skill lives in
  *this* repository under `sigil-skill/`. Either mirror the directory to a repo
  of that name as part of the release, or change the command to name this repo
  and subdirectory. Whichever way it is resolved, one of the two must move.
- **Two versions to keep in step.** `skill.json` `version` and the SKILL.md
  front matter's `metadata.version`. `make check-versions` prints both and warns
  when they drift.

## One-time owner actions

These are account-level settings, not repository files. Each needs doing once.

### PyPI trusted publisher (required before the first `sigilsec` release)

`publish-pypi.yml` carries no token by design. Until the trusted publisher is
registered, the publish step fails with an OIDC error.

1. Sign in to <https://pypi.org> as an owner of the `sigilsec` project.
2. For a **first-ever** publish the project does not exist yet: use
   *Your projects → Publishing → Add a new pending publisher*. For an existing
   project: *Manage project → Publishing → Add a new publisher*.
3. Choose **GitHub** and enter exactly:
   - Owner: `NOMARJ`
   - Repository: `sigil`
   - Workflow name: `publish-pypi.yml`
   - Environment name: **leave blank**
4. Save. If you later add an `environment:` to the job, the publisher entry must
   be updated to name the same environment or publishing breaks.

The distribution name is `sigilsec`, not `sigil-cli` — that name is taken on
PyPI by an unrelated project. The import package is still `sigil_cli` and the
command is still `sigil`. `publish-pypi.yml` reads the name from
`python/pyproject.toml`, so renaming the distribution means re-registering the
trusted publisher.

### npm trusted publisher (already registered)

npm allows one trusted publisher per package, which is why `publish-npm.yml` is
the only workflow that runs `npm publish` for `@nomarj/sigil` and `release.yml`
dispatches it rather than publishing inline. The entry points at org `NOMARJ`,
repo `sigil`, workflow `publish-npm.yml`.

### Secrets used by the remaining channels

`CARGO_TOKEN` (crates.io), `NPM_TOKEN` (MCP server), `VSCE_PAT` (VS Code),
`HOMEBREW_TAP_TOKEN` (tap repo), `DOCKER_USERNAME` / `DOCKER_PASSWORD` (Docker
Hub), and for JetBrains `JETBRAINS_MARKETPLACE_TOKEN` plus the signing trio
`JETBRAINS_CERTIFICATE_CHAIN` / `JETBRAINS_PRIVATE_KEY` /
`JETBRAINS_PRIVATE_KEY_PASSWORD`. The MCP registry uses an interactive
`mcp-publisher login github`, not a stored secret.

## Post-release verification

Do these against the published artifacts, not a local build.

```bash
# PyPI wrapper: install, then confirm it fetches and runs the matching binary
python3 -m venv /tmp/sigil-verify && /tmp/sigil-verify/bin/pip install "sigilsec==X.Y.Z"
/tmp/sigil-verify/bin/sigil --version        # first run downloads + checksum-verifies
/tmp/sigil-verify/bin/sigil scan . --no-cache

# npm wrapper
npx --yes @nomarj/sigil@X.Y.Z --version

# MCP server: it speaks stdio, so a clean startup is the check
npx --yes @nomark/sigil-mcp-server@X.Y.Z     # then Ctrl-C
# ...and from a real client: add it to .mcp.json and confirm the tools appear

# Homebrew
brew update && brew install nomarj/tap/sigil && sigil --version

# Release assets and checksums (download an asset first — --ignore-missing
# checks only the files that are actually present, so an empty directory
# "passes" vacuously)
gh release view vX.Y.Z
gh release download vX.Y.Z --pattern 'sigil-linux-x64.tar.gz' --pattern 'SHA256SUMS.txt'
sha256sum -c --ignore-missing SHA256SUMS.txt

# crates.io / PyPI / MCP registry listings
curl -sf https://crates.io/api/v1/crates/sigil-cli/X.Y.Z > /dev/null && echo crates ok
curl -sf https://pypi.org/pypi/sigilsec/X.Y.Z/json > /dev/null && echo pypi ok
curl "https://registry.modelcontextprotocol.io/v0/servers?search=io.github.nomarj/sigil"
```

Checklist:

- [ ] Release has all five binaries plus `SHA256SUMS.txt`, and is not a draft
- [ ] `pip install sigilsec==X.Y.Z` then `sigil --version` reports X.Y.Z
- [ ] `npx @nomarj/sigil@X.Y.Z --version` reports X.Y.Z
- [ ] MCP server starts under `npx` and its tools appear in a client
- [ ] Homebrew formula updated and installs
- [ ] `make check-versions` still passes on `main`
- [ ] `evaluation_results/` and the README accuracy table match the run that was
      actually executed for this release

## If something fails mid-release

- **npm step failed** — re-run `publish-npm.yml` alone with the tag; it skips if
  the version is already published, so re-runs are safe.
- **PyPI step failed** — re-run `publish-pypi.yml` with the same tag; it also
  skips an already-published version.
- **crates.io step failed** — `release.yml` runs it *after* the GitHub release
  precisely so this cannot block the binaries; re-run the job or
  `cargo publish` from `cli/`.
- **A published release exists for the tag with no assets** — it can never
  receive them. Bump the version and push a new tag; do not fight it.
- **Versions drift after a partial release** — fix forward with a patch release.
  Never re-point an existing tag.
