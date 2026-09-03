# Contributing to Sigil

Thanks for your interest in making AI agent code safer. Sigil is built by [NOMARK](https://nomark.ai) and contributions from the community are welcome.

## Ways to Contribute

**Report malicious packages.** Found a dodgy MCP server, agent skill, or package? Report it via `sigil report <package>` from the CLI, or open an issue with the `threat-report` label.

**Report bugs.** Something not scanning right? False positive driving you mad? Open an issue using the bug report template.

**Suggest features.** Got an idea? Start a thread on the [Discussions](https://github.com/NOMARJ/sigil/discussions) tab; confirmed feature work is tracked as an issue with the `feature` label. We read every one.

**Submit code.** Bug fixes, new scan rules, documentation improvements, and new features are all welcome via pull request.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/NOMARJ/sigil.git
cd sigil

# Install Rust toolchain (if you don't have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# The Rust CLI is a workspace under cli/
cd cli

# Build
cargo build

# Run tests
cargo test

# Run the CLI locally against the fixture corpus
cargo run -- scan ../tests/fixtures/
```

## Pull Request Process

1. **Fork the repo** and create your branch from `main`.
2. **Write tests** for any new scan rules or functionality.
3. **Run the test suite** — all tests must pass before review.
4. **Keep PRs focused.** One feature or fix per PR. Small PRs get reviewed faster.
5. **Write a clear description** of what changed and why.
6. **Update docs** if your change affects CLI behaviour, scan output, or configuration.

## Writing Scan Rules

Detection rules are **data, not code**. They live in declarative JSON signature
packs under `cli/packs/core/v1/`, one file per threat family, and the engine
compiles them into regexes and predicates at load time. Per
[ADR-0005](docs/adr/ADR-0005-signed-declarative-signature-packs.md) the rules
engine never executes rule-supplied code: no Lua, no JS, no plugin scripts, and
no taint tracking inside a pack. If a detection cannot be expressed as a regex
plus the declarative filters below, it does not belong in a pack; open an issue
and describe the gap instead.

The schema is `cli/src/corpus/schema.rs`. Everything in this section is derived
from it and from `Phase::default_weight` in `cli/src/scanner/mod.rs`; if the two
ever disagree, the code wins and this document has a bug.

### An annotated example

`PERSIST-002` from `cli/packs/core/v1/persistence.json`:

```json
{
  "id": "PERSIST-002",
  "phase": "code_patterns",
  "severity": "high",
  "pattern": "(?i)(Library/Launch(Agents|Daemons)/[^\\s\"']*\\.plist|\\blaunchctl[\"',\\s]+(load|bootstrap|enable|submit)\\b)",
  "description": "Persistence — macOS LaunchAgent/LaunchDaemon installation",
  "suppress": {
    "path_contains": ["Formula/", "Casks/"]
  },
  "remediation": "Remove the LaunchAgent/LaunchDaemon installation. Code that survives a reboot and runs outside the agent's session is a backdoor shape, whatever the stated purpose.",
  "references": ["MITRE T1543.001", "MITRE T1543.004"],
  "tags": ["persistence", "launchd", "macos"]
}
```

Reading it top to bottom:

- `id` is the family prefix plus a zero-padded number, unique across all packs.
- `phase` decides the scoring multiplier (5x here) and which heading the finding appears under.
- `severity` is the rule's own rating; the phase weight multiplies it into the score.
- `pattern` is one regex. `(?i)` makes it case-insensitive. The two alternatives anchor on the operative tokens (a launchd plist path, or a `launchctl` verb), not on surrounding prose.
- There is no `file_filter`, so the rule runs on every file. The `suppress` block keeps it quiet on Homebrew formulae and casks, which legitimately install launchd services.
- `remediation`, `references` and `tags` are carried onto every finding this rule produces and surface in JSON, SARIF (`help`) and HTML output. Write them.

### Rule fields

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | `FAMILY-NNN`. Families in use: `INSTALL-` (install_hooks.json), `CODE-` (code_patterns.json), `PERSIST-` (persistence.json), `NET-` and `EXFIL-` (network_exfil.json), `RSHELL-` (reverse_shells.json), `CRED-` (creds.json), `OBFUSC-` (obfuscation.json, obfuscation_chain.json), `PROV-` and `HYGIENE-` (provenance.json), `PROMPT-` (prompt_injection.json), `MANIP-` (agent_manipulation.json), `SKILL-` (skill_security.json), `INFER-` (inference_security.json), `SUPPLY-` (supply_chain.json). |
| `phase` | yes | Canonical snake_case phase name. Sets the default weight: `install_hooks` 10, `code_patterns` 5, `network_exfil` 3, `credentials` 2, `obfuscation` 5, `provenance` 1 (per-rule 1-3), `prompt_injection` 10, `skill_security` 5, `inference_security` 5. |
| `severity` | yes | `low`, `medium`, `high`, or `critical`. |
| `pattern` | yes | A single regex compiled by the Rust `regex` crate: no lookaround, no backreferences. Escape for JSON (`\\b`, `\\s`). |
| `description` | yes | Human-readable title; becomes the finding snippet prefix. Convention is `Family — what it is`. |
| `weight` | no | Integer override of the phase weight. Leave it out unless you can justify the exception. |
| `file_filter` | no | Restricts which files the rule runs on. Any of `filename_exact` (basenames), `extensions` (no leading dot), `filename_suffix`. Absent or empty means every file. |
| `suppress` | no | Predicates that discard a match after it fires. Any of `path_contains`, `filename_suffix`, `line_contains`, `nearby_contains` (matched line plus a small following window), `file_header_contains` (first 1 KB of the file), `safe_domains` (domain strings on the matched line). |
| `evidence` | no | `standalone` (default) or `corroborate`. Only meaningful on a `critical` rule: see [Evidence-gated Critical](#evidence-gated-critical). |
| `remediation` | no, expected | What to change or verify when the rule fires. One or two sentences. |
| `references` | no, expected | CWE, MITRE ATT&CK technique, OWASP entry, advisory, or campaign the rule was derived from. |
| `tags` | no, expected | Behaviour tags such as `exfiltration`, `persistence`, `manipulation`; they feed `profile.behaviors` in JSON output. |

### Evidence-gated Critical

A `critical` severity is a claim: *this is what a compromised package looks
like*. Some patterns earn it alone — an `INSTALL-003` postinstall that pipes a
download into a shell is not something a legitimate package does by accident.
Others are Critical because of the company they usually keep. A PEM
`PRIVATE KEY` armour header is Critical in a published tarball and completely
ordinary in `tests/certs/`, and one regex on one line cannot tell the two
apart.

`"evidence": "corroborate"` marks the second kind:

```json
{
  "id": "CRED-006",
  "phase": "credentials",
  "severity": "critical",
  "pattern": "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
  "description": "Embedded private key",
  "evidence": "corroborate"
}
```

A corroborating rule still reports at Critical, still carries its full weight
into the score, and still fails `--fail-on critical`. What it cannot do is
drive the **verdict** to `CRITICAL RISK` on its own:
`determine_verdict` returns `CRITICAL RISK` only when there is at least one
`standalone` Critical finding, or Critical findings from **two different**
corroborating rules. Two hits of the *same* corroborating rule are one
observation repeated, not two independent ones, so they do not gate. Anything
that does not gate falls through to the ordinary score thresholds.

Omitting the field means `standalone`, so every rule written before this
existed keeps its behaviour. Findings carry the value as an additive
`evidence` key in `--format json`, emitted only when it is not the default.

Choose `corroborate` when the clean-package evidence says the pattern has a
routine benign shape the regex cannot exclude — measure it with
`scripts/rule_precision.py` before deciding, not from the rule's name.

### Score saturation

`calculate_score` counts at most `PER_RULE_FILE_SCORE_CAP` (3, in
`cli/src/scanner/scoring.rs`) findings per `(rule, file)` pair. Every finding
is still reported and still counted in `findings_count`; only its contribution
to the aggregate score saturates. This exists because the score is a sum: one
Unicode data table in `idna` matched `OBFUSC-CHAIN-008` 1,723 times and by
itself produced a 19,140-point HIGH RISK verdict. When you write a rule that
can match many times in one file, you do not need to defend against volume in
the pattern — the cap already does it.

**Provenance rules** (`provenance_rules` array, phase 6) match filesystem
metadata rather than content: `kind` is one of `filename_regex`, `hidden_file`,
`binary_extension`, `file_size_bytes`, with `pattern`, `size_threshold`,
`allowed_path_prefixes` and `excluded_filenames` as the kind requires. They
take the same `remediation` / `references` / `tags` fields.

**Correlation rules** (`correlation_rules` array) are a post-pass over
*findings*, not over file content. They fire when a `source` finding and a
`sink` finding (each selected by `rule_prefixes` or `rule_ids`) occur in the
same file within `window_lines` (default 20) and the value assigned on the
source line appears in the sink call's arguments; `sink_excludes` lists
substrings that disqualify the link. `EXFIL-CHAIN-001` in `network_exfil.json`
(credential read reaching a network send) is the shape to copy. This is the
one place a pack can say "line 9 feeds line 10" without the engine executing
anything: the link is a text identity check, not taint analysis.

### Fixtures

Every rule ships with two fixtures:

1. **Malicious**: a synthetic, defanged file that must fire. Put it under
   `tests/fixtures/<phase>/` (for example `tests/fixtures/code_patterns/`) and
   add a case to `tests/fixtures/MANIFEST.json`:

   ```json
   {
     "path": "code_patterns/example.py",
     "expect_phase": "CodePatterns",
     "expect_min_severity": "High",
     "source": "Advisory or campaign this shape is modeled on",
     "synthetic": true
   }
   ```

   `expect_phase` is the enum variant name (`InstallHooks`, `CodePatterns`,
   `NetworkExfil`, `Credentials`, `Obfuscation`, `Provenance`,
   `PromptInjection`, `SkillSecurity`, `InferenceSecurity`);
   `expect_min_severity` is `Low` / `Medium` / `High` / `Critical`. The
   `fixture_corpus_matches_manifest` test in `cli/src/scanner/mod.rs` scans
   every case and asserts at least one finding of that phase at or above that
   severity. Keep the manifest's `data_source`, `sample_size` and `limitations`
   fields honest: fixtures are synthetic unless a case says otherwise.

2. **Benign**: a file that looks similar and must NOT fire. Put it under
   `tests/fixtures/clean/` with a manifest case of `"expect_clean": true`, or,
   if the benign shape is common enough that the rule will keep hitting it in
   the wild, encode it as a `suppress` predicate on the rule as well.

Never commit a live payload, a working exfiltration endpoint, or a real
credential. Replace them with obvious placeholders (`example.invalid`,
`PLACEHOLDER`) that still exercise the regex.

### Checking your work

```bash
cd cli
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt
```

All three must be clean. The pack loader validates every rule at test time, so a
malformed regex or an unknown phase name fails `cargo test` with the rule id in
the message.

### Measuring a rule change

A rule change is a claim about two populations, and both need a number.

**Recall** — `scripts/run_eval.py` scans the Datadog malicious-package dataset
and reports detection at each severity threshold:

```bash
SIGIL_BIN=cli/target/release/sigil python3 scripts/run_eval.py \
    --dataset datadog --dataset-path /path/to/dataset \
    --control-path /path/to/control --out evaluation_results/ [--limit N]
```

**Precision** — `scripts/rule_precision.py` scans a directory of clean,
popular packages and reports, per rule, how many of them it fired on:

```bash
scripts/rule_precision.py cli/target/release/sigil /path/to/control \
    --samples /path/to/sigil_samples.json --out rule_precision.json
```

The table is sorted by clean packages hit. A rule near the top with few
malicious hits is over-broad: look at the actual matched lines before deciding
what to do about it, because the fix differs by what you find. A pattern that
matched documentation prose wants a narrower pattern; a pattern that matched
the real thing in a benign context wants a lower `severity` or
`"evidence": "corroborate"`; a pattern that matched the same data file a
thousand times is already handled by the score cap and wants nothing.

Both scripts run real scans and nothing else — no sampling, no estimation, no
`random`. Per CLAUDE.md, any number that reaches a document must come from a
run you actually executed, with its data source, sample size and limitations
stated alongside it.

### The self-scan gate

Sigil scans its own repository as a required CI check (`.github/workflows/sigil-selfscan.yml`):

```bash
cli/target/release/sigil scan . --no-cache --fail-on high
```

Run it before you push. A new rule that fires on Sigil's own tree at High or
Critical fails the gate for everyone. That is sometimes correct (the tree
contains detection research, fixtures, and the bash scanner's grep strings by
design), but each hit needs one of two scoped suppressions, never a blanket
exclusion:

- A `.sigilignore` entry, scoped to the narrowest path that needs it, with a
  comment explaining why the pattern is there on purpose. The existing file
  shows the convention.
- An inline marker on the flagged line, or the line before it, naming the rule
  and giving a reason:

  ```text
  subprocess.run(argv)  # sigil:ignore CODE-013 -- argv list, no shell
  # sigil:ignore-next-line CRED-008 -- placeholder value in a test
  ```

  Markers suppress by exact rule id only; there is no wildcard. Suppressed
  findings are not dropped: they are reported under `inline_suppressed` in JSON
  and as SARIF `suppressions` so a reviewer can audit every one from the report.

### Output contract

`--format json` is a stable, versioned contract
([ADR-0010](docs/adr/ADR-0010-output-contract-sarif-exit-codes.md)).
`serde_json` writes keys alphabetically and downstream consumers
(`scripts/run_eval.py`, `sigil explain`) locate the findings array by the first
`[` on stdout, so **no new top-level key may sort before `"findings"`** and
`"summary"` must hold scalars only. `findings_array_is_still_the_first_array_in_the_document`
in `cli/src/output.rs` enforces this; if you need a new top-level key, pick a
name that sorts after `findings` (`profile`, `scanner` and `summary` already
do).

## Code Style

- Rust code follows standard `rustfmt` formatting. Run `cargo fmt` before committing.
- Python code (API service) follows `black` formatting with `ruff` for linting.
- Commit messages: imperative mood, concise. `Add install hook detection for Poetry` not `Added some stuff`.

## Issue Labels

| Label | Meaning |
|-------|---------|
| `bug` | Something broken |
| `feature` | New capability |
| `scan-rule` | New or improved detection rule |
| `threat-report` | Malicious package report |
| `false-positive` | Rule triggering incorrectly |
| `docs` | Documentation improvement |
| `good-first-issue` | Suitable for new contributors |

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, be constructive, be helpful.

## Questions?

Open a discussion on the [Discussions](https://github.com/NOMARJ/sigil/discussions) tab or reach out at hello@nomark.ai.

---

**SIGIL** by NOMARK — *A protective mark for every line of code.*
