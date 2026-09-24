# Rolling Sigil out across an organisation

This guide is for the team that owns developer security tooling: how to put
Sigil on every laptop and CI runner, set one policy for all of them, add your
own detection rules, and wire the results into code scanning, test reports and
your SIEM. Everything here describes the `sigil` binary as it ships; anything
not available yet is marked **not available**.

- [What you control, and where](#what-you-control-and-where)
- [Organisation policy](#organisation-policy-sigil_policy_file)
- [Project policy and the scanned-tree guard](#project-policy-and-the-scanned-tree-guard)
- [Custom rule packs and signing](#custom-rule-packs-and-signing)
- [Adopting Sigil on an existing codebase: baselines](#adopting-sigil-on-an-existing-codebase-baselines)
- [Exit-code contract](#exit-code-contract)
- [CI gates](#ci-gates)
- [Reports: SARIF, JUnit, Markdown, JSON for a SIEM](#reports)
- [Claude Code: enforce the guard with managed settings](#claude-code-enforce-the-guard-with-managed-settings)
- [Air-gapped and offline operation](#air-gapped-and-offline-operation)
- [Limitations](#limitations)

Policy file keys, the baseline format and the compact rule format are
specified in [configuration.md](configuration.md#scan-policy-sigilyml) and
[schemas.md](schemas.md#file-formats-used-by-the-cli).

---

## What you control, and where

| Control | Where it lives | Who sets it | Scope |
|---|---|---|---|
| Organisation policy | file named by `SIGIL_POLICY_FILE` | security team (MDM, CI image) | every `sigil scan`; `rule_packs` also apply to `clone`/`pip`/`npm` |
| Locked keys | `locked:` in the organisation policy | security team | project files and flags can only make them stricter |
| Pack signing key | `SIGIL_PACK_PUBLIC_KEY` (64 hex chars, Ed25519) | security team | every pack not compiled into the binary must be signed |
| Machine-wide rule packs | `~/.sigil/packs/*.json` | security team / user | every scan on that machine; may replace a core pack by id |
| Project policy | `.sigil.yml` (or `--config FILE`) | repository owners | scans of that repository |
| Per-line exceptions | `# sigil:ignore RULE-ID -- reason` | developers | one line or file |
| Accepted findings | `.sigil-baseline.json` (`sigil baseline`) | repository owners | scans that name it |

Precedence for a scan is: organisation policy, then project policy, then
command-line flags — with locked keys only ever tightened. `sigil config
--policy` prints the result for the current directory: every file that
applied, every merged value, and every loosening that was refused.

## Organisation policy (`SIGIL_POLICY_FILE`)

Write one YAML file and point `SIGIL_POLICY_FILE` at it on every machine and
runner:

```yaml
# /etc/sigil/policy.yml — organisation scan policy
version: 1
fail_on: high               # exit 1 on any finding at or above HIGH
fail_on_verdict: HIGH       # ...or when the overall verdict is HIGH or CRITICAL
fail_on_incomplete: true    # ...or when anything could not be fully inspected
disable_rules: []           # nothing switched off centrally
rule_packs:
  - /etc/sigil/packs/        # your signed packs (a directory or files)
locked:                     # project files and flags can only tighten these
  - fail_on
  - fail_on_verdict
  - fail_on_incomplete
  - disable_rules
  - ignore_paths
  - trusted_domains
  - rule_packs
allow_project_policy: true  # false = every project file is tighten-only
```

Distribute it the way you distribute other endpoint configuration, and set the
variable for every shell, IDE and CI job:

- Linux: a file in `/etc/profile.d/` (`export SIGIL_POLICY_FILE=/etc/sigil/policy.yml`)
  and the same variable in your CI runner image.
- macOS: install the file with your MDM and set the variable in the login
  environment your MDM manages.
- Windows: a machine-level environment variable set by Group Policy or Intune.

Check a file before you push it:

```bash
sigil config --validate /etc/sigil/policy.yml --org   # exit 0 valid, 1 invalid, 2 unreadable
```

Behaviour you can rely on:

- **Fail closed.** When `SIGIL_POLICY_FILE` is set but the file is missing or
  invalid, every scan exits `2` with the reason. It never falls back to
  defaults silently.
- **Locked keys.** For a locked key, a project file or a flag may only make the
  scan stricter: a lower `fail_on`/`fail_on_verdict`/`min_severity`, raised
  severities, `fail_on_incomplete` switched on but never off. Additions to a locked list (`disable_rules`, `ignore_paths`,
  `trusted_domains`, `rule_packs`) and a locked `baseline` are refused. Each
  refusal is printed as a warning on stderr and listed in the JSON report under
  `policy.refused`. `locked: [all]` locks every lockable key.
- **`allow_project_policy: false`** makes every project policy file (discovered
  or passed with `--config`) tighten-only, whether or not keys are locked.
- `locked` and `allow_project_policy` are only accepted in the organisation
  file; a project file that uses them is rejected with an error.
- **Fail closed on coverage.** `fail_on_incomplete: true` fails a scan that
  could not fully inspect the target: an unreadable file or directory, a text
  file over 10 MB scanned only at its two ends, an instruction or markdown
  file whose bytes are not decodable text, a file whose analysis ran out of
  time, an archive that could not be opened or is encrypted, or a reference
  `--follow-refs` could not fetch. The JSON report carries
  `summary.complete` and `summary.incomplete_count`, and the findings name each
  gap (`PROV-INCOMPLETE-001`, `PROV-BUDGET-001`, `ARTIFACT-008`,
  `ARTIFACT-009`, `REF-002`). Lock `disable_rules` as well, so a project cannot
  suppress those rules to get around the gate.

## Project policy and the scanned-tree guard

A repository can carry a `.sigil.yml` (also `.sigil.yaml` or `sigil.yml`):

```yaml
fail_on: medium
disable_rules: [NET-012]            # ids or globs such as "PROV-*"
severity_overrides: {CODE-013: low}
ignore_paths: [tests/fixtures/]     # .sigilignore (gitignore) syntax
trusted_domains: [api.openai.com]
baseline: .sigil-baseline.json
rule_packs: [.sigil/rules/]
```

Sigil looks for it in the scan root, then in the current directory. Nothing a
policy suppresses disappears: findings it takes out of the verdict are listed
in the JSON (`policy.suppressed`, each with the file and key responsible),
emitted in SARIF with `suppressions[].kind = "external"`, shown as skipped
tests in JUnit, and counted in the text and Markdown summaries.

**The scanned-tree guard.** Sigil is for judging code you do not trust yet, so a
policy file shipped *inside* that code cannot weaken the judgement. A
`.sigil.yml` found in the scan root is trusted only when you run Sigil from
inside that tree (the current directory is the scan root or below it — the
normal CI case, `sigil scan .`). Scanning a downloaded skill from elsewhere
(`sigil scan ~/Downloads/some-skill`) applies that skill's policy
**tighten-only**: its `disable_rules`, `ignore_paths`, `trusted_domains`,
`baseline`, `rule_packs` and any loosening value are refused and reported, and
the refusal tells you to pass `--config <file>` if you do vouch for it.
`sigil clone`, `sigil pip` and `sigil npm` never read a policy from the
quarantined content at all. Discovery can be switched off entirely with
`--no-project-config` or `SIGIL_NO_PROJECT_CONFIG=1`; the organisation policy
still applies.

## Custom rule packs and signing

Add organisation-specific detections — internal hostnames that must not leak
into published skills, banned SDKs, your own secret formats — without forking
Sigil. A compact YAML pack:

```yaml
# acme-rules.yaml
pack: {id: acme-rules, name: ACME internal rules, version: 1.0.0}
rules:
  - id: ACME-001
    pattern: 'internal-artifacts\.acme\.example'
    severity: high
    description: Reference to the internal artifact mirror
    extensions: [py, js, ts, md]
    remediation: Internal mirrors must not appear in published skills.
    references: [CWE-200]
    tags: [acme, data-leak]
```

The full pack schema used by `cli/packs/core/v1/*.json` is accepted too, in
JSON or YAML. Custom packs are **additive**: a pack whose id matches a
built-in pack, or a rule whose id matches any existing rule, is refused, so a
file named at scan time can never replace a core pack and remove its
detections. (Replacing a core pack remains possible, deliberately, only from
the machine-level `~/.sigil/packs/` directory.) Rule ids must look like
`PREFIX-NAME` so `sigil:ignore` markers and policy globs can name them.

Author, check and try rules without scanning anything:

```bash
sigil rules validate acme-rules.yaml      # every problem, with the rule it is in; exit 0/1/2
sigil rules test acme-rules.yaml ./some-dir   # run only this pack and print what fires
sigil --rules acme-rules.yaml scan .      # use it for one scan (repeatable flag)
sigil rules list --phase network_exfil    # the active corpus, incl. custom and disabled rules
sigil rules show ACME-001                 # pattern, filters, remediation, policy status
```

**Signing.** When `SIGIL_PACK_PUBLIC_KEY` is set on a machine, every pack that
is not compiled into the binary — `~/.sigil/corpus/`, `~/.sigil/packs/`,
`--rules`, and policy `rule_packs` — must carry a valid Ed25519 signature, or
the scan exits `2` with a `[SECURITY]` error. Sign packs on a trusted machine:

```bash
openssl genpkey -algorithm ed25519 -out sigil-packs.pem   # once; keep it offline
sigil rules sign acme-rules.yaml --key sigil-packs.pem -o acme-rules.signed.json
# stderr prints: export SIGIL_PACK_PUBLIC_KEY=<64 hex chars>
```

`sigil rules sign` validates the pack, converts a compact pack to the full
schema, and writes signed JSON. Any edit after signing breaks verification.
Push the signed pack (to `~/.sigil/packs/` or the directory your organisation
policy lists under `rule_packs`) and the public key (as
`SIGIL_PACK_PUBLIC_KEY`) with the same mechanism as the policy file. A compact
YAML pack cannot carry a signature, so on a keyed machine it is refused with a
message naming `sigil rules sign`.

## Adopting Sigil on an existing codebase: baselines

Turning a gate on for a large repository usually means dozens of findings
someone has already looked at. Record them once and fail only on new ones:

```bash
sigil baseline . --reason "accepted at adoption, reviewed in SEC-1234"
#   -> .sigil-baseline.json (or -o FILE; .yaml/.yml writes YAML)
sigil scan . --baseline .sigil-baseline.json    # or `baseline:` in .sigil.yml
```

Entries match by Sigil's content fingerprint (rule, file and normalised matched
text; **not** the line number), so code moving around a file does not revive
them, and a second copy of an accepted line is a new finding. Each entry
accepts exactly one finding. Entries that no longer match are reported as stale
so the file can be pruned by regenerating it. The file stores hashes, not the
matched text, so committing it does not commit attack strings.

A baseline may also hold hand-written glob rules, each with a mandatory reason
and an optional expiry:

```yaml
rules:
  - rule: "NET-012"
    path: "scripts/install/"
    reason: "installer downloads pinned release assets over TLS (SEC-1234)"
    expires: 2027-01-31
```

`sigil scan -f json` output is also accepted as a baseline.

## Exit-code contract

Checked against the binary by `cli/tests/customisation.rs` (scan, baseline,
diff, rules and config) and the `exit_code_tests` in `cli/src/main.rs`
(acquisitions):

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `sigil scan` | no active finding at or above `fail_on` (default `high`), verdict below `fail_on_verdict`, and, with `fail_on_incomplete`, nothing left uninspected | the gate failed | the scan could not run or produce its report: missing path, invalid policy/flag/format, unreadable baseline, unverifiable or invalid rule pack, report file not writable, `--enhanced` without login |
| `sigil clone` / `pip` / `npm` | verdict LOW RISK | any other verdict | acquisition or scan failed |
| `sigil diff` | no new findings | new findings | unreadable baseline or path |
| `sigil baseline` | baseline written | — | scan or write failed |
| `sigil rules validate` | valid | invalid (every problem listed) | path unreadable |
| `sigil config --validate` | valid | invalid | file missing |
| `sigil hook pretooluse` | always 0 (the decision is in the JSON on stdout) | — | — |

Findings suppressed by a policy, a baseline, an inline marker or a ledger
approval never affect the exit code. `2` always means "no usable verdict";
treat it as a failed job, never as a pass. (`sigil diff` returned `2` for new
findings before this release; it now returns `1`.)

## CI gates

The scan is the same command everywhere; only the report plumbing differs.

**GitHub Actions** — the bundled action, or the CLI directly with SARIF into
code scanning:

```yaml
jobs:
  sigil:
    runs-on: ubuntu-latest
    permissions: {contents: read, security-events: write}
    env:
      SIGIL_POLICY_FILE: /etc/sigil/policy.yml   # provided by your runner image
    steps:
      - uses: actions/checkout@v4
      - name: Install Sigil
        run: cargo install sigil-cli --locked   # or the install script / a pinned release binary
      - name: Scan (the gate)          # exit 1 fails the job, 2 errors it
        run: sigil scan . -f sarif -o sigil.sarif
      - name: Job summary
        if: always()
        run: sigil scan . -f markdown -o "$GITHUB_STEP_SUMMARY" || true   # served from the scan cache
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with: {sarif_file: sigil.sarif, category: sigil}
```

(Alternatively `uses: NOMARJ/sigil@main` with `upload-sarif: true`; see
[cicd.md](cicd.md).)

**GitLab CI** — JUnit into the merge-request test widget:

```yaml
sigil:
  stage: test
  script:
    - sigil scan . -f junit -o sigil-junit.xml
  artifacts:
    when: always
    reports:
      junit: sigil-junit.xml
```

**Jenkins** (declarative):

```groovy
stage('Sigil') {
  steps { sh 'sigil scan . -f junit -o sigil-junit.xml' }
  post  { always { junit 'sigil-junit.xml' } }
}
```

**Azure DevOps**:

```yaml
- script: sigil scan . -f junit -o $(Build.ArtifactStagingDirectory)/sigil-junit.xml
  displayName: Sigil scan
- task: PublishTestResults@2
  condition: always()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: $(Build.ArtifactStagingDirectory)/sigil-junit.xml
```

In JUnit, each active finding is one test case; findings at or above
`fail_on` are failures, the rest pass with the detail in `system-out`,
suppressed findings are skipped (with the reason), and when
`fail_on_verdict` is set the verdict is its own test case.

## Reports

`-f/--format` selects `text` (default), `json`, `sarif`, `html`, `markdown`
(`md`) or `junit`; `-o/--output FILE` writes the report to a file instead of
stdout (the text report is then written without colour). Progress and
warnings always go to stderr, so a JSON or SARIF stdout is exactly one
document.

**SARIF (GitHub code scanning).** SARIF 2.1.0 with `partialFingerprints`
(`sigilFingerprint/v1`, line-independent), rule `help` from each rule's
remediation, and suppressed findings as results with `suppressions`:
`inSource` for `sigil:ignore` markers, `external` for policy and baseline
suppressions — so code scanning shows them as dismissed rather than silently
missing.

**JSON (SIEM ingestion).** `sigil scan -f json -o /var/log/sigil/<id>.json`
and forward the file with your log shipper. Stable keys (ADR-0010):

| Key | Meaning |
|---|---|
| `summary.verdict`, `summary.score`, `summary.grade` | overall result |
| `summary.findings_count`, `summary.files_scanned` | volume |
| `findings[]` | `rule`, `severity`, `phase`, `file`, `line`, `snippet`, `fingerprint`, `title`, `remediation`, `references`, `tags`, `behavior` |
| `scanner.engine_version`, `scanner.corpus_digest` | exactly which binary and rule set produced it |
| `policy.sources[]`, `policy.refused[]`, `policy.suppressed[]` | present when a policy is active: what applied, what was refused, what was suppressed and by what |
| `summary.gate`, `summary.policy_suppressed_count`, `summary.baseline_suppressed_count` | present when a policy is active |

`fingerprint` is the natural deduplication key across runs.

**Markdown** is written for pull-request comments and CI job summaries.
Paths and matched text from the scanned tree are rendered inside code spans
with pipes escaped, so a hostile file name cannot inject links or markup into
the comment.

## Claude Code: enforce the guard with managed settings

`sigil hook pretooluse` reads a Claude Code `PreToolUse` payload on stdin and
answers with a permission decision: it denies unscanned acquisitions
(`git clone`, `npm install <pkg>`, `pip install <pkg>`, `curl … | sh`, …) with
the `sigil` command to use instead, and asks for confirmation on lockfile
restores and one-shot runners (`npx`, `uvx`, `pipx run`). To make that
organisation-wide rather than per-user, put the hook in Claude Code's managed
settings file, which users cannot override (see Claude Code's documentation
for its location on each platform; at the time of writing it is
`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS and
`/etc/claude-code/managed-settings.json` on Linux):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "sigil hook pretooluse" }]
      }
    ]
  }
}
```

`SIGIL_GUARD_MODE` selects `enforce` (default), `advise` (every deny becomes
ask) or `off`. See the limitation on `SIGIL_BYPASS` below before relying on the
guard as a hard control.

## Air-gapped and offline operation

- The detection corpus is compiled into the binary, so scanning needs no
  network and no download on first run. Released corpus updates and custom
  packs are plain files you can carry across the air gap (verify them with
  `SIGIL_PACK_PUBLIC_KEY`).
- Policy files, baselines and reports are local files.
- Three enrichment feeds make network requests, and only when the tree has
  something for them: OSV advisories (when a lockfile is present), CISA KEV
  and EPSS (when there are CVE findings), and npm/PyPI registry provenance
  (for package manifests). Each has a 15–20 s timeout, falls back to cached
  data, and never fails the scan; `--verbose` prints each feed's time. There is
  **no switch to skip them** in this release (not available); scanning with
  `--phases` set to anything but `all` skips them.
- `--enrich`, `--submit`, `--enhanced`, `sigil login`, `sigil fetch` and
  `sigil explain` need the Sigil cloud and are not for air-gapped use.

## Limitations

Stated plainly so nothing here is over-relied on:

- **`.sigilignore` is honoured from the scanned tree.** A tree can hide its own
  files from the walk with a `.sigilignore`. The scanned-tree guard covers
  policy files, not `.sigilignore`. (Tracked for a future release.)
- **`SIGIL_BYPASS=1`** — the Claude Code guard allows a command that sets
  `SIGIL_BYPASS=1` itself, so an agent can opt out. Treat the guard as a strong
  default for a cooperative agent, not a boundary against a hostile one. An
  organisation-level "no bypass" switch is **not available**.
- Policies apply to `sigil scan`. For `clone`/`pip`/`npm` only the
  organisation and `--config` rule packs apply; their verdict gate is fixed
  (LOW RISK passes).
- The HTML report shows the post-policy result but does not list
  policy-suppressed findings; use JSON, SARIF or JUnit for that audit trail.
- There is no central policy server; distribution is by file and environment
  variable through the tooling you already use.
