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
- [Rule ids that changed (lifecycle classification)](#rule-ids-that-changed-lifecycle-classification)
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
  - min_severity            # else a project can hide findings under the gate
  - severity_overrides      # else a project can lower severities under the gate
  - baseline                # else a project can accept every current finding
  - disable_rules
  - ignore_paths
  - trusted_domains
  - rule_packs
allow_project_policy: true  # false = every project file is tighten-only
```

Locking `fail_on` alone does not hold the gate: an unlocked `min_severity`,
`severity_overrides`, `baseline`, `disable_rules`, `ignore_paths` or
`trusted_domains` each lets a project take findings out from under it. The
example locks all of them (`locked: [all]` is the short form). Leave
`baseline` unlocked only if projects may adopt Sigil with a baseline of
their own, and know that it can accept anything present today. `sigil config
--validate FILE --org` lists every unlocked key that can undo a locked gate.

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
the refusal tells you to pass `--config <file>` if you do vouch for it. If
that skill's policy file does not even load, it is set aside with a refusal
rather than allowed to stop the scan, so shipping a malformed `.sigil.yml`
cannot keep Sigil from reporting on the skill.
`sigil clone`, `sigil pip` and `sigil npm` never read a policy from the
quarantined content at all. Discovery can be switched off entirely with
`--no-project-config` or `SIGIL_NO_PROJECT_CONFIG=1`; the organisation policy
still applies.

The guard is a heuristic about *where you stand*, not about who wrote the
file: `git clone <url> && cd <repo> && sigil scan .` trusts that repository's
`.sigil.yml` exactly as CI does. Judge unfamiliar code with `sigil clone`, or
scan it from outside the tree, or pass `--no-project-config`. The text report
names every policy file that applied (`project policy applied: …`), and a
locked organisation policy bounds what any project file can do.

`trusted_domains` excuses a Network/Exfil finding only when every URL on the
line is readable and points at a trusted host (or a subdomain of one). A URL
whose host is hidden behind userinfo (`https://trusted@evil`), percent
encoding, a template, or shell quoting (`"https://trusted".evil.io`) is never
excused, nor are Critical findings, credential-flow chains, reverse shells and
the rules that show data leaving (`SKILL-017` file or command-output upload,
`NET-011` encode-then-send, `NET-018` DNS exfiltration). Trust hosts you
control: a multi-tenant host such as `github.com` or `hooks.slack.com` serves
an attacker's account as readily as yours.

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
A full-schema rule can exempt individual matches by the text around them
(`suppress.match_context`) or by the value it captured
(`suppress.value_matches`) instead of dropping whole lines; see
[schemas.md](schemas.md#match-local-suppression-full-schema).

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

### YARA rules

A security team that keeps its detections in YARA can point Sigil at them as
they are. `.yar` and `.yara` files load wherever a rule pack does — `--rules`,
a directory of packs, a scan policy's `rule_packs`, the organisation policy —
next to JSON and YAML packs. Sigil parses and evaluates them itself (no
libyara, no plug-in), and refuses what it cannot evaluate faithfully rather
than skipping it. (The machine-level `~/.sigil/packs/` directory reads JSON
packs only, and warns about a `.yar` file placed there; to deploy YARA files to
every machine, list their directory under the organisation policy's
`rule_packs`.)

```yara
// acme.yar
rule Acme_Canary_Token : acme
{
    meta:
        description = "Internal canary token in a published skill"
        severity    = "high"           // critical | high | medium | low (default medium)
        phase       = "network_exfil"  // any Sigil phase (default code_patterns)
        remediation = "Canary tokens must not ship. Remove it and rotate the token."
        reference   = "https://wiki.example.invalid/canaries"
    strings:
        $token = "example-canary-token" nocase wide ascii fullword
        $bytes = { 53 49 47 49 4C ?? [0-16] 4C }
    condition:
        any of them and filesize < 5MB
}
```

```bash
sigil rules validate acme.yar             # every problem with file:line; exit 0/1/2
sigil rules test acme.yar ./some-dir      # run only these rules and print what fires
sigil --rules acme.yar scan .             # or --rules ./yara/ for a directory of rule files
sigil rules show YARA-ACME-CANARY-TOKEN   # the rule as written, and what the policy does to it
```

**Identity.** Each rule becomes the Sigil rule `YARA-<NAME>`: the name
upper-cased with `_` turned into `-`, so `Acme_Canary_Token` is
`YARA-ACME-CANARY-TOKEN`. Inline `sigil:ignore` markers, `disable_rules`
(`YARA-*` works), `severity_overrides` and baselines address it like any other
rule. A file is one pack, `yara.<file name without extension>`. As with every
custom pack, a rule whose id is already taken — by a built-in rule, another
pack, or another rule in the same file whose name differs only in case or
`_` — is refused, never allowed to replace it.

**Evaluation.** YARA's semantics, not Sigil's line-oriented ones: strings match
a file's raw bytes anywhere, across line breaks, in binary files the text
phases skip; `#a` counts every offset a match starts at, overlapping ones
included; `filesize` is the real size. A finding carries the rule's severity
and phase, the line of the earliest matching string (none in a binary file), a
snippet naming the rule and the matched strings (escaped, cut at 48 bytes;
`private` strings are never shown), and the rule's remediation, or a generic
one naming the rule file. What is evaluated:

| Unit | Evaluated |
|---|---|
| Files on disk up to 10 MB, text or binary | the whole file |
| Files of 10–512 MB | the first and last 2 MB, at their real offsets, with the real `filesize`; `^`, `$`, `\b` and `fullword` at the edge of either part see the file's real neighbouring bytes. The finding is marked `[head/tail of oversized file]` and a `PROV-INCOMPLETE-001` note records that the middle was not read |
| Files over 512 MB | not evaluated; reported as not content-scanned, as for every rule |
| Archive members (zip, tar, gzip, two levels deep) | text members; with YARA rules loaded, binary members and document XML too, 32 MB of them in total. A member past that cap is reported on its archive (`ARTIFACT-008`). A member over 4 MB is evaluated on its first 4 MB with `filesize` undefined (so a `filesize` comparison is false, negated or not), and the finding is marked `[first part of oversized member]` |
| Bytecode string constants | not evaluated separately: the `.pyc` file itself is evaluated on disk |

**The subset.**

| | Supported |
|---|---|
| Rules | `rule`, tags, `private` (evaluated and referable, never reported), `global` (a global rule that does not match switches off every rule in its file), references to rules defined earlier in the same file |
| `meta:` | any keys. Sigil reads `description`, `author`, `reference` (repeatable), `severity`, `phase` and `remediation`; a key one letter away from one of these draws a warning |
| Text strings | escapes `\"` `\\` `\t` `\n` `\r` `\xHH`; modifiers `nocase`, `wide`, `ascii`, `fullword`, `private` |
| Hex strings | bytes, `??`, nibbles `4?` and `?4`, jumps `[n]`, `[n-m]`, `[n-]`, `[-]`, alternatives `( 41 \| 42 43 )`, comments; modifier `private` |
| Regular expressions | `/.../` with the `i` and `s` flags; modifiers `nocase`, `ascii`, `fullword`, `private`. YARA's regex syntax with YARA's meaning, matched over bytes: an escape YARA gives no meaning is the character itself (`\z`, `\A`, `\<`, `\v` are letters, not anchors), `{,n}` is `{0,n}`, a `{` that starts no repetition is a literal, and a class is a list of bytes and ranges (`[[:alpha:]]`, `&&`, `--`, nested `[` are not class syntax). YARA's refusals are kept: `(?...)` groups, back-references, non-ASCII characters in a class |
| Conditions | `true`, `false`, `$a`, `#a`, `$a at N`, `$a in (N..M)`, `any`/`all`/`none`/`N`/`N%` `of them` and `of ($a*, $b)`, `and`, `or`, `not`, parentheses, `filesize`, integers (decimal, `0x`, `0o`, `KB`, `MB`), `+ - * \ %`, `== != < <= > >=`. As in libyara: `0 of` means none of them, a string named twice in a set counts twice, a computed percentage over 100 is never met |

Refused, with the construct named at its `file:line`: `import` and every
module (`pe`, `elf`, `math`, `hash`, `dotnet`, …), `include`, `for` loops,
`uint8()` … `int32be()`, `@a[i]` and `!a[i]`, `#a in (range)`, the string
operators (`contains`, `matches`, `startswith`, …), external variables,
`entrypoint`, `defined`, bitwise operators, floating-point numbers, `of` over
rules or with `at`/`in`, the `xor`, `base64` and `base64wide` modifiers, `wide`
regular expressions, and `~` in hex strings. YARA's own compile errors are
enforced as well: a string the condition never uses, an undefined string, a
rule defined twice, a reference to a rule not yet defined, a jump at either end
of a hex alternative's branch, a constant range whose lower bound is above its
upper bound, a constant zero divisor, a constant percentage outside 1–100.
One deliberate difference: a constant `N of` larger than its set, which can
never match, is refused where YARA accepts it.

The subset was checked against libyara 4.5.4 (yara-python) on synthetic
inputs: 127 rules × 60 inputs, every (rule, input) pair evaluated by both,
7,620 of 7,620 agreeing. The rules cover each string form and modifier,
counts, `at`/`in`, sets and quantifiers, arithmetic and undefined values,
private, global and referenced rules, and the regex forms where the two
dialects differ; the inputs are short synthetic byte strings. It is not a
test on real rule libraries or real files.

**Fail closed.** A YARA file with any problem is refused as a whole, like any
custom pack. `sigil rules validate` lists every problem with its `file:line`
and exits `1`; a scan exits `2` rather than run without the rule, because a
rule that silently does not run is a detection gap nobody notices.

**Limits**, so that no rule can hold a scan past its per-file budget, whatever
the scanned bytes are:

- YARA evaluation shares the per-file budget (`SIGIL_FILE_BUDGET_SECS`,
  default 30 s), and every search is split into chunks of 64 KiB of start
  positions with the budget checked between them. The regex engine is
  linear-time, but not always fast: once a wide bounded jump overflows the
  lazy DFA's cache it crawls — `{ 41 [0-511] 42 }` over 9.5 MB of
  high-complexity synthetic data (the binary expansions of 1, 2, 3, …
  concatenated) took 54 s as one search, and `/A.*B/s` over 9.5 MB crafted
  so that every start is just too long a match, over 200 s. Chunked, a scan
  of either file stops at the budget (30.6 s and 30.7 s wall) and reports
  `PROV-BUDGET-001`. A rule whose evaluation the budget cut short is not
  reported either way — a search cut short reads as "no match", which
  `not $a` or `#a < 5` would turn into a finding — so a truncated count never
  produces a wrong finding; the file is reported as not fully analysed.
  `sigil rules test` applies the same budget and prints a `PROV-BUDGET-001`
  note for a sample it could not finish.
- The counted repetition in one string — bounded hex jumps and regex `{n,m}`
  counts, summed, plus the minimum of `[n-]` and `{n,}` — is capped at 512,
  and a wider string is refused with the limit named, because the cost per
  byte of a crawling search grows with that width. `[-]`, `*` and `+` are not
  counted.
- A match of a string with an unbounded part (`[-]`, `[n-]`, `*`, `+`,
  `{n,}`) is at most 4096 bytes long. This is not libyara's limit, in either
  direction. Measured with libyara 4.5.4: a regular expression match stops at
  about 1 KB (`/QQQ.*ZZZ/s` matched with 1,018 bytes between the markers,
  not 1,019), so Sigil can match a regex YARA would not; an unbounded hex jump
  is not limited at all (`{ 51 51 51 [-] 5A 5A 5A }` matched across
  200,000 bytes), so a hex string whose jump spans more than about 4 KB
  matches in YARA and not in Sigil.
- `#a` stops counting at 1,000,000 matches, as YARA does.
- A rule file is at most 8 MB; a condition has at most 1000 terms and 64
  levels of nesting (parentheses, `not`), its sets name at most 1,000,000
  strings in total (`them` counts every string of the rule), and hex
  alternatives nest at most 16 deep. Parsing and evaluation recurse, so a
  pathological file is refused rather than allowed to exhaust a thread's stack
  or its memory.

**Cost.** Rules are compiled once per scan. On this repository's self-scan
(523 files, 4 cores, median of 5 runs) one text rule took the YARA stage
2.3 ms in total and 100 rules of three strings each 1.77 s summed across scan
threads; the scan's own time stayed within run-to-run noise (11.53 s with no
rules, 11.46 s and 11.68 s with them). Chunking every search for the budget
(above) cost the YARA stage about 10%: in two paired runs with the 100 rules,
1.55 s and 1.66 s against 1.41 s and 1.50 s before (3.5–3.8% of stage time);
the scan's time again stayed within run-to-run noise (medians of 3
interleaved runs on a shared, loaded machine: 12.0 s against 11.7 s with no
rules, 11.3 s against 11.7 s with one rule, 12.3 s against 11.7 s with 100,
every run in 11.1–14.8 s, findings identical). With YARA rules loaded every
file's bytes are kept in memory while it is scanned, and binary archive
members are retained for them (32 MB cap).

**Signing.** A YARA file cannot hold a signature inside it, so it is signed
detached: `<file>.sig` beside it holds a base64 Ed25519 signature over the
file's exact bytes, prefixed with `sigil-yara-detached-signature-v1\n` so the
signature can never be replayed for anything else Sigil verifies.

```bash
sigil rules sign acme.yar --key sigil-packs.pem -o acme.yar.sig
# stderr prints: export SIGIL_PACK_PUBLIC_KEY=<64 hex chars>
```

`sigil rules sign` refuses to sign a file that does not validate. Ship the
`.sig` next to the `.yar`. With `SIGIL_PACK_PUBLIC_KEY` set, a YARA file
without a valid signature — none, one from another key, or one for a file
edited after signing — is refused with a `[SECURITY]` error and the scan exits
`2`, exactly as an unsigned JSON or YAML pack is. Without the key, a `.sig`
that is present is reported as "signed (not verified)".

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
stdout (the text report is then written without colour). `-o` is honoured by
`scan`, `clone`, `pip`, `npm`, `baseline` and `rules list`/`show`/`sign`
(`sbom` and `policy generate` keep their own `-o`); any other command refuses
it with exit `2` rather than ignore it and leave the file unwritten. Progress and
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

## Rule ids that changed (lifecycle classification)

Policies, baselines and SIEM rules key on rule ids and fingerprints. The
third MCP false-positive pass
([mcp-server-calibration.md](detection/mcp-server-calibration.md#third-pass-lifecycle-scripts-and-match-local-suppression))
moved some findings to new ids:

| Was | Now | When |
|---|---|---|
| `INSTALL-003` (Critical) | `INSTALL-010` (Medium) | `preinstall`/`postinstall` is exactly `node <local script>` and the script passes the inert test |
| `INSTALL-003` (Critical) | `INSTALL-011` (Low) | the command is exactly `npx only-allow <pm>` |
| `INSTALL-004` (Medium) | `INSTALL-012` (Low) | `prepare`/`prepublish` runs only build steps (`tsc`, `husky`, `chmod +x`, `shx`/`rimraf` on package paths) |
| `INSTALL-004` (Medium) | `INSTALL-009` (Low) | the key is `prepublishOnly`, which npm runs on publish only |
| `CODE-014` (High) | `CODE-016` (Medium) | a `bin` launcher installs its own platform package at run time |
| `SKILL-006` on `package.json` | (none) | `INSTALL-003` already reports npm lifecycle keys |

- A `disable_rules` or `severity_overrides` entry for `INSTALL-003`,
  `INSTALL-004` or `CODE-014` no longer applies to the findings that moved;
  add the new id if you want the same treatment. Globs such as `INSTALL-*`
  keep matching.
- The fingerprint covers the rule id, the file and the snippet, so a baseline entry for a
  moved finding is reported stale and the finding comes back under its new id.
  Regenerate the baseline (`sigil baseline`) after upgrading.
- The corpus digest now covers every rule field that can change a finding
  (severity, evidence, suppressions, provenance rules, an engine revision), so
  cached scan results are invalidated once on upgrade.

## Limitations

Stated plainly so nothing here is over-relied on:

- **`.sigilignore` is honoured from the scanned tree.** A tree can hide its own
  files from the walk with a `.sigilignore`. The scanned-tree guard covers
  policy files, not `.sigilignore`. (Tracked for a future release.)
- **`sigil:ignore` markers are outside the organisation policy.** An inline
  marker in the scanned tree suppresses the rule it names on that line or
  file, at any severity, whatever the organisation policy locks. Each one is
  listed in the report (`inline_suppressed`, SARIF `inSource`), so review
  them as part of code review; there is no switch to disable them.
- **Standing inside a tree trusts its `.sigil.yml`.** The guard applies when
  you scan a tree from outside it; `cd`-ing into a freshly downloaded
  repository and running `sigil scan .` applies that repository's policy in
  full (the report names it). Use `sigil clone`, scan from outside, or
  `--no-project-config` for code you have not reviewed, and lock the
  organisation policy's loosening keys.
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
- **YARA support is a subset**: the string-matching core, without modules
  (`pe`, `elf`, `math`, …), loops or offset reads. A rule that needs them is
  refused with the construct named, not approximated, so a library that leans
  on modules has to be split. Directories of rule files are read one level
  deep.
