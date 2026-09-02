# What Sigil can adopt from prism-scanner

**Status:** research note — the review that produced this branch, kept as the record of
how each decision was reached
**Date:** 2026-09-02
**Subject:** [aidongise-cell/prism-scanner](https://github.com/aidongise-cell/prism-scanner)
(Apache-2.0, v0.2.2, one author)

---

## Summary

prism-scanner is a Python scanner for AI-agent skills, MCP servers and packages. It is
small — 4,643 lines of Python, 39 rule ids plus 16 YAML signatures, one author, 27 commits
all dated 2026-04-06 — and it has more visible traction than Sigil. The question this note
answers is *why*, and what of it is worth taking.

The short answer, after checking every candidate against Sigil's source and measuring the
ones that mattered:

1. **Its traction comes from distribution and positioning, not detection.** `pip install
   prism-scanner` is the whole install story; it is listed in the official MCP registry;
   its skill files carry Chinese trigger phrases for the ClawHub audience; it prints a
   letter grade and hands you a badge; it published a "Top-100 skills" report. None of
   that is detection, and all of it was cheap to match once named.
2. **Two product ideas were genuinely missing from Sigil.** A host-side *residue* scan
   (what installed tooling left in your shell rc, crontab, hooks and credential files)
   with a reversible cleaner, and an explicit link between a manifest's install script
   and the file it runs. Both now exist, built Sigil's way (classification by shape and by
   the corpus rather than keyword lists; backups and a manifest before any change).
3. **Most of prism's rules were either already covered or a pack edit away.** Sigil's
   corpus went from 214 rules in 12 packs to 276 in 14 on this branch; the additions were
   bounded by the self-scan gate (0 new High/Critical) and by fixtures.
4. **The most valuable thing the review found was Sigil's own.** `dist/` and `build/` were
   hard-excluded from every scan, and 230 of the 844 malicious packages in the evaluation
   set ship code under `dist/`. prism does not have that blind spot because it never
   optimised for a sub-60-second self-scan. Measured effect: §7.
5. **Sigil's real competitive weakness is not prism.** It is the false-positive rate on
   clean, popular packages (75% flagged at High or worse before this branch, §7), which no
   amount of prism-matching changes. §8 ranks that first.

### Traction, measured

| | prism-scanner | Sigil |
|---|---|---|
| GitHub stars / forks / open issues | 19 / 2 / 0 | 5 / 2 / 4 |
| First public release | PyPI 2026-03-15 (repository history published 2026-04-06) | repository created 2026-02-15 |
| Primary channel | PyPI: 1,512 downloads without mirrors over 153 days; 179 in the last 30 days, 23 in the last 7 | npm `@nomarj/sigil`: 58 in the last 30 days, 8 in the last 7 (Homebrew, `install.sh` and `cargo install` are not measurable from here) |
| Registry listings | official MCP registry (`io.github.aidongise-cell/prism-scanner`), PyPI, Homebrew tap (placeholder formula), npm wrapper (unpublished) | npm, Homebrew tap, crates.io; MCP server package unpublished, not in the registry |
| Commits / authors | 27 / 1 | hundreds / several |

```
Data Source: GitHub repository metadata (2026-09-02), pypistats.org API without mirrors, api.npmjs.org
Sample Size: the two projects
Limitations: star and download counts are small enough that a single blog post moves them; Sigil's non-npm install channels are uncounted; prism's PyPI count includes CI re-installs.
```

Both numbers are small. "More traction" here means roughly four times the stars and three
times the monthly downloads on the main channel — a discoverability gap, not a product
gap.

### Implementation status

Everything in this table is on the branch this note was written on. "Measured" means a
real run, with the run described in §7 or in the row.

| Area | Shipped as | Measured |
|---|---|---|
| Host residue (§4) | `sigil residue scan \| plan \| apply \| rollback`, `cli/src/residue/` (9 checks, command classification by shape, backups + manifest, refusal rules); MCP `sigil_residue_scan` / `sigil_residue_plan` | synthetic home with 4 planted problems: 6 items (1 Critical, 4 High, 1 Info), 3 plannable, apply 3, rollback restores the file byte-identical; a second apply after a partial first one chains correctly (regression test) |
| Grade, profile, key risks, platform (§3) | `scanner::profile`, `summary.grade` / `recommendation` / `platform`, top-level `profile`; MCP `sigil_grade` | JSON contract test keeps `summary` scalar-only and `findings` the first array |
| HTML report (§3) | `--format html`, `cli/src/html_report.rs` (no scripts, everything escaped) | prism's own fixture renders; self-scan renders |
| Inline suppression (§3) | `sigil:ignore RULE[,RULE] -- reason`, `-next-line`, `-file`; reported under `inline_suppressed` and as SARIF `suppressions` | 21 self-scan findings carry a marker and are listed, not dropped |
| `sigil scan <git-url>` (§3) | routes to the quarantine clone path | unit test on URL detection |
| GitHub Action (§3) | `upload-sarif` / `sarif-file` inputs, `grade` / `badge` / `sarif-file` outputs, job-summary badge | entrypoint exercised with a local harness (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY` as files); no live workflow run on this branch |
| Rules (§5) | 62 new rules across persistence, manipulation, prompt injection, network, credentials, hygiene, skill security, one correlation rule, `TYPOSQUAT-001`, `INSTALL-REF-001` | self-scan gate: 0 new High/Critical, +45 Medium, +1 Low; 27 fixture cases pass; prism's own fixture: 20 findings, grade F |
| Walker (§6) | `dist/` and `build/` no longer hard-excluded | 230 / 844 malicious samples carry `dist/` files; recall and false-positive deltas in §7 |
| pip wrapper (§1) | `python/` — `pip install sigilsec`, standard library only, SHA-256 against `SHA256SUMS.txt`, fail closed | 29 tests; the name `sigil-cli` was found taken on PyPI during review (§Verification) |
| MCP registry (§1) | `plugins/mcp-server/server.json`, `mcpName` in `package.json` | validated against the 2025-12-11 schema; publishing waits on the npm release (owner action) |
| Skill discovery (§2) | English and Chinese trigger phrases in every `SKILL.md`; `sigil-skill/skill.json` | none — this is metadata |
| Community (§1) | issue templates (bug, false positive, false negative, new rule, threat report), PR template, code of conduct, CONTRIBUTING rule-authoring guide | none |
| MCP server fix (§6) | scan tools read the JSON contract's `summary`; exit code 1 with a document is a result | 12 tools verified over stdio: `tools/list`, `sigil_scan`, `sigil_grade`, `sigil_residue_scan`, `sigil_residue_plan` |
| Rule metadata | `remediation`, `references`, `tags` on every rule that lacked them (179 rules across 10 packs, written by one agent per pack) | all 276 rules now carry `remediation` and `tags`, and `references` where an identifier was certain; every pack diffed against HEAD as parsed rules — ids, patterns, severities, descriptions, filters and suppressions unchanged; 304 tests pass |

### Verification status

Every candidate gap was checked against the source before it was written down, then
re-checked adversarially after implementation. Method: eight verification agents, one per
group (persistence, network, credentials, manipulation, output, supply chain, residue,
growth), each with the prism source and the Sigil tree, each required to cite file and
line. A second pass of refuters was told to disprove each item against the tree *as it
stood after implementation*. The container restarted before the residue group's refuter
and the completeness critic finished; their partial output is in the session record and
nothing below depends on it.

The refuters changed the plan in seven places. These are the corrections that matter,
recorded because the first draft was wrong:

| Item | First draft | What the refuter found | Outcome |
|---|---|---|---|
| `NET-015` abused-TLD rule | shipped at Low | the host character class allowed `/`, so `https://cdn.example.com/assets/file.download` matched | fixed: host class excludes `/`, `?`, `#` |
| Install-script elevation | bump every finding in a referenced file one level | verdict was already CRITICAL from `INSTALL-003`; a blanket bump rewrites fingerprints and hits prebuilt-binary downloaders; "the durable part is the explicit link" | replaced by one finding, `INSTALL-REF-001`, on the manifest, one level above the worst finding in the file; nothing else changes |
| `NET-016` hard-coded public IP | proposed at Low as a correlation input | never gates, never changes a verdict, and prism's own P4 labels the link-local metadata address a "public IP"; `NET-013` already covers the one that matters | dropped |
| `SKILL-009` dangerous tool grants | one High rule for `rm`, `curl`, `python`, … | a `curl` grant is common and not malicious; the prose-list shape argued for Medium | split: `SKILL-009` High for delete/escalate/persist/shell, `SKILL-010` Medium for downloaders and interpreters |
| pip package name | `sigil-cli`, matching crates.io | already taken on PyPI by an unrelated project (`sigil-cli` 1.5.2, "Configuration driven CLI builder") | renamed `sigilsec` (free at time of writing) |
| `summary.platform` | ship it | "an informational label with no consumer"; Sigil's rules are already file-scoped; a monorepo will be mislabelled | kept, with that dissent recorded: it is one scalar, additive, and the head-to-head in §7 needed it; §8 says what should consume it or it should go |
| `SKILL-007` malformed manifest | Medium, any JSON manifest | "a packaging defect, not a malicious signal"; JSONC configs would be flagged | kept at Low, restricted to skill and MCP manifests, JSONC tolerated; the dissent stands and is fair |

Items the refuters confirmed as real and unimplemented are in §8. Items they refuted
outright are in the next section.

### What is explicitly not worth taking

- **Shannon-entropy secret detection (P7).** Measured on real files: 1,375 hits, all
  in three lockfiles. prism hides that flood behind its extension gate (it never reads
  lockfiles). The vendor-prefix rules (`CRED-013..029`) capture the durable value at
  near-zero false positives, and an entropy primitive is a computed, non-declarative
  check that [ADR-0005](../adr/ADR-0005-signed-declarative-signature-packs.md) keeps out
  of packs. The refuter disagreed with rejecting it; the measurement did not change.
- **A bare `system\s*:` delimiter rule.** 26 hits on Sigil's own tree at the gate.
  `PROMPT-003` already matches the tag forms.
- **The "star us on GitHub" line after every scan.** The owner's written distribution
  policy rejects exactly this (`SIGIL-DISTRIBUTION-ROADMAP.md` §3.3.5, §8).
- **Keyword-based residue heuristics.** prism flags an rc line because it contains an
  agent's name. Sigil's residue checks classify the *command* (pipe-to-shell, base64
  decode, remote `eval`, inline Python, reverse-shell shape, a binary in a temporary or
  cache path, a binary that no longer exists) and run the corpus over it; the tool table
  is used for inventory and attribution only.
- **`--show-trace`.** On prism's own fixture 14 of 18 "traces" are one-word strings.
  Sigil's correlation findings already embed the source line, the sink line and the
  identifier that links them in the snippet.
- **A "contradictory instructions" manipulation rule.** prism's regex is `do this but
  also don't`; there is no shape there to match.
- **Python-only AST and intra-file taint (S1–S14).** This is prism's most expensive
  component and its most limited: Python only, one file at a time, and it produced
  nothing on the JavaScript fixture. Sigil's answer is the declarative correlation rule
  (`EXFIL-CHAIN-001`: a credential read whose assigned identifier reaches a network
  send within 20 lines), which is the one thing a line regex cannot say, expressed
  without the engine executing anything.
- **An "Awesome AI Security" badge.** The premise that prism is listed there could not
  be verified from the list's source; nothing to copy.
- **Whole-line bullet manipulation patterns (P10 as written).** Taken, but re-cut: each
  `MANIP-*` rule is bounded (`[^.\n]{0,80}` instead of `.*`) and scoped to instruction
  files, and the measured self-scan cost was 0 hits.

---

## 1. Distribution is the gap, not detection

**What prism does.** `pip install prism-scanner`. That is the whole install section of
its README. The npm wrapper exists in the repository but was never published; the
Homebrew tap is a placeholder. Everything else — the MCP registry entry, the ClawHub
skill manifest — points back at the PyPI package.

**What Sigil had.** Four install paths (`install.sh`, Homebrew tap, npm wrapper, `cargo
install`), none of them `pip`, for a tool whose second most common target is a Python
package, and whose MCP server package points at an npm name that was never published
(`registry.npmjs.org/@nomark/sigil-mcp-server` → not found; `@nomarj/sigil` is published
at 1.0.2 … 1.3.6).

**What shipped.** `python/` is a standard-library-only wrapper: it picks the release
asset for the platform, downloads it from the pinned GitHub Releases URL, verifies it
against the release's `SHA256SUMS.txt`, fails closed, caches it under `~/.sigil/bin/`,
and hands off with `execv`. It adds no supply-chain surface of its own — which matters,
because a security scanner delivered through a wrapper that could itself be tampered
with is a bad joke. The `server.json` for the MCP registry is written and validated;
publishing it requires the npm package to exist first, which is an owner action
documented in `plugins/mcp-server/README.md`.

**What the review caught.** The obvious name, `sigil-cli`, is taken on PyPI by an
unrelated project. The wrapper is published as `sigilsec`; the import package is still
`sigil_cli` and the command is still `sigil`.

## 2. Positioning: skills, MCP, and the ClawHub audience

prism describes itself as a scanner for "AI agent skills" first and packages second, and
its skill files carry Chinese trigger phrases (`安全扫描`, `这个插件安全吗`, `安装前检查`)
alongside English ones. That is not decoration: ClawHub and the OpenClaw ecosystem have a
large Chinese-speaking user base, and an agent decides whether to invoke a skill by
matching the user's words against the skill description. A skill that only triggers on
English sentences is invisible to half the audience prism is courting.

Sigil's four skill descriptions now carry the same bilingual trigger phrases and a
`skill.json` for ClawHub discovery. The README comparison table also gained an honest
prism column: it has a real skills/MCP focus, and a real residue cleaner, and it is
Python-AST-only where Sigil is multi-ecosystem.

## 3. Output people paste

prism prints a letter grade and a recommendation sentence, emits an HTML report, uploads
SARIF from its GitHub Action, and hands the caller a shields.io badge. Sigil printed a
verdict and a score.

All four are presentation over the verdict Sigil already computed, and they were built
that way: the grade is a label (A no findings, B low-severity only, C/D/F for the three
risk verdicts), never a second score; the HTML report is one self-contained page with no
scripts and every value escaped, and it renders the JSON document rather than
re-deriving anything; the SARIF upload is a guarded `always()` step so findings reach Code
Scanning even when the threshold fails the job.

Two of prism's output features turned out to be better done Sigil's way. Inline
suppression markers capture a *reason* (`sigil:ignore CODE-013 -- argv list, no shell`),
support next-line and whole-file scopes, and never drop the finding: it is listed under
`inline_suppressed` with its attribution and emitted as a SARIF `suppressions` entry, so
a reviewer can audit every one from the report. And `sigil scan <git-url>` reuses the
quarantine clone path instead of adding a second fetcher.

## 4. Host residue

This is the one feature prism has that Sigil had nothing for, and it is the one that
justifies the "cleaner" in prism's positioning: after you have installed and removed a
few agent skills, what is left in your shell rc, your crontab, your git hooks, your
credential file permissions, your `/etc/hosts`?

prism's version (R1–R10) reads those places and flags entries that contain an agent
keyword, then offers a plan/apply/rollback cleaner with backups. The shape is right; the
detection is keyword matching, which both misses (`curl … | sh` in `.zshrc` with no agent
name in it) and over-fires (a legitimate `alias claude=…`).

`sigil residue` keeps the shape and replaces the detection:

- **Commands are classified by what they do**, not by what they mention: pipe-to-shell,
  base64 decode into a shell, `eval`/`source` of remote or temporary content, inline
  Python with sockets or `subprocess`, reverse-shell forms, an executable under `/tmp`,
  `/dev/shm` or `~/.cache`, an executable that no longer exists (a dangling hook or
  cron entry is the classic leftover), and finally the detection corpus itself.
- **Sigil recognises its own footprint.** The alias block `sigil setup shell` writes and
  the pre-commit hook `sigil setup git` installs are reported as inventory — unless they
  no longer match what Sigil writes, which is reported as tampering. The markers are
  shared constants between `setup.rs` and the checks so the two cannot drift.
- **`apply` is reversible by construction.** Every target is copied into
  `~/.sigil/backups/<id>/` with a manifest before it is touched; each action is checked
  against the file *as it is now* (a second removal in the same file is judged against
  the text after the first — a bug the first version had and a regression test now pins);
  symlinks, anything outside the home directory or the repository, and anything under
  `~/.sigil` are refused; system files (`/etc/hosts`, `/etc/cron.d`, `sudoers.d`) are
  reported and never changed. Without a terminal it refuses to run unless told `--yes`.
- **Secrets in evidence are redacted** before they reach stdout, and the JSON document is
  a different `kind` from a scan result, so nothing downstream mistakes it for one.
- **The MCP server exposes scan and plan only.** An agent can find residue and show the
  plan; a human applies it in a terminal. prism made the same call.

## 5. Rules

The verification pass sorted prism's rules into three bins:

**Already covered** (no change): reverse shells (Sigil has 81 rules to prism's handful),
`<system>` delimiter tags, zero-width and bidi characters, base64 and hex obfuscation,
`eval`/`exec`/`pickle`/`child_process`, credential file reads for `~/.aws` and `~/.ssh`.

**A pack edit away** (shipped, all declarative, all with fixtures):
persistence (`PERSIST-001..013`: cron, launchd, systemd, shell rc reference and write,
`authorized_keys`, sudoers and `NOPASSWD`, hosts/resolv, Windows Run keys and `schtasks`,
git hooks and `core.hooksPath`, autostart); agent manipulation (`MANIP-001..005`:
gaslighting, guilt, authority impersonation, urgency bypass, emotional coercion — each
bounded and scoped to instruction files); prompt injection (`PROMPT-009..011`: act-as-if
role play, `new instructions:`, override-your-rules; the existing rules now also cover
`.cursorrules`, `.windsurfrules`, `.clinerules`, `AGENTS.md`, `CLAUDE.md`, `.mdx`,
`.rst`); network (`NET-013` cloud metadata, `NET-014` tunnels and dynamic DNS, `NET-015`
abused TLDs, `NET-017` miners, `NET-018` DNS exfiltration, and `NET-007` widened);
credentials (`CRED-013..029` vendor token shapes from Slack to PyPI, `CRED-030..043`
credential stores, browser and keychain theft, and a same-line credential-plus-send
rule); publish hygiene (`HYGIENE-001..007`: source maps, `.env` variants, keys, `.pem`,
`.npmrc`/`.pypirc`/`.netrc`, dumps); skill manifests (`SKILL-008` wildcard grants,
`SKILL-009` destructive grants, `SKILL-010` downloaders and interpreters).

**Needed engine work, done Sigil's way:** the typosquat check (`TYPOSQUAT-001`, direct
dependencies within one edit of a top npm or PyPI name, with an allowlist for real
packages such as `httpx2`), the correlation rule (`EXFIL-CHAIN-001`), the install-script
link (`INSTALL-REF-001`), and the malformed-manifest check (`SKILL-007`, Low).

Every addition was run against Sigil's own tree before it was kept. The gate
(`sigil scan . --fail-on high`) shows 0 new High or Critical findings; the 45 new Medium
findings are almost all the residue module naming the crontab, rc and hosts files it
inspects, plus six `CRED-001` hits on the API reading its own keys from the environment
(the rule was deliberately widened to every `*_KEY`/`*_SECRET`/`*_TOKEN` read at Medium;
reading a secret from the environment is what a reviewer should *see*, not what should
fail a gate). The residue module carries file-level `sigil:ignore` markers with reasons
for the four rules it must trip.

## 6. What measuring prism revealed about Sigil

None of these came from prism's feature list. They came from running both tools on the
same inputs.

1. **`dist/` and `build/` were never scanned.** `DEFAULT_EXCLUDED_DIRS` listed them as
   "vendored/generated noise" under the ADR-0008 time budget. In a published npm package
   `dist/` *is* the package: 230 of the 844 malicious samples in the evaluation set carry
   files there. In a git checkout the project's own `.gitignore` already keeps build
   output out (the walker honours it inside real repositories), so removing the two
   entries changes nothing for repository scans and everything for package scans. Effect
   on recall and on the clean control set: §7.
2. **The MCP server printed `undefined`.** Its scan tools read `result.verdict` and
   `result.score` at the top level; the output contract had moved them under `summary`.
   Every agent using the server got "Verdict: undefined | Score: undefined". Fixed, with
   a fallback for older binaries.
3. **`NET-015` was wrong as shipped** (above). The refuter's probe found it; the
   self-scan had not, because nothing in the tree ends a URL path in `.download`.
4. **Engine time rose from 2,238 ms to 6,606 ms** on the self-scan (451 → 474 files),
   well inside the 60-second ADR-0008 budget but a 3× increase worth watching as the
   corpus grows. Wall time (2 m 31 s) is dominated by the advisory feeds through the
   proxy, not by the engine.
5. **`sigil-cli` is not available on PyPI**, and the first draft of the wrapper would
   have failed at publication.

## 7. Head-to-head measurements

```
Data Source: Datadog malicious-software-packages-dataset (real, human-triaged malicious npm and PyPI packages, plus its ai-skills bucket), commit 0f6b305b; clean control set of 20 popular npm and PyPI packages fetched from the registries
Sample Size: 844 malicious samples (204 per ecosystem/category bucket, deterministic selection) and 20 clean packages for the Sigil-vs-Sigil comparison; 268 malicious samples (60 per bucket) and the same 20 clean packages for the three-way comparison with prism, which scans at ~16 s per sample
Limitations: the dataset has selection bias (mostly GuardDog-identified, per Datadog's disclaimer); Sigil runs its offline phases only (no OSV/provenance feeds) for reproducibility; prism runs with --offline; the control set is small, so one package moves the false-positive rate by 5 points; precision is imbalance-distorted by 844:20 and is not reported; "detected" for prism means at least one non-info finding at the threshold, for Sigil at least one finding at the threshold, so the two are comparable but not identical
```

### Sigil main vs this branch (844 malicious, 20 clean)

| Threshold | main (4bb7778) recall | branch recall | main FP rate | branch FP rate |
|---|---|---|---|---|
| ≥ any | 86.37% (729) | 87.91% (742) | 90.00% (18/20) | 90.00% (18/20) |
| ≥ Medium | 86.14% (727) | 87.80% (741) | 85.00% (17/20) | 85.00% (17/20) |
| ≥ High | 75.95% (641) | 79.27% (669) | 75.00% (15/20) | 75.00% (15/20) |
| ≥ Critical | 47.87% (404) | 63.86% (539) | 25.00% (5/20) | 25.00% (5/20) |

The branch detects 13 more samples at any severity, 28 more at High and 135 more at Critical, and flags exactly the same clean packages as before at every threshold. The Critical jump is mostly `INSTALL-REF-001` (a lifecycle script that runs a file with findings) and the new credential-store and same-line credential-plus-send rules; the High gain is spread across the persistence, network and hygiene rules and the `dist/` walk. One sample hit the harness's 120-second scan cap on the branch (none on main) and is counted as not detected; the slowest sample in the per-sample run below took 97 s, a large Python package whose bundled JavaScript is now walked. The control set is unchanged because the rules that fire on popular packages (`NET-001`, the `OBFUSC-*` rules on minified code, `CRED-001`) were already firing before this branch, which is the point §8 makes.

### Three-way on prism's subset (268 malicious, 20 clean)

| Threshold | Sigil main recall | Sigil branch recall | prism 0.2.2 recall | Sigil main FP | Sigil branch FP | prism FP |
|---|---|---|---|---|---|---|
| ≥ any | 88.06% (236) | 89.18% (239) | 45.15% (121) | 90% (18/20) | 90% (18/20) | 65% (13/20) |
| ≥ Medium | 87.69% (235) | 88.81% (238) | 45.15% (121) | 85% (17/20) | 85% (17/20) | 65% (13/20) |
| ≥ High | 76.49% (205) | 79.48% (213) | 30.22% (81) | 75% (15/20) | 75% (15/20) | 60% (12/20) |
| ≥ Critical | 51.12% (137) | 54.85% (147) | 10.07% (27) | 25% (5/20) | 25% (5/20) | 20% (4/20) |

Per bucket (recall at ≥ High):

⟨BUCKET_TABLE⟩

prism could not finish 35 of the 268 samples: 33 exceeded the harness's 90-second cap and 2 produced no JSON. Those count as not detected above; excluding them, prism's recall is 51.9% at any severity and 34.8% at High, still well under half of Sigil's. The cap is the harness's choice, not prism's: without it the first attempt spent over four minutes on single samples and would not have finished. prism graded 112 of the 268 malicious packages **A** (clean), and 12 of the 20 popular clean packages **F**. Its false-positive rate on the control set is lower than Sigil's (60% against 75% at High), which is partly because it reads only ten file extensions and never sees lockfiles, and partly real: it does not fire on plain `requests.post` or on every `*_KEY` environment read, and Sigil should not either (§8). Sample by sample, at any severity: both tools caught 119, Sigil alone 120, prism alone 2, neither 27. At High: both 73, Sigil alone 140, prism alone 8. Per bucket the gap is widest on npm — prism's deepest engine is Python-only and 230 of the 844 malicious packages ship JavaScript under `dist/` — and narrowest on the PyPI compromised-library bucket, where its AST rules do their best work. The 2 samples only prism caught are worth reading for rule ideas: agentinsync-agentinsync-skill.zip, 2022-12-07-aioconsol.zip.

### The self-scan gate

| | main | branch |
|---|---|---|
| findings | 17 | 63 |
| High / Critical | 2 / 0 (both GHSA advisories in `dashboard/package-lock.json`, unchanged) | 2 / 0 |
| inline-suppressed | — | 21 |
| engine time | 2,238 ms | 6,606 ms |
| gate (`--fail-on high`) | red, pre-existing | red, same two advisories |

## 8. Ranked recommendations

What is left, in the order it is worth doing. Nothing here is prism-specific any more.

| # | Recommendation | Why | Cost |
|---|---|---|---|
| 1 | **Narrow the false-positive rate on clean packages, rule family by rule family, with the control set as the gate.** 75% of popular packages flagged at High before this branch is the number that stops `sigil` from gating real installs. Start with the families that fire on the control set (§7 lists them once the run completes). | this is the competitive weakness; prism's is worse but nobody measures prism | M |
| 2 | **Publish.** `sigilsec` to PyPI, `@nomark/sigil-mcp-server` to npm, then `mcp-publisher publish`. Until then the wrapper, the `server.json` and the README instructions point at nothing. | every other channel gain in this note is blocked on it | S, owner |
| 3 | **A rule-scoped suppression file** (`RULE-ID path-glob [-- reason]`) for files you cannot edit. It must be reported under its own key and as SARIF `external` suppressions, not folded into `inline_suppressed`. | the refuter confirmed the gap and rejected the first storage design | S |
| 4 | **Give `summary.platform` a consumer or remove it**: phase selection under the ADR-0008 budget, or the known-good lookup keyed by ecosystem. | one scalar with a dissent on record | S |
| 5 | **A public registry scan report** (ClawHub or the MCP registry), aggregate-only, with the disclosure block, fetched through quarantine. prism's Top-100 report is its best marketing asset. Naming skills with D/F grades at a 70% first-scan false-positive rate is reputationally irreversible and is the owner's call, not an agent's. | content marketing that is also measurement | M, owner decision |
| 6 | **Windows residue checks.** Run keys and `schtasks` are scan-side rules only; `sigil residue` has launchd and systemd checks but nothing for Windows. | the wrapper now installs on Windows | S |
| 7 | **Run the Action once with `upload-sarif: true`** under `security-events: write` to confirm the CodeQL upload step in a live workflow. | exercised locally only | S, owner |

## 9. Where Sigil can compete

Honestly: prism's advantages were cheap, and they have been matched on this branch. What
it does not have, and cannot get without becoming a different program, is what Sigil
should lead with:

- **Detection depth.** A decode worklist that runs every phase over decoded payloads,
  correlation rules, a known-good corpus that turns "unmodified published release" into
  LOW RISK and a changed file into `KNOWNGOOD-DRIFT-001`, 276 declarative rules in a
  signed corpus, and a residue scanner that judges commands rather than keywords.
- **Multi-ecosystem.** prism's deepest engine is Python-only and produced nothing on a
  JavaScript target; 230 of 844 malicious packages ship JavaScript under `dist/`.
- **CI-native.** Exit codes that gate, SARIF that Code Scanning ingests, a self-scan that
  the repository runs on itself as a required check.
- **Reversibility as a design rule.** Quarantine before install, a trust ledger instead of
  silent allowlists, backups and a manifest before any residue fix.

And the one thing it should fix before saying any of that loudly: the control-set
false-positive rate. A scanner that flags 15 of 20 popular packages at High is one that
people learn to ignore, and no comparison table changes that. §8 puts it first for that
reason.

---

## Sources

- [aidongise-cell/prism-scanner](https://github.com/aidongise-cell/prism-scanner) — source at v0.2.2, `src/prism/engines/{ast_engine,manifest_engine,pattern_engine,residue_engine,taint}.py`, `src/prism/rules/*.yaml`, `cleaner.py`, `mcp_server.py`, `action.yml`, `reports/clawhub-top100/`
- [pypistats.org API](https://pypistats.org/api/) — `prism-scanner` downloads without mirrors, 2026-03-15 to 2026-09-01
- [api.npmjs.org](https://api.npmjs.org/downloads/point/last-month/@nomarj/sigil) — `@nomarj/sigil` downloads
- [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) — evaluation samples, commit `0f6b305b`
- [Official MCP registry](https://registry.modelcontextprotocol.io) and the `2025-12-11` server schema
- [ADR-0005](../adr/ADR-0005-signed-declarative-signature-packs.md), [ADR-0008](../adr/ADR-0008-scanner-walker-normalization-context.md), [ADR-0010](../adr/ADR-0010-output-contract-sarif-exit-codes.md), [ADR-0011](../adr/ADR-0011-known-good-corpus.md)
- `scripts/run_eval.py` — the measurement harness; `evaluation_results/honest_detection_eval.md` — the published baseline
