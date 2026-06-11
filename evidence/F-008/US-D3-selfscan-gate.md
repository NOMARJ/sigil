# F-008 US-D3 — Self-scan as a required CI gate

Date: 2026-06-11. Branch: `worktree-agent-adeba4bea51c91546` (off `f-008/phase-a-b-hardening`).
Binary: `cli/target/release/sigil` (sigil-cli 1.1.2, release build).
Data source: Real — live self-scan of this repository working tree. No synthetic data.

## Summary

Built the release binary, ran the full self-scan, triaged every high+critical finding
into (a) self-reference-by-design / scanner-FP and (b) genuine issues. Wrote a precisely
scoped, rationale-backed `.sigilignore`; fixed the one genuine code smell found; and added
a SHA-pinned `actionlint`-clean CI workflow that gates on `--fail-on high`.

| | Findings (all) | High+Critical | Gate exit (`--fail-on high`) |
|---|---|---|---|
| **Before** (`.sigilignore` absent) | 1919 | 1073 | 1 |
| **After** (`.sigilignore` + fix)   | 166  | 0    | 0 |

Before, by severity: 362 Critical / 711 High / 777 Medium / 69 Low (1167 files scanned).
After: 0 Critical / 0 High / 130 Medium / 36 Low (432 files scanned). The 166 residual
findings are all **below** the `high` threshold, so the gate exits 0 honestly. Medium/Low
residuals are real signal kept visible (curl-in-Dockerfile, subprocess in git_analyzer,
MCP-server references) — not suppressed, just not gating.

## Category (a) — self-reference-by-design + known scanner-FP (suppressed in `.sigilignore`)

High+critical counts at baseline, grouped by suppression rationale:

| Count | Category | Examples |
|------:|----------|----------|
| 237 | Vendored skill/command corpus (scan targets, not Sigil source) | `packs/data/skills/llm/llm-evaluation/SKILL.md` (40), `packs/data/skills/llm/rag-implementation/SKILL.md` (30) |
| 222 | Signature/detection RESEARCH docs | `docs/malicious-signatures.md` (50), `docs/detection-patterns.md` (36), `docs/prompt-injection-patterns.md` (19) |
| 184 | Scanner TEST INPUTS | `api/tests/test_scanner_service.py` (38), `api/tests/performance/test_d1_d4_evaluation.py` (23) |
| 129 | Detection-ENGINE source (function is to embed the patterns) | `api/utils/code_flow_analyzer.py` (18), `api/services/scanner.py` (14), `cli/src/scanner/phases.rs` (13), `api/services/prompt_scanner.py` (11) |
| 87 | Sigil skill docs/scripts | `sigil-skill/sigil-scan/references/PHASES.md` (66) |
| 51 | Synthetic attack fixtures (Phase B) | `tests/fixtures/**`, `tests/regression/**` |
| 40 | Security blog research articles | `blog/03-six-phases-of-detection.md` (18) |
| 39 | Other project docs/txt (verdicts, pattern names as evidence) | `docs/VERIFICATION_REPORT.md` (22), `tasks/lessons.md` (5) |
| 23 | Archived/dead code | `archive/**` |
| 22 | Plugin skill/README docs | `plugins/claude-code/skills/fix-finding/SKILL.md` (12) |
| 20 | Bash scanner source (patterns as literal grep strings) | `bin/sigil` |
| 13 | Seed/sample scan data | `api/seed_data.py` |
|  6 | Captured scan output | `scan_output.txt` |

### Detection-engine source: why these specific files, not whole trees

`api/` and `cli/` are **not** excluded wholesale. Only the individual files whose
*purpose* is to define or describe the malicious patterns are listed — verified by
inspecting the actual findings:

- `api/services/scanner.py`, `scanner_v1.py`, `prompt_scanner.py`, `openclaw_rules.py`,
  `pattern_grouper.py`, `explanations.py`, `threat_intel.py` — pattern dictionaries,
  jailbreak-persona regexes (DAN/AIM/STAN), and human-readable risk explanations.
- `api/utils/code_flow_analyzer.py` — the dataflow analyzer's dangerous-sink list
  (`eval(`, `exec(`, `os.system(`, `pickle.loads`, `child_process.exec`).
- `api/data/threat_signatures.json`, `whitelist_patterns.json` — the signature pack and
  allowlist; patterns live here as data by definition.
- `api/prompts/*.py`, `api/scanner/phase9_llm_detector.py` — LLM prompt templates listing
  injection examples to detect, and an evidence-formatting delimiter join (PROMPT-007 FP).
- `cli/src/scanner/phases.rs`, `normalize.rs`, `mod.rs`, `context.rs` — Rust rule message
  strings and unicode-normalizer test asserting `eval(`.
- `plugins/mcp-server/src/index.ts`, `plugins/vscode/src/runner.ts` — tool-description
  strings listing detected patterns; `execFile`/`child_process` used to invoke the binary.
- `dashboard/src/components/onboarding/FirstScanStep.tsx`, `InsightsGuideStep.tsx`,
  `FindingsList.tsx`, `app/threats/page.tsx` — demo/onboarding UI that displays example
  malicious snippets and label text to users.

### Known scanner-FP in real production code (suppressed WITH rationale, reported for Phase C)

These are benign idioms the current rules over-flag. They are documented, not hidden, and
are FP-narrowing work for Phase C (scanner logic is out of scope for this story):

- `api/routers/attestation.py`, `bot/attestation.py`, `api/services/mcp_crawler.py` —
  `base64.b64decode` of signing keys / fetched MCP manifests. Decode-without-exec; the
  CODE/OBFUSC base64 rule fires on any `b64decode`.
- `.env.example` — `sk_live_your_stripe_secret_key` and `PRIVATE KEY "-----BEGIN…-----..."`
  are literal **template placeholders**, not credentials (CRED-006 can't tell template
  from key).
- `docker-compose.yml` — `${SIGIL_PG_PASSWORD:-sigil_dev_password}` is an env-overridable
  **local-dev** default; production uses Azure SQL (no compose). CRED-008 can't see the
  env-override default syntax.
- `package.json`, `dashboard/package.json` — first-party `postinstall`/`preuninstall`
  installing Sigil's OWN prebuilt binary, not a dependency supply-chain hook.
- `dashboard/playwright.config.ts` (INFER-002 on test `baseURL: localhost:3000`),
  `test_auth0_flow.sh` (NET-006 on an echoed OAuth callback URL in a dev script).
- `scripts/*.cjs` harness scripts referencing pattern strings as data.

## Category (b) — genuine issues found and how each was handled

One genuine issue, fixed (not suppressed):

- **`api/services/notifications.py:56`** — `"ts": __import__("time").time()`. A real
  dynamic-import code smell that legitimately trips **CODE-010** (`__import__()` — dynamic
  import). This is benign but it IS poor style, so the honest action is to fix the code,
  not ignore it. Replaced with a top-level `import time` and `time.time()`. The file is
  therefore **not** in `.sigilignore` — the finding is gone because the code improved.
  `python3 -c "import ast; ast.parse(...)"` confirms syntax OK.

No other genuine vulnerabilities (real hardcoded live secret, real eval-on-untrusted-input,
real exfil in product code) were found. Every other high+critical finding is either
self-reference-by-design or a documented scanner FP per the breakdown above.

## Verification

### Gate passes honestly on a clean tree

```
$ ./cli/target/release/sigil scan . --no-cache --fail-on high > /dev/null 2>&1; echo $?
0
```
Human-text run confirms: `Breakdown: 0 critical, 0 high, 130 medium, 36 low`. (The
"CRITICAL RISK" text banner is a cosmetic score-based label; per ADR-0010 the **exit code**
is the CI interface, and it is 0 because nothing is >= the `high` threshold.)

### The gate is meaningful — canary still trips it

A real malicious file dropped at repo root (NOT covered by any `.sigilignore` entry):

```
$ printf "eval(__import__('os').environ)\n" > ./canary.py
$ ./cli/target/release/sigil scan . --no-cache --fail-on high ; echo $?
  HIGH     [CODE-001] canary.py:1      (eval() call — arbitrary code execution)
  HIGH     [CODE-010] canary.py:1      (__import__() — dynamic import)
1
$ rm ./canary.py
$ ./cli/target/release/sigil scan . --no-cache --fail-on high > /dev/null 2>&1; echo $?
0
```

The suppressions did not weaken the scanner: a new malicious file at the repo root is
detected and forces exit 1; removing it returns the tree to exit 0.

### actionlint

```
$ actionlint .github/workflows/sigil-selfscan.yml ; echo $?
0
```
actionlint 1.7.12 (Homebrew), clean. Workflow SHA-pins `actions/checkout@34e1148…` (v4) and
`dtolnay/rust-toolchain@29eef33…` (stable) to match the SHAs already used in
`.github/workflows/ci.yml` and the other workflows.

## Files

- `.sigilignore` — new, repo root, every entry/block rationale-commented.
- `.github/workflows/sigil-selfscan.yml` — new, SHA-pinned, actionlint-clean gate.
- `api/services/notifications.py` — fixed category (b) `__import__("time")` → `import time`.
- `evidence/F-008/US-D3-selfscan-gate.md` — this file.
