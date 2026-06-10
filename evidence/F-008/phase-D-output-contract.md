# Phase D — Output contract (US-D1, US-D2) + D3 status

Date: 2026-06-10. Verification on `cli/target/release/sigil`.

## US-D1 — exit-code contract (ADR-0010) — DONE
Added `--fail-on <low|medium|high|critical>` (default high). Exit logic extracted to
pure `exit_code_for(findings, threshold)`; missing path / invalid `--fail-on` → 2.

Done-when (all observed):
```
scan test-repo            (High findings, default fail-on=high)  -> 1   ✓
scan <empty dir>                                                 -> 0   ✓
scan <nonexistent path>                                          -> 2   ✓
scan test-repo --fail-on critical  (findings are High, not Crit) -> 0   ✓
scan test-repo --fail-on bogus                                   -> 2   ✓
```
Unit tests: `exit_code_tests::*` (5 cases) pass.

## US-D2 — SARIF 2.1.0 — DONE
`output::print_scan_sarif` emits SARIF 2.1.0. Validated against the official OASIS schema:
```
$ sigil scan test-repo --format sarif > out.sarif
$ check-jsonschema --schemafile sarif-schema-2.1.0.json out.sarif
ok -- validation done   (exit 0)
```
(schema: raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json)

## US-D3 — self-scan CI gate — NOT DONE (triage required)
Self-scan of the repo currently reports 1921 findings, 1074 high+critical. Inventory shows
these are dominated by Sigil's OWN pattern-bearing files — legitimate self-reference, not bugs:
- docs/malicious-signatures.md, docs/detection-patterns.md, docs/prompt-injection-patterns.md (the signature research)
- packs/data/skills/**/SKILL.md (vendored skill corpus used as scan targets)
- api/tests/test_scanner_service.py, api/tests/performance/test_d1_d4_evaluation.py (scanner test inputs)
- bin/sigil (the bash scanner whose source contains the patterns as grep strings)
- sigil-skill/sigil-scan/references/PHASES.md (phase documentation)

US-D3 needs an honest `.sigilignore` covering these self-reference categories WITH written
rationale, AND a real review of the residual non-doc/non-test source findings (e.g.
api/utils/code_flow_analyzer.py) to confirm none are genuine before the gate can pass clean.
This triage is the remaining work; deferred to avoid a blanket-ignore that would hide real findings.

cargo test: 23 passed / 0 failed.
