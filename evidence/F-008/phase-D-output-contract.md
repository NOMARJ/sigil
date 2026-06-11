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

## US-D3 — self-scan CI gate — DONE (2026-06-11)
Triaged 1073 high+critical self-findings. All are category (a) self-reference-by-design
(signature docs, vendored `packs/` skill corpus, `api/tests/` scanner inputs, detection-
engine source in `api/services/*` + `cli/src/scanner/*`, `bin/sigil`, synthetic
`tests/fixtures/**`) or documented scanner-FP (base64-decode-without-exec, `.env.example`
template placeholders, dev-default compose password, first-party lifecycle scripts).
One category (b) genuine code smell FIXED: `api/services/notifications.py`
`__import__("time").time()` → top-level `import time` (removes CODE-010 by improving code,
not suppressing). `.sigilignore` is precisely scoped (individual engine files, NOT whole
api/ or cli/ trees) with per-block written rationale.

After: `sigil scan . --no-cache --fail-on high` → exit 0 (0 critical / 0 high / 130 medium
/ 36 low). Gate proven meaningful — canary `eval(__import__('os').environ)` at repo root →
CODE-001 + CODE-010 HIGH → exit 1; removed → exit 0. `.github/workflows/sigil-selfscan.yml`
SHA-pinned (checkout 34e1148…, rust-toolchain 29eef33…), actionlint 1.7.12 clean.
Full evidence: evidence/F-008/US-D3-selfscan-gate.md.

cargo test: 23 passed / 0 failed.
