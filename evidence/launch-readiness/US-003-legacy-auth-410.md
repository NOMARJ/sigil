# US-003 — Legacy Auth Tests → 410 Post-Auth0 (CRITICAL-004)

**Story:** F-007 / US-003 · **Linear:** NOM-1071 · **Executor:** agent (buildable)
**Date:** 2026-06-08 · **Depends on:** US-001

> **Data Source:** Real test execution (local dev workstation)
> **Sample Size:** `api/tests -k auth` (50 tests: 38 passed, 12 skipped) + full suite (562)
> **Limitations:** Local run, not CI.

## Change (test-only)

The production endpoints `POST /v1/auth/register` and `POST /v1/auth/login` were deprecated to
`HTTP_410_GONE` during the Auth0 migration (`api/routers/auth.py:605-621` register, `:624-640`
login — both `deprecated=True`, detail *"This endpoint is deprecated. Please use Auth0
authentication at /api/auth/login"*). Six legacy tests still asserted the pre-migration
contract (201/200/401/409). They are flipped to assert `410`, each referencing the production
410 contract and the Auth0 migration (`docs/internal/AUTH0_SETUP_GUIDE.md`, ADR-0002).

**Only `api/tests/test_auth.py` was edited — no `api/routers/auth.py` or production source.**

Tests flipped (200/201/401/409 → 410):

| Test | Old expectation | New |
|------|-----------------|-----|
| `TestRegistration::test_register_success` | 201 + token body | 410 + "deprecated" detail |
| `TestRegistration::test_register_duplicate_email` | 201 then 409 | 410 (both calls) |
| `TestRegistration::test_register_empty_name` | 201 + name=="" | 410 + "deprecated" detail |
| `TestLogin::test_login_success` | 200 + token body | 410 + "deprecated" detail |
| `TestLogin::test_login_wrong_password` | 401 | 410 |
| `TestLogin::test_login_nonexistent_user` | 401 | 410 |

Validation tests (`test_register_short_password`, `test_register_missing_email`) were left
unchanged — they assert 422, which fires during Pydantic validation *before* the 410 handler,
so they still pass.

## Verification

`-k auth` (AC: previously-failing legacy-auth tests now pass):
```
$ python3 -m pytest api/tests -q -k auth
38 passed, 12 skipped, 512 deselected, 4 warnings in 1.18s
```

Full suite (`/tmp/pytest-us003-2026-06-08.txt`):
```
20 failed, 203 passed, 339 skipped, 6 warnings in 1.98s
```

| Metric | Baseline (US-001) | After US-002 | After US-003 |
|--------|------|------|------|
| passed | 167 | 197 | **203** |
| failed | 25 | 26 | **20** |
| errors | 31 | 0 | 0 |

203 = 197 + 6 (the six flipped auth tests). No previously-passing test regressed.

## Honest finding — layered failures exposed by US-002

When US-002 removed the event-loop errors, **7 `test_scan.py::TestScanSubmission` tests** (which
were *errors* in the US-001 baseline, categorized there as `test-only-fixture-eventloop`) now
surface as **failures** with `assert 422 == 200`: the `clean_scan_request` fixture payload no
longer matches the current `/v1/scan` Pydantic request schema. This is a **stale test fixture**
(test-only, buildable) — not an event-loop issue and not a production bug. Together with
`test_monitoring::test_email_channel` (wrong mock target, US-001 §3d), these are **8
buildable-but-unscoped test fixes** that no current F-007 story covers. Surfaced for owner
decision rather than fixed under probation (scope discipline).

## Residual failures after US-001/002/003 (20)

| Bucket | Count | Buildable? | Status |
|--------|-------|-----------|--------|
| Stale test fixture — `test_scan` submission (422 schema drift) | 7 | ✅ test-only | unscoped |
| Stale test mock — `test_email_channel` | 1 | ✅ test-only | unscoped |
| Real-bug-protected — scanner FP + 7 novel-vector gaps (`api/services/scanner.py`) | 9 | 🔒 owner | gated |
| Real-bug-protected — `/metrics` duplicated charset (`api/main.py`) | 1 | 🔒 owner | gated |
| Real-bug-protected — MetricsMiddleware categorization | 1 | 🔒 owner | gated (possibly-stale) |
| Real-bug-protected — `aggregate_score` 4.5≠15.0 (`api/services/scoring.py`) | 1 | 🔒 owner | gated (possibly-stale) |
| **Total** | **20** | | |

CRITICAL-004 (`pytest exits 0`) is **not** fully closed by the agent-buildable subset: it needs
(a) an owner decision on the 8 unscoped test-only fixes and (b) owner-approved production fixes
for the 12 real-bug-protected items.

## AC verification

- [x] Only test files changed — no `api/routers/auth.py` / `api/` production source edits
- [x] Each updated test references the Auth0 migration + production 410 contract
- [x] `pytest -k auth` shows the previously-failing legacy-auth tests now pass (38 passed)
- [x] This file lists each test flipped 200/201/401/409 → 410
