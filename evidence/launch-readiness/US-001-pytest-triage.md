# US-001 — API Test-Suite Failure Triage (CRITICAL-004)

**Story:** F-007 / US-001 · **Linear:** NOM-1069 · **Executor:** agent (buildable)
**Date:** 2026-06-08

> **Data Source:** Real test execution (local dev workstation, not CI, not production)
> **Sample Size:** Full `api/tests` suite — 25 failed, 167 passed, 339 skipped, 31 errors (56 failures+errors)
> **Limitations:** Run against a workstation where `api/.env` defines `SIGIL_DATABASE_URL`, so the
> app lifespan connects to the **live Azure MSSQL** pool. This is itself the root cause of the
> event-loop bucket (see Root Cause). Category counts are a snapshot of THIS baseline; several
> SQL-path items are expected to reclassify after the US-002 in-memory fix — flagged inline, not assumed.

---

## 1. Verbatim pytest tail

Command (authoritative single run, teed to `/tmp/pytest-baseline-2026-06-08.txt`):

```
$ python3 -m pytest api/tests -q
...
25 failed, 167 passed, 339 skipped, 6 warnings, 31 errors in 13.97s
```

Environment: Python 3.9.6, pytest 8.3.4, pytest-asyncio 0.25.2.

The PRD report cited "25 failures + 31 errors" = 56. **This baseline matches exactly: 25 + 31 = 56.**

---

## 2. Root cause (shared across the largest bucket)

`api/database.py:92 connect()` is gated by `settings.database_configured` (true when
`SIGIL_DATABASE_URL` is set). Local `api/.env` sets it, so:

1. `main.py:80` lifespan → `await db.connect()` builds a real `aioodbc` pool bound to the
   TestClient's event loop.
2. conftest fixtures (`registered_user`, `pro_user`) call `asyncio.run(db.insert(...))`
   (`conftest.py:241,285`) — each `asyncio.run()` spins a **fresh ephemeral loop**.
3. With `_pool` truthy, `db.insert()` takes the SQL path (`database.py:225
   async with self._pool.acquire()`) instead of the intended in-memory branch
   (`database.py:211 if not self._pool`).
4. Pool bound to loop A, used from loop B → `RuntimeError: ... got Future attached to a
   different loop`. After a TestClient context closes (`db.disconnect()` → `_pool.close()`),
   the next `asyncio.run` finds a closed pool → `RuntimeError: Cannot acquire connection
   after closing pool`.

The conftest is **designed for in-memory** (fixtures write to `db._memory_store`; the autouse
`_reset_memory_stores` clears it between tests). The presence of `SIGIL_DATABASE_URL` in the
local env defeats that design. CI (no DB env) likely does not hit this — confirming it is a
**test-infra/env issue, not a production code defect**. This is exactly what US-002 fixes.

**Reclassification note:** because items 10–12, 22–24 below currently fail/error *on the SQL
path*, some may flip to PASS once US-002 forces in-memory mode. They are categorized here by
their observed baseline symptom; US-002/US-004 will confirm empirically. The `/v1/report` 500
(items 10–11) is a genuine MSSQL `uniqueidentifier`-conversion bug on the SQL path and stays
real-bug-protected (US-004) regardless — in-memory would merely hide it.

---

## 3. Per-item categorization (56 items, one category each)

Categories: `test-only-fixture-eventloop` (→ US-002) · `stale-expectation-legacy-auth-410`
(→ US-003) · `real-bug-protected` (owner-gated; names production module) ·
`test-only-fixture-mock` (buildable, but unscoped by any current story).

### 3a. Event-loop / pool fixture — `test-only-fixture-eventloop` (→ US-002), 34 items

ERRORS (31) — all `RuntimeError: ... attached to a different loop` / `Cannot acquire connection after closing pool`:

- category: test-only-fixture-eventloop | api/tests/test_auth.py::TestTokenValidation::test_me_with_valid_token
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints::test_get_threat_found
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints::test_get_threat_not_found
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints::test_list_signatures
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints::test_signatures_with_since_filter
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints::test_signatures_contain_multiple_phases
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatedEndpoints::test_pro_user_can_list_threats
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatedEndpoints::test_pro_user_can_create_signature
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatedEndpoints::test_pro_user_can_delete_signature
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatedEndpoints::test_free_plan_blocked_from_threats
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatedEndpoints::test_plan_gating_returns_403_not_422
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestAuthenticationOnNonGatedEndpoints::test_auth_me_endpoint_works
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestAuthenticationOnNonGatedEndpoints::test_jwt_token_generation_works
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestAuthenticationOnNonGatedEndpoints::test_login_generates_valid_token
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatingBehavior::test_all_gated_endpoints_work_for_pro_users
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanGatingBehavior::test_all_gated_endpoints_block_free_users
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestImplementedFix::test_unified_auth_supports_custom_jwt
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestImplementedFix::test_unified_auth_enforces_plan_gating
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_clean
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_with_findings
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_returns_scan_id
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_critical_findings_high_score
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_with_threat_intel_hashes
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_validation_error
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_medium_risk_verdict
- category: test-only-fixture-eventloop | api/tests/test_scan.py::TestScanSubmission::test_submit_scan_low_risk_verdict
- category: test-only-fixture-eventloop | api/tests/test_threat.py::TestThreatLookup::test_threat_not_found
- category: test-only-fixture-eventloop | api/tests/test_threat.py::TestThreatLookup::test_threat_found
- category: test-only-fixture-eventloop | api/tests/test_threat.py::TestSignatures::test_get_all_signatures
- category: test-only-fixture-eventloop | api/tests/test_threat.py::TestSignatures::test_get_signatures_since_filter
- category: test-only-fixture-eventloop | api/tests/test_threat.py::TestSignatures::test_signatures_contain_all_phases

FAILURES (3) — `RuntimeError: Cannot acquire connection after closing pool` (same root cause):

- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanSubscriptionManagement::test_default_plan_is_free
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanSubscriptionManagement::test_pro_plan_detection_works
- category: test-only-fixture-eventloop | api/tests/test_auth_dependency_injection.py::TestPlanSubscriptionManagement::test_subscription_data_structure

### 3b. Legacy auth post-Auth0 — `stale-expectation-legacy-auth-410` (→ US-003), 6 items

Endpoints now return `410 Gone` after the Auth0 migration; tests still assert 200/201/401.
Test-only edits, no production source change.

- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestRegistration::test_register_success (assert 410 == 201)
- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestRegistration::test_register_duplicate_email (assert 410 == 201)
- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestRegistration::test_register_empty_name (assert 410 == 201)
- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestLogin::test_login_success (assert 410 == 200)
- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestLogin::test_login_wrong_password (assert 410 == 401)
- category: stale-expectation-legacy-auth-410 | api/tests/test_auth.py::TestLogin::test_login_nonexistent_user (assert 410 == 401)

### 3c. Real bugs in production code — `real-bug-protected` (owner-gated), 15 items

`/v1/report` 500 — MSSQL `uniqueidentifier` conversion (→ US-004), production module `api/routers/threat.py` + `api/database.py`:

- category: real-bug-protected | api/tests/test_threat.py::TestThreatReport::test_submit_report (assert 500 == 201; module api/routers/threat.py, api/database.py)
- category: real-bug-protected | api/tests/test_threat.py::TestThreatReport::test_submit_report_minimal (assert 500 == 201; module api/routers/threat.py, api/database.py)

Publisher reputation — endpoint returns default 50.0 not stored 85.0, production module `api/routers/threat.py` (SQL-path; may reclassify under US-002):

- category: real-bug-protected | api/tests/test_threat.py::TestPublisherReputation::test_known_publisher (assert 50.0 == 85.0; module api/routers/threat.py)

Scanner false-positive + detection gaps — production module `api/services/scanner.py`:

- category: real-bug-protected | api/tests/test_method_detection.py::test_method_names_not_flagged (false positive: obj.eval(expr) flagged code-eval; module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestSupplyChainPolymorphism::test_detect_git_url_hijack (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestSupplyChainPolymorphism::test_detect_phantom_dependency (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestBuildTimeCodeGeneration::test_detect_macro_expansion (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestBuildTimeCodeGeneration::test_detect_ast_manipulation (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestBuildTimeCodeGeneration::test_detect_webpack_plugin (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestBuildTimeCodeGeneration::test_detect_babel_transform (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestCrossLanguageBridgeExploits::test_detect_ffi_boundary (module api/services/scanner.py)
- category: real-bug-protected | api/tests/test_novel_vectors.py::TestNovelVectorCoverage::test_all_patterns_detected (12/19 patterns; module api/services/scanner.py)

Scoring — `aggregate_score` returns 4.5 not 15.0 for a single HIGH finding, production module `api/services/scoring.py` (POSSIBLY stale-expectation — scoring spec unconfirmed):

- category: real-bug-protected | api/tests/test_scoring.py::TestAggregateScore::test_single_finding (assert 4.5 == 15.0; module api/services/scoring.py; possibly-stale)

Monitoring — `/metrics` content-type emits duplicated `charset=utf-8`; MetricsMiddleware lacks 'dashboard' category. Production module `api/monitoring`:

- category: real-bug-protected | api/tests/test_monitoring.py::TestMetrics::test_prometheus_metrics_endpoint (duplicated charset=utf-8; module api/main.py /metrics)
- category: real-bug-protected | api/tests/test_monitoring.py::TestMetrics::test_endpoint_categorization (assert 'other' == 'dashboard'; module api/monitoring MetricsMiddleware; possibly-stale)

### 3d. Test-only mock defect, NOT event-loop — `test-only-fixture-mock` (buildable, unscoped), 1 item

`test_email_channel` patches `api.monitoring.alerting.settings` but `EmailChannel` reads
settings elsewhere, so `smtp_configured` stays false → "SMTP not configured". A wrong
mock target — buildable test-only fix, but **not covered by US-002 (event-loop) or any other
F-007 story**. Flagged for owner: a 13th remediation item exists outside current scope.

- category: test-only-fixture-mock | api/tests/test_monitoring.py::TestAlerts::test_email_channel (mock target mismatch; buildable, unscoped)

---

## 4. Category summary

| Category | Count | Story | Buildable under probation? |
|----------|-------|-------|----------------------------|
| test-only-fixture-eventloop | 34 | US-002 | ✅ yes (test-infra) |
| stale-expectation-legacy-auth-410 | 6 | US-003 | ✅ yes (test-only) |
| real-bug-protected | 15 | US-004 (2 of 15) + uncovered | 🔒 owner-gated (production code) |
| test-only-fixture-mock | 1 | none (uncovered) | ✅ buildable, but unscoped |
| **Total** | **56** | | |

**Buildable subset this run:** US-002 (34 items) + US-003 (6 items) = **40 items** addressable
without touching production code. The remaining 16 (15 real-bug-protected + 1 unscoped mock)
require owner approval to touch production modules or sit outside F-007's current story set.

**Real-bug-protected modules named** (per AC #4): `api/routers/threat.py`, `api/database.py`
(uniqueidentifier conversion + publisher endpoint), `api/services/scanner.py` (false positive +
7 missing novel-vector patterns), `api/services/scoring.py` (aggregate score), `api/main.py` /
`api/monitoring` (metrics content-type + endpoint categorization).

## 5. AC verification

- [x] Evidence file exists with verbatim `python3 -m pytest api/tests -q` tail (§1)
- [x] Every failure/error assigned exactly one category with file::test id (§3, 56 items)
- [x] `grep -c 'category:'` >= 56 (see below)
- [x] Real-bug-protected items name the production module (§3c)
