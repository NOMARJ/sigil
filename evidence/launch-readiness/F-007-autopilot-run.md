# F-007 Launch Readiness Remediation — Autopilot Run (PARTIAL)

**PRD:** `tasks/prd-launch-readiness.json` · **Epic:** EP-003 · **Branch:** `feature/launch-readiness-remediation`
**Date:** 2026-06-08 · **Mode:** `/autopilot --skip-plan` · **Governance:** trust 0 / probation
**Result:** **PARTIAL** — all agent-buildable stories complete; gated stories untouched; verdict stays NOT READY.

> **Data Source:** Real local test/audit/lint runs (workstation, not CI/production)
> **Sample Size:** api/tests suite (562), dashboard npm audit (prod deps), 1 CI workflow
> **Limitations:** Local only. Owner/operator/environment-gated stories not executed under probation.

## Stories executed (agent-buildable, non-destructive)

| Story | Status | Evidence |
|-------|--------|----------|
| US-001 Triage pytest failures | ✅ DONE | `US-001-pytest-triage.md` — 56 items categorized (`grep -c category:`=57) |
| US-002 Event-loop fixture fix | ✅ DONE | `US-002-event-loop-fix.md` — errors 31→0, no regression, test-infra only |
| US-003 Legacy auth → 410 | ✅ DONE | `US-003-legacy-auth-410.md` — 6 tests flipped, `-k auth` 38 passed |
| US-006 Next.js upgrade assessment | ✅ DONE | `US-006-nextjs-upgrade-assessment.md` — real audit, blast radius, rollback |
| US-008 Rust CI workflow draft | ✅ DONE | `US-008-rust-ci.md` — actionlint CLEAN, pinned 1.82.0 |

## Stories NOT executed (gated under probation — require go-ahead)

| Story | Gate | Why blocked |
|-------|------|-------------|
| US-004 `/v1/report` 500 diagnosis | owner | Touches `api/database.py`/`api/routers/threat.py` (DB behavior). Real MSSQL `uniqueidentifier` bug confirmed on SQL path (US-002 showed it passes in-memory). |
| US-005 Signup CTA repair | owner | Auth-flow change (CHARTER II.5). |
| US-007 Apply Next.js upgrade | operator | Dependency bump + build/deploy; follows US-006 plan. |
| US-009 Verify `cargo test` | environment | No local Rust toolchain; runs via US-008 CI on merge or operator-approved local install. |
| US-010 Pricing reconciliation | operator | Cross-ref F-003 STORY-107/111/112 (fresh deploy). |
| US-011 Installer URL | operator | Cross-ref F-004 + F-003 STORY-108/112 (CDN fresh deploy). |
| US-012 Re-run report + flip verdict | agent (blocked) | Hard deps US-004/005/007/009/010/011 all gated → verdict cannot honestly become READY. |

## Integration verification (final, post-US-003)

```
$ python3 -m pytest api/tests -q
20 failed, 203 passed, 339 skipped, 6 warnings in 2.27s   (0 errors)
```

Baseline → now: passed 167→203, errors 31→0, failed 25→20. **Entire branch touches only
tests + evidence + progress.md + the new CI workflow — no production source** (`git diff
--name-only cf4391d..HEAD` verified). Probation gates fully respected.

## CRITICAL-004 residual (20 failures) — why pytest does not yet exit 0

Buildable-but-UNSCOPED (no F-007 story covers; owner decision needed to add scope):
- 7 × `test_scan.py::TestScanSubmission::*` — stale fixture (`clean_scan_request` → `422` schema drift)
- 1 × `test_monitoring.py::TestAlerts::test_email_channel` — wrong mock patch target

Real-bug-protected (owner-gated production fixes):
- 9 × scanner (`api/services/scanner.py`) — 1 false positive (`obj.eval`) + 7 missing novel-vector patterns + coverage gate
- 1 × `/metrics` duplicated `charset=utf-8` (`api/main.py`)
- 1 × MetricsMiddleware `_categorize_endpoint('/dashboard/tools')` (possibly-stale)
- 1 × `aggregate_score` 4.5≠15.0 (`api/services/scoring.py`, possibly-stale)

## Feature ACs (SOLUTION.md F-007)

| AC | State |
|----|-------|
| CRITICAL-001 signup CTA | ⛔ owner-gated (US-005 not run) |
| CRITICAL-002 pricing page | ⛔ operator-gated (cross-ref F-003) |
| CRITICAL-003 installer URL | ⛔ operator-gated (cross-ref F-004) |
| CRITICAL-004 pytest exits 0 | 🟡 partial — errors 31→0, 6 auth fixed; 20 residual (8 unscoped-test + 12 owner-gated) |
| HIGH-001 npm audit clean | 🟡 assessed (US-006), apply gated (US-007) |
| HIGH-002 cargo test verifiable | 🟡 CI mechanism drafted (US-008), first run gated (US-009) |
| Report verdict READY | ⛔ stays NOT READY — gated blockers remain |

## Next actions for owner/operator

1. Decide on the 8 unscoped test-only fixes (would further close CRITICAL-004 cheaply).
2. Approve US-004 (DB) + US-005 (auth) production changes.
3. Operator: run US-007 (Next.js apply per US-006 plan), US-010/US-011 (fresh deploys).
4. Merge this branch → first `rust-cli.yml` run discharges US-009; or approve local `cargo test`.
5. Re-run US-012 once the above clear.
