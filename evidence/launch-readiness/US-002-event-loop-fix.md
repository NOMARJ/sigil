# US-002 — Event-Loop Fixture Fix (CRITICAL-004)

**Story:** F-007 / US-002 · **Linear:** NOM-1070 · **Executor:** agent (buildable)
**Date:** 2026-06-08 · **Depends on:** US-001

> **Data Source:** Real test execution (local dev workstation)
> **Sample Size:** Full `api/tests` suite (562 tests)
> **Limitations:** Local run, not CI. The fix targets a local-env contamination that CI likely
> does not hit; it is nonetheless correct test hygiene (unit tests should not require live Azure SQL).

## Root cause (from US-001 §2)

`api/database.py:92 db.connect()` builds a real `aioodbc` pool whenever
`settings.database_configured` is true (i.e. `SIGIL_DATABASE_URL` is set). The developer's
`api/.env` sets it, so the app lifespan (`main.py:80`) created a real pool bound to the
TestClient event loop. Conftest fixtures call `asyncio.run(db.insert(...))` on ephemeral loops
→ `RuntimeError: ... got Future attached to a different loop` and `Cannot acquire connection
after closing pool`. The suite is designed for the in-memory store.

## Fix (test-infra only)

`api/tests/conftest.py` — added a session-scoped, autouse `_force_in_memory_db` fixture that
sets `settings.database_url = None` (→ `database_configured` False → `db.connect()` no-ops) and
`db._pool = None` for the session, then restores it. **No `api/database.py` or any production
source path was modified** (`git diff --stat api/` shows `api/tests/conftest.py | 28 ++` only).

## Before / after (verbatim pytest tails)

Baseline (US-001, `/tmp/pytest-baseline-2026-06-08.txt`):
```
25 failed, 167 passed, 339 skipped, 6 warnings, 31 errors in 13.97s
```

After fix (`/tmp/pytest-us002-2026-06-08.txt`):
```
26 failed, 197 passed, 339 skipped, 6 warnings in 2.15s
```

Event-loop error count after fix:
```
$ grep -cE "attached to a different loop|Cannot acquire connection after closing pool" /tmp/pytest-us002-2026-06-08.txt
0
```

## Regression analysis (AC: "no previously-passing test regresses")

| Metric | Baseline | After | Delta |
|--------|----------|-------|-------|
| passed | 167 | 197 | **+30** |
| failed | 25 | 26 | +1 |
| errors | 31 | **0** | **−31** |
| skipped | 339 | 339 | 0 |
| total | 562 | 562 | 0 |

- **Errors 31 → 0** — strictly decreases (AC met). All event-loop/pool errors eliminated.
- **Passing 167 → 197** — the 167 baseline passes are preserved; +30 are formerly-erroring tests
  that now run in-memory.
- **All 26 current failures were already non-passing in the baseline** (6 legacy-auth → US-003;
  7 scan, formerly errors; 8 novel-vectors; 3 monitoring; 1 scanner FP; 1 scoring — all
  real-bug-protected per US-001). No test that passed in the baseline now fails.
- The +1 net failure is errors→failures reclassification (7 `test_scan` submission tests moved
  from ERROR to FAILED), not a regression — they were never passing.

**Side effect confirming US-001:** `test_threat::test_submit_report` (was `assert 500==201`) and
`test_known_publisher` (was `assert 50.0==85.0`) now **pass** in-memory — confirming they were
SQL-path artifacts. The `/v1/report` 500 remains a real MSSQL `uniqueidentifier` bug on the SQL
path (→ US-004); in-memory mode merely bypasses it. Flagged so US-004 diagnosis accounts for it.

## AC verification

- [x] Fixture/conftest change does not modify `api/database.py` production code (test-infra only)
- [x] `pytest api/tests -q` reports 0 errors attributable to event-loop/Future-loop binding
- [x] Error count strictly decreases (31 → 0); no previously-passing test regresses
- [x] Before/after pytest tails captured above
