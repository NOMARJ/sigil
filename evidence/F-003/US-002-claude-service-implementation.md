# US-002 — Implement claude_service per ADR-0003 Branch A + register interactive.router

**Feature:** F-003 Pro Billing + Tier Gating Verification (closeout PRD)
**Story:** US-002
**Branch:** `feature/f-003-closeout`
**Status:** DONE locally (5 of 6 ACs verified); AC #6 (production curl) requires deploy.
**Captured:** 2026-05-04 (autopilot, TDD)

---

## What Was Built

Per ADR-0003 (`status: accepted`, owner-approved 2026-05-04), Branch A implemented:

1. `api/services/llm_service.py` — `_call_llm_api` renamed to `call_llm_api`; added optional `model: str | None = None` parameter that flows through to the local payload dict via `effective_model = model or llm_config.model`. Internal caller `_perform_analysis` updated. **No global mutation of `llm_config.model`** — that pattern was rejected in the ADR because it races under concurrent coroutines.
2. `api/services/claude_service.py` (new, 39 lines) — `ClaudeService` class with `analyze_with_claude(prompt, model=None, max_tokens=2000)` that delegates to `llm_service.call_llm_api(prompt, max_tokens, model=model)`. Module-level `claude_service = ClaudeService()` singleton.
3. `api/main.py` — added `interactive` to the router import block; added `app.include_router(interactive.router)` after `billing.router`.
4. `api/tests/test_interactive_router_registered.py` — removed both `@pytest.mark.skip` decorators (the F1.7 BLOCKED reason no longer applies).
5. `api/tests/test_claude_service.py` (new, 195 lines) — 4 tests pinning the wrapper contract:
   - `test_call_llm_api_uses_default_model_when_none` — payload uses `llm_config.model` when `model=None`.
   - `test_call_llm_api_uses_override_model_when_provided` — payload uses override; `llm_config.model` equals its pre-call value after the call returns. Note: this single-coroutine post-call assertion does NOT exclude a save/set/restore pattern by itself.
   - `test_claude_service_threads_model_through` — wrapper forwards model to `call_llm_api`.
   - `test_concurrent_claude_calls_do_not_share_model_state` — pins the wrapper's parameter-threading contract end-to-end: two concurrent calls with different model overrides each see their own `model` parameter arriving at the inner call after a deliberate `await asyncio.sleep(0.01)` interleave. Does NOT directly catch a save/set/await/restore mutation pattern (the fake captures `model` from its parameter, not from `llm_config.model`); the no-global-mutation property is enforced by construction in `call_llm_api` (local read, never a write) and by ADR-0003 review.
6. `api/tests/test_pro_performance.py` and `api/tests/test_phase9_llm.py` — updated `_call_llm_api` references to the new public name (these files are in the `extended_files` skip-set in `conftest.py:60-79`, so they don't run by default; updated for codebase coherence).

## Acceptance Criteria — Verification

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Branch chosen in ADR-0003 is implemented | ✅ | Branch A (thin shim) — `api/services/claude_service.py` + `LLMService.call_llm_api` rename |
| 2 | `python3 -c 'from api.routers import interactive; assert interactive.router is not None'` exits 0 | ✅ | See "Reproduction" below — output: `OK: interactive.router prefix = /v1/interactive` |
| 3 | Removed both `@pytest.mark.skip` decorators in `test_interactive_router_registered.py` | ✅ | `grep -c '@pytest.mark.skip' api/tests/test_interactive_router_registered.py` returns 0 |
| 4 | `pytest test_interactive_router_registered.py` shows 2 PASSED, 0 SKIPPED | ✅ | See "Reproduction" — both `test_interactive_router_is_importable` and `test_interactive_router_is_mounted_in_main` PASS |
| 5 | `api/main.py` imports `interactive.router` and registers it via `app.include_router(...)` | ✅ | `api/main.py` line 295 (import block), line 343 (`app.include_router(interactive.router)`) |
| 6 | Production curl `POST .../v1/interactive/investigate` returns 401 or 422, NOT 404 | ⏳ | Requires deploy — local TestClient already returns non-404 (asserted in test #4 above); production verification is post-merge step |

## Reproduction

```bash
cd /Users/reecefrazier/CascadeProjects/sigil

# AC #2: import succeeds
python3 -c "from api.routers import interactive; assert interactive.router is not None; print('OK: interactive.router prefix =', interactive.router.prefix)"
# → OK: interactive.router prefix = /v1/interactive

# AC #3: zero skip decorators remain
grep -c "@pytest.mark.skip" api/tests/test_interactive_router_registered.py
# → 0

# AC #4: 2 passed, 0 skipped
python3 -m pytest api/tests/test_interactive_router_registered.py -v
# → test_interactive_router_is_importable PASSED
# → test_interactive_router_is_mounted_in_main PASSED
# → 2 passed in ~5s

# Full claude_service + interactive suite (6 tests)
python3 -m pytest api/tests/test_claude_service.py api/tests/test_interactive_router_registered.py -v
# → 6 passed in 14.67s
```

## Test Results — Full Output (Green Phase)

```
api/tests/test_claude_service.py::test_call_llm_api_uses_default_model_when_none PASSED
api/tests/test_claude_service.py::test_call_llm_api_uses_override_model_when_provided PASSED
api/tests/test_claude_service.py::test_claude_service_threads_model_through PASSED
api/tests/test_claude_service.py::test_concurrent_claude_calls_do_not_share_model_state PASSED
api/tests/test_interactive_router_registered.py::test_interactive_router_is_importable PASSED
api/tests/test_interactive_router_registered.py::test_interactive_router_is_mounted_in_main PASSED
======================== 6 passed, 3 warnings in 14.67s ========================
```

## Regression Check

Ran `pytest api/tests/ --ignore=api/tests/test_pro_performance.py --ignore=api/tests/test_phase9_llm.py --ignore=api/tests/test_auth.py`:

- **Pre-existing failures observed:** `test_scan.py`, `test_threat.py`, `test_auth_dependency_injection.py` — `RuntimeError: ... attached to a different loop` from `aioodbc/connection.py:123` in test fixture setup. **Confirmed pre-existing** by stashing my changes and running the same test (`test_submit_scan_clean`) — same error on the unmodified tree. Not introduced by this commit.
- **Pre-existing failure observed:** `test_auth.py::TestRegistration::test_register_success` — returns 410 Gone (expected 201). Caused by Auth0 migration commit `6d3b173` (ADR-0002 removed the legacy `/v1/auth/register` endpoint). Not introduced by this commit.
- **Tests adjacent to my changes — all PASS:** `test_claude_service.py`, `test_interactive_router_registered.py`, `test_llm_prompts.py`, `test_billing_trial_period.py`, `test_database_reserved_word_columns.py`, `test_auth_userinfo_fallback.py` — 35/35 PASSED.

## Files Changed

```
api/main.py                                       (router import + registration line)
api/services/llm_service.py                       (rename + model parameter)
api/services/claude_service.py                    (new — 39 lines)
api/tests/test_claude_service.py                  (new — 195 lines, 4 tests)
api/tests/test_interactive_router_registered.py   (skip decorators removed)
api/tests/test_pro_performance.py                 (rename pass-through)
api/tests/test_phase9_llm.py                      (rename pass-through)
```

## Next Steps

After this branch lands and deploys to production:

1. Smoke-test AC #6: `curl -sS -o /dev/null -w '%{http_code}' -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'` should return `401` (auth required) or `422` (validation), NEVER `404`.
2. Verify the existing `evidence/F-003/F1.7-BLOCKED.md` symptoms are resolved by re-running the reproducibility commands at the bottom of that file.
3. Mark F1.7 closed in the F-003 progress entry.

## Cross-References

- `docs/adr/ADR-0003-claude-service-strategy.md` — accepted, Branch A.
- `evidence/F-003/F1.7-BLOCKED.md` — original triage; this story is the resolution.
- `evidence/F-003/STORY-104-DONE-closes-F1.5-F1.6.md` — predecessor work that exposed F1.7.
- `tasks/prd-remaining-f-003-work.json` US-002 — this story's PRD entry.
