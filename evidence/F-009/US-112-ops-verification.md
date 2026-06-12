# Evidence: US-112 — Ops verification (env, retention, live smoke)

**Date:** 2026-06-12 · **Feature:** F-009 · **Status:** PASS (core feature) — live Fable 5 adjudication verified through prod. Metering usage-row write is the one remaining gap; root-caused, code fixed, prod migration prepared and pending owner approval (schema change, CHARTER II.5).

## Deploy summary

- F-009 merged to `sigil` main, images built in ACR. API revision rolled to the SHA-pinned `sigil-api:f3bbb37` (digest `sha256:2d850c…`) → revision `sigil-api--0000105` Running, 100% traffic.
- `sigil-infra` PRs #9/#10/#11 merged → production `terraform apply` green. `ANTHROPIC_API_KEY` (secretRef `anthropic-api-key`, sourced from Key Vault `claude-secret-key`) and `SIGIL_AUTH0_CLIENT_ID` wired on `sigil-api`.
- 3 bot workers force-rolled to the new image, all Healthy.

## Verified (deterministic)

| Check | Result |
|-------|--------|
| `ANTHROPIC_API_KEY` env on sigil-api (secretRef name only) | `ANTHROPIC_API_KEY → secretRef anthropic-api-key` ✅ |
| `anthropic-api-key` Container App secret present | present ✅ (Key Vault `claude-secret-key` via TF data source) |
| New revision healthy + serving | `sigil-api--0000105` Running, 100% traffic ✅ |
| API liveness | `GET https://api.sigilsec.ai/health` → 200 ✅ |
| Adjudicate gate intact (unauthenticated) | `POST /v1/scans/x/findings/0/adjudicate` → 401 ✅ |
| `sigil login` (device flow) | fixed end-to-end; owner completed login, token saved as `reece@nomark.au` ✅ |

## Live smoke — PASS (real claude-fable-5 through prod)

Authenticated as the owner's **Pro** account against `https://api.sigilsec.ai`:

1. Submitted a scan with a dual-use finding → `scan_id 56a21652-ca95-44b6-9a61-31e4ace91dbd`, verdict `CRITICAL_RISK`.
2. `POST /v1/scans/56a21652…/findings/0/adjudicate` → **HTTP 200** with a real model verdict:

```json
{"classification":"suspicious","confidence":0.6,
 "rationale":"The code calls eval(x) on a variable whose origin is completely unknown…",
 "model":"claude-fable-5","adjudicated_at":"2026-06-12T06:28:42.543415"}
```

3. Verdict confirmed persisted on the finding (`findings_json.adjudication`).

This proves: key wired + funded, deep-model (`claude-fable-5`) path live in prod, thinking-block response handling correct, verdict persistence correct.

**Data Source:** Real production API call · **Sample Size:** 1 adjudication (owner account) · **Limitations:** single Pro-tier call; the Free-402 path (below) is unverified pending the credits schema.

## Remaining gap: metering usage-row write

After the 200, best-effort metering logged (does **not** block adjudication — wrapped in try/except at `api/routers/scan.py:980`):

```
[ERROR] api.database: Failed to execute procedure sp_DeductCredits:
  ('42000', "…Could not find stored procedure 'sp_DeductCredits'. (2812)…")
[WARNING] api.routers.scan: LLM usage metering failed for 92AD6765-…:
  'MssqlClient' object has no attribute 'DatabaseError'
```

### Root cause

The credit/metering schema was **never applied to prod**, and the original migration is **incompatible** with the current schema:

1. **`add_credits_system.sql` cannot apply to prod.** It declares `user_credits.user_id NVARCHAR(128)` with an FK to `users(id)`, but prod `users.id` is `UNIQUEIDENTIFIER` (`api/schema.sql:40`). The FK is a type mismatch and fails — so the tables and `sp_DeductCredits` were never created.
2. **Code defect masking DB errors.** `deduct_credits` caught `db.DatabaseError`, but `db` is an `MssqlClient` instance with no such attribute — evaluating the `except` clause itself raised `AttributeError`, hiding the real "missing procedure" error.
3. **`initialize_user_credits` read a nonexistent column.** It did `SELECT subscription_tier FROM users`, but the prod `users` table has no `subscription_tier`; tier lives in the `subscriptions` table via `get_user_plan`. The FREE-user credit-init path would fail.

The owner's call returned 200 because **Pro short-circuits the gate** (`require_llm_access` returns before any credits work, `api/gates.py:166`); metering runs post-hoc and is best-effort.

### Fixes applied (code — committed-ready, tested)

- `api/services/credit_service.py`: `except db.DatabaseError` → `except pyodbc.Error` (defect #2).
- `api/services/credit_service.py`: `initialize_user_credits` now sources tier via `get_user_plan` (defect #3).
- Tests: `api/tests/test_llm_metering.py` — `TestDeductCreditsErrorHandling` (2 regressions: insufficient-credits maps cleanly; driver error is never masked by `AttributeError`). Suite: 36 passed.

### Fix pending owner approval (schema — CHARTER II.5)

- `api/migrations/add_credits_system_prod.sql` (NEW): prod-compatible, idempotent, minimal — `user_credits` + `credit_transactions` with `UNIQUEIDENTIFIER` user_id, plus `sp_DeductCredits` / `sp_AddCredits`. Omits `interactive_sessions` (its FK references `scans(scan_id)`, absent in prod), `credit_packages`, the tier-reset proc, and the analytics view — none are on the adjudication path. **Not applied** — applying to prod MSSQL is an owner-approval boundary.

Once applied: re-run the live smoke to confirm a `credit_transactions` row is written (defect #1), and verify the Free-402 path.

## Pending — needs owner action

1. Approve + apply `add_credits_system_prod.sql` to prod MSSQL (then I re-run the smoke to confirm the usage row + Free-402).
2. **Anthropic org 30-day data retention** — Fable 5 requires it; an Anthropic org-console setting I can't read from here. Owner attests.

No secrets in this file — secretRef / Key-Vault names only.
