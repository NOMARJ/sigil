# Evidence: US-112 — Ops verification (env, retention, live smoke)

**Date:** 2026-06-12 · **Feature:** F-009 · **Status:** ✅ DONE — live Fable 5 adjudication verified through prod (async, no 504); metering usage row written and verified in `credit_transactions`; prod credits schema applied; retention attested.

## Final verification (rev `sigil-api--0000108`, image `2eff98f`)

Authenticated Pro smoke against `https://api.sigilsec.ai`:

```
POST .../findings/0/adjudicate → 202 (pending) → poll → 200 complete
  verdict: "suspicious"  model: claude-fable-5                       (async; no edge 504)

credit_transactions (most recent):
  transaction_type=scan  credits_amount=-3  model_used=claude-fable-5  tokens_used=318  2026-06-12 09:22:00
user_credits:
  user_id=92ad6765-…  credits_balance=4997  credits_used_month=3
```

`initialize_user_credits` created the Pro row (5000 allowance); `sp_DeductCredits` charged 3 credits (318 tokens × Fable rate); the usage row persisted with `model_used = claude-fable-5`. **Usage row visible — metering closed.**

**Data Source:** Real production · **Sample Size:** 1 adjudication + 1 metered transaction (owner Pro account) · **Limitations:** Free-402 path is unit-tested only (no live Free account exercised).

It took five defects to get a usage row written — see the diagnosis trail below. The original `200`-sync status note at the top of this file is superseded by the async contract (`202` + poll).

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

### Schema fix (defect #1) — APPLIED to prod (owner-approved)

- `api/migrations/add_credits_system_prod.sql` (NEW): prod-compatible, idempotent, minimal — `user_credits` + `credit_transactions` with `UNIQUEIDENTIFIER` user_id, plus `sp_DeductCredits` / `sp_AddCredits`. Omits `interactive_sessions` (its FK references `scans(scan_id)`, absent in prod), `credit_packages`, the tier-reset proc, and the analytics view — none are on the adjudication path.
- Applied 2026-06-12 via `sqlcmd` from the owner's admin IP. Verify query returned all four objects **present**: `user_credits`, `credit_transactions`, `sp_DeductCredits`, `sp_AddCredits`.
- Code fix deployed: `sigil-api--0000106` (image `84b7ce1`).

### Follow-on: async adjudication (fixes a 504 surfaced by the smoke)

Post-deploy smoke on rev 106 showed the **client** got `504 "stream timeout"** while the **server completed and persisted a real verdict** (`{"classification":"suspicious","model":"claude-fable-5","adjudicated_at":"2026-06-12T08:09:31"}`). Root cause: `timeout_seconds=30` is too low for Fable-5 (thinking always on) → tenacity retry churn → total >240s → edge proxy cut. Owner chose the async pattern.

- `POST .../adjudicate` now schedules a background job → `202` + pending marker (or `200` if already complete; `?force` re-runs). `GET .../adjudicate` polls (`200` complete/error, `202` pending, `404` none). State persists on the finding; stale pending self-heals. `LLM_TIMEOUT` default 30→120s. CLI `sigil explain` polls. Commit `1121136`; full API suite 315 passed.

## Defect trail (five, to write one usage row)

1. `deduct_credits` caught `db.DatabaseError` — `MssqlClient` has no such attr → `AttributeError` masked the real error. → `except pyodbc.Error`.
2. `initialize_user_credits` read `SELECT subscription_tier FROM users` — no such column; tier is in `subscriptions` via `get_user_plan`. → fixed.
3. `add_credits_system.sql` couldn't apply: `user_credits.user_id NVARCHAR(128)` FK → `users(id) UNIQUEIDENTIFIER` type mismatch. → `add_credits_system_prod.sql` (applied).
4. Edge proxy 504 on the inline call: `timeout_seconds=30` too low for Fable-5 → retry churn >240s. → async adjudication (`202`+poll), `LLM_TIMEOUT` 120s.
5. **Root cause** — the whole `credit_service` data layer used asyncpg-style `fetch_one`/`execute`/`fetch_all` that `MssqlClient` doesn't implement; calls `AttributeError`'d and were swallowed, so no row was ever created and `deduct_credits` recursed to "maximum recursion depth exceeded". → ported to `select_one`/`insert`/`execute_raw_sql` + recursion guard.

## Resolved

1. **`credit_transactions` row** — verified present (see Final verification). ✅
2. **Anthropic org 30-day data retention** — Owner attested: on (2026-06-12). ✅

## Known out-of-scope follow-up

- `credit_service.purchase_credits` still uses `db.fetch_one` against `credit_packages` (not provisioned in prod) — the Stripe credit-pack top-up flow, separate from F-009 metering. Will `AttributeError`/fail if invoked; tracked separately.
- Free-tier `402` path verified by unit test only (`test_free_exhausted_402`); no live Free account exercised.

No secrets in this file — secretRef / Key-Vault names only.
