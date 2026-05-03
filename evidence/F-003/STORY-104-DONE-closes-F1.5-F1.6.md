# STORY-104 DONE — Real Auth0 free-tier 403 baseline observed

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-104 (PARTIAL → DONE)
**Status:** PASS — `GET /v1/policies` with real Auth0 JWT for free-tier user returns HTTP 403 with structured GateError response
**Captured:** 2026-05-03 (autopilot session via `/bugfix` cascade F1 → F1.5 → F1.6)
**Verifier:** Claude Code (Opus 4.7) via `agent-browser 0.26.0` + `curl`

---

## What Closed STORY-104

The agent-browser round-trip surfaced a stack of three sequential P0 ship-blockers between the freshly-issued Auth0 JWT and the canonical 403 GateError response. Fixing them in order opened the path:

| # | Defect | Fix | Commit / Revision |
|---|---|---|---|
| F1 | Production API missing `SIGIL_AUTH0_DOMAIN` / `_AUDIENCE` env vars → 503 "Authentication service not configured" for every Bearer header | `az containerapp update --set-env-vars` | revision `sigil-api--0000071` |
| F1.5 | Auth0 access token has no `email` claim by default → 401 "Auth0 token missing email claim" | `/userinfo` fallback in `verify_auth0_token` | commit `69b9f13` → revision `0000072` |
| F1.6 | T-SQL reserved-word column `subscriptions.plan` not bracket-quoted in SQL gen → 500 `pyodbc.ProgrammingError "Incorrect syntax near the keyword 'plan'"` on first authenticated read | `_q()` helper bracketing every column-name interpolation | commit `43f2165` → revision `0000073` |

Each defect was hidden behind the previous one. Without F1, you couldn't see F1.5. Without F1.5, you couldn't see F1.6. Each fix exposed the next layer.

## STORY-104 PRD AC Verification

PRD AC: *"`POST /v1/interactive/investigate` (or any `require_plan(PlanTier.PRO)` route) returns 403 for the free user."*

Test user `auth0|69f7205bc86474842dbb1ed3` (`reece+sigil-f003-f1verify-1777803354@nomark.au`) signed up via `agent-browser`, JWT captured via `/api/auth/token`.

```bash
$ curl -sS -H "Authorization: Bearer $JWT" \
    -w '\nHTTP %{http_code}\n' \
    https://api.sigilsec.ai/v1/billing/subscription
{"plan":"free","status":"active","billing_interval":"monthly",
 "current_period_start":"2026-05-03T10:42:29.131560",
 "current_period_end":"2026-06-02T10:42:29.131560",
 "cancel_at_period_end":false,
 "stripe_subscription_id":null,"checkout_url":null}
HTTP 200
```

User has `plan: "free"`, `status: "active"` — auto-provisioned in MSSQL by `_auto_provision_auth0_user` after F1.5 made the email claim available.

```bash
$ curl -sS -H "Authorization: Bearer $JWT" \
    -w '\nHTTP %{http_code}\n' \
    https://api.sigilsec.ai/v1/policies
{"detail":"This feature requires the pro plan or higher.",
 "required_plan":"pro",
 "current_plan":"free",
 "upgrade_url":"https://app.sigilsec.ai/upgrade"}
HTTP 403
```

```bash
$ curl -sS -H "Authorization: Bearer $JWT" \
    -w '\nHTTP %{http_code}\n' \
    https://api.sigilsec.ai/v1/threats
{"detail":"This feature requires the pro plan or higher.",
 "required_plan":"pro",
 "current_plan":"free",
 "upgrade_url":"https://app.sigilsec.ai/upgrade"}
HTTP 403
```

**STORY-104 PRD AC: SATISFIED.**

The structured GateError body (`required_plan`, `current_plan`, `upgrade_url`) is exactly what the dashboard's `PlanGate` component is built to consume — confirms the gating contract end-to-end.

## Sanity — Non-Gated Endpoints

```bash
$ curl -sS https://api.sigilsec.ai/health  # 200, db+redis connected
$ curl -sS -H "Authorization: Bearer $JWT" https://api.sigilsec.ai/v1/scans  # 200, scan list
```

No regression on either unauthenticated `/health` or non-Pro authenticated `/v1/scans`.

## NEW Finding F1.7 (does NOT block STORY-104, but blocks Pro feature delivery)

`POST /v1/interactive/investigate` returns **404 "Bad request: not found"** even with a valid JWT and proper request body. Root cause: `interactive.router` is **not imported or registered in `api/main.py`**:

```python
# api/main.py:295-320 — interactive is NOT in this list
from api.routers import (
    alerts, analytics, attestation, auth, badge, billing,
    device_flow, email, feed, forge, github_app, metrics,
    permissions, policies, publisher, realtime, registry,
    report, rescan, scan, system, team, threat, verify,
)
```

`api/routers/interactive.py:63` defines `router = APIRouter(prefix="/v1/interactive", tags=["interactive-analysis"])` with **33 Pro-gated routes** (the AI investigation, chat, attack-chain analysis, compliance-mapping endpoints — the headline Pro feature of the $29 plan).

**Effect:** Every advertised Pro feature on the pricing page (AI Investigation Assistant, False Positive Verification, Interactive Security Chat, Attack chain tracing, Compliance mapping) returns 404 in production. Users who pay $29/month will get 404s when they try to use the features they paid for.

**Severity:** P0 — directly blocks F-003's downstream "user gets value from Pro tier" goal, but **does not block STORY-104** (the AC says "any `require_plan(PlanTier.PRO)` route", and `/v1/policies` is also Pro-gated and works).

**Fix:** add `interactive` to the `from api.routers import (...)` block in `api/main.py:295-320` and add `app.include_router(interactive.router)` to the registration block at `api/main.py:329-359`. This may have been a regression (the route file is rich and tested implies it was previously wired).

Recorded for follow-up. Does not need to ship before STORY-104 closes.

## Test User Cleanup Required (operator)

Three Auth0 test users created during this autopilot work, none have an MSSQL `users` row except the third (which got auto-provisioned post F1.5). Operator should delete via Auth0 Dashboard → Users:

| Email | Auth0 ID | MSSQL row? |
|---|---|---|
| `reece+sigil-f003-1777801888@nomark.au` | `auth0\|69f71abe8253a1122bb3acd9` | No |
| `reece+sigil-f003-f1verify-1777803354@nomark.au` | `auth0\|69f7205bc86474842dbb1ed3` | **Yes** (provisioned at 10:42:29 by F1.6 code path; subscription record `plan=free`) |
| `reece+sigil-f003-f15verify-1777804501@nomark.au` | (separate user from later browser run) | check & delete |

For the auto-provisioned MSSQL row, also clean up:
```sql
DELETE FROM subscriptions WHERE user_id IN
  (SELECT id FROM users WHERE email LIKE 'reece+sigil-f003-%');
DELETE FROM users WHERE email LIKE 'reece+sigil-f003-%';
```

(Use `?` parameterised SELECT first to confirm the rows before DELETE.)

## Reproducibility (operator, after Auth0 sign-in)

```bash
# Capture a fresh free-tier JWT via the dashboard:
agent-browser open https://app.sigilsec.ai/api/auth/login
# (sign in / sign up)
JWT=$(agent-browser eval "fetch('/api/auth/token').then(r=>r.json()).then(t=>t.accessToken)")

# Free user reads subscription:
curl -sS -H "Authorization: Bearer $JWT" \
  https://api.sigilsec.ai/v1/billing/subscription
# Expected: 200, {"plan":"free","status":"active",...}

# Free user hits a Pro-gated endpoint:
curl -sS -H "Authorization: Bearer $JWT" \
  https://api.sigilsec.ai/v1/policies
# Expected: 403, {"required_plan":"pro","current_plan":"free",...}
```

## Verdict

**STORY-104: DONE.**
- [x] Fresh Auth0 sign-up creates user row in MSSQL with `subscription_tier='free'` (verified via /v1/billing/subscription return = `plan: free`).
- [x] `require_plan(PlanTier.PRO)` route returns 403 for the free user (verified on `/v1/policies` and `/v1/threats`).
- [x] Real Auth0 free-tier JWT used (not minted) — sourced from `/api/auth/token` in agent-browser session.
- [x] Structured GateError body confirms the gating contract.

This unblocks STORY-105 from the *authentication-and-gating* side. STORY-105 still requires:
- Test-mode webhook subscription audit + fix (separate `we_*` from STORY-101's live-mode fix).
- Browser-driven Stripe Checkout with `4242 4242 4242 4242` test card.
- 12-section evidence pack per STORY-105's TDD anchor.

And separately, F1.7 (interactive router not registered) needs to land before any paid Pro user can actually use the AI investigation features they're paying for.
