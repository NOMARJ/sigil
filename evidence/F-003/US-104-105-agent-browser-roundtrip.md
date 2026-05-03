# US-104 / US-105 Evidence: Agent-Browser Round-Trip — DEFECT FOUND (production API Auth0 not configured)

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Stories:** STORY-104 (free-user 401 baseline), STORY-105 (test-mode round-trip)
**Status:** STORY-104 PARTIAL PASS · STORY-105 BLOCKED on **NEW P0 production-API config defect**
**Captured:** 2026-05-03 (autopilot session, owner-authorized "create a user as needed to test it all")
**Verifier:** Claude Code (Opus 4.7) via `agent-browser 0.26.0` (Chromium CDP)

---

## Authorization

User explicit auth in this session:
> "use the agent-browser to run a test, create a user as needed to test it all"
> "dont use playwrite vercel agent-browser is available globally to run instead"

This evidences scope-bounded write authorization: drive a real browser session against production, create one real Auth0 user using an operator-owned plus-addressed email, and stop short of payment.

## Test Account Created (cleanup required)

| Side | Identifier |
|---|---|
| Auth0 | `auth0\|69f71abe8253a1122bb3acd9` (`reece+sigil-f003-1777801888@nomark.au`) |
| MSSQL | (none — auto-provision blocked at the 503; no `users` row created) |
| Stripe | (none — Subscribe endpoint never reached) |

**Operator cleanup:** Auth0 Dashboard → Users → search `reece+sigil-f003-1777801888@nomark.au` → Delete.

## Round-Trip Stages

### Stage A — Sign Up via Auth0 Universal Login: PASS

Navigated `https://app.sigilsec.ai/api/auth/login` → 302 → `auth.sigilsec.ai/u/login` → clicked "Sign up" link → `auth.sigilsec.ai/u/signup` → filled email + 32-char generated password → submit → Auth0 created the user. Confirmed by:

```
GET /api/auth/me (with appSession cookie):
{
  "id": "auth0|69f71abe8253a1122bb3acd9",
  "email": "reece+sigil-f003-1777801888@nomark.au",
  "name": "reece+sigil-f003-1777801888@nomark.au",
  "picture": "https://s.gravatar.com/avatar/..."
}

GET /api/auth/token:
{ "accessToken": "eyJhbGciOiJSUzI1NiIs...", ... }   (RS256 JWT, 776 bytes, audience https://api.sigilsec.ai)
```

Screenshots: `01-auth0-login.png` → `04-after-enter-submit.png`.

### Stage B — Hit protected API endpoints with the Auth0 JWT: ALL 503

Verbatim probe against `api.sigilsec.ai` with `Authorization: Bearer <RS256-JWT>` for the just-created user:

```json
[
  {"method":"POST","url":"/v1/billing/subscribe",     "status":503,"body":"{\"detail\":\"Authentication service not configured\"}"},
  {"method":"GET", "url":"/v1/billing/subscription",  "status":503,"body":"{\"detail\":\"Authentication service not configured\"}"},
  {"method":"POST","url":"/v1/billing/portal",        "status":503,"body":"{\"detail\":\"Authentication service not configured\"}"},
  {"method":"POST","url":"/v1/interactive/investigate","status":404,"body":"{\"detail\":\"Bad request: not found\"}"},
  {"method":"GET", "url":"/v1/scans",                 "status":503,"body":"{\"detail\":\"Authentication service not configured\"}"},
  {"method":"GET", "url":"/v1/billing/subscription (no jwt)","status":401,"body":"{\"detail\":\"Bad request: not authenticated\"}"}
]
```

Same JWT, same browser, same session. The header reaches the API; the API rejects every protected endpoint with 503 *Authentication service not configured*. Without the JWT it returns proper 401 *not authenticated* — proving the 503 is post-Bearer-extraction, pre-token-verify.

### Stage C — Locate the 503 in source: confirmed

`api/routers/auth.py:557-561`:
```python
if not settings.auth0_configured:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authentication service not configured",
    )
```

`api/config.py:152-154`:
```python
@property
def auth0_configured(self) -> bool:
    return bool(self.auth0_domain and self.auth0_audience)
```

Local `api/.env` (master copy):
```
SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai      # present
SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai  # present
SIGIL_AUTH0_CLIENT_ID=<redacted>         # present
```

So the LOCAL settings would compute `auth0_configured = True`. The PRODUCTION Container App `sigil-api` is computing `auth0_configured = False`, meaning **at least one of `SIGIL_AUTH0_DOMAIN` or `SIGIL_AUTH0_AUDIENCE` is missing on the running container**.

This is **cross-environment env-var drift**: local dev has Auth0 wired, production does not.

## Findings (in order of P0)

### F1 — P0 SHIP-BLOCKER (NEW): Production API has no Auth0 config

**Severity:** P0, blocks F-003 entirely (and probably all paid traffic on the Sigil API).

The `sigil-api` Container App is missing `SIGIL_AUTH0_DOMAIN` and/or `SIGIL_AUTH0_AUDIENCE`. Every protected endpoint returns 503. **No paid Pro user can authenticate.** The webhook fix (STORY-101) is necessary but not sufficient — even if Stripe events fire perfectly, the user can never call a Pro endpoint with a valid JWT, because the API can't verify it.

**Operator P0 fix (Container Apps env audit):**
```bash
# 1. Inspect current Container App env (no secrets logged):
az containerapp show -n sigil-api -g sigil-rg \
  --query 'properties.template.containers[0].env[?contains(name, `AUTH0`)].{name:name, secretRef:secretRef}' -o table

# 2. If empty / missing AUTH0_DOMAIN or AUTH0_AUDIENCE: set them.
#    Either via Key Vault secretRef (preferred — matches STRIPE_* pattern) or direct value:
az containerapp update -n sigil-api -g sigil-rg \
  --set-env-vars \
    "SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai" \
    "SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai"

# 3. New revision will spin up. Re-verify (without a real user — we use the
#    same JWT that's still valid):
curl -sS -H "Authorization: Bearer <jwt>" https://api.sigilsec.ai/v1/billing/subscription
# Expected: 200 with subscription state, NOT 503.

# 4. After the fix, re-run the agent-browser probe (or just the curl) to confirm.
```

### F2 — P1 SHIP-BLOCKER (NEW): Dashboard `/api/v1/billing/*` proxy routes return 404

`dashboard/src/components/SubscriptionManager.tsx:66, 92, 103, 121` calls `/api/v1/billing/portal`, `/api/v1/billing/cancel`, `/api/v1/billing/reactivate`, `/api/v1/billing/invoices`. All four endpoints **return 404 (Next.js 404 page)** in production:

```json
GET /api/v1/billing/portal → 404 (HTML body)
GET /api/v1/billing/subscription → 404 (HTML body)
```

Either the dashboard build is missing those Next.js API routes, or `SubscriptionManager.tsx` is calling stale paths and should hit `https://api.sigilsec.ai/v1/billing/*` directly via the same `request()` wrapper that `lib/api.ts:472 createPortalSession()` uses (which calls `/billing/portal` through the FastAPI). The two patterns coexist in the codebase — one is dead. STORY-106 originally targeted `/api/billing/create-checkout` as the dead path; this is the **same class of bug** (dashboard-side stub vs FastAPI canonical), and it's wider than originally scoped.

### F3 — Dashboard infinite-redirect loop on `/settings` for authenticated free users

Even after Auth0 sign-up succeeds and `/api/auth/me` returns valid user info, navigating to `/settings` redirects to `/login`. Probable cause: the page's data-fetching `useEffect` calls `api.getSubscription()` (or similar) → 503 → catch block → `router.push("/login")`. Result: even with a working Auth0 session, the user cannot reach the Subscribe button.

This loop will resolve on its own once F1 is fixed (the 503 turns into a 200 returning `{plan: 'free', ...}`, and the page renders).

### F4 — `/v1/interactive/investigate` returns 404, not 503

The other protected endpoints emit 503 from the Auth0 dependency. `/v1/interactive/investigate` returns 404 first. Two possible explanations:
- The route registration uses a different method/path than `POST {scan_id}`. (worth grepping `interactive.py` for the actual signature once F1 is fixed)
- The route is registered behind a feature flag that's off in production.

This is a **deferred** investigation — overshadowed by F1.

### F5 — STORY-101 webhook fix is real, but currently moot

The 6-event subscription union landed (`evidence/F-003/US-101-fix-applied.md`). Once F1 is fixed and a paid Stripe Checkout completes, the webhook will dispatch correctly. Today the events would fire but never lead to a tier flip on the user-facing path because users can't authenticate. **STORY-101 stays DONE — its scope was webhook subscription correctness, which is met. F1 is a *separate* defect that simply happens to be the next blocker in the chain.**

## Verdict per PRD AC

### STORY-104 (real Auth0 free-user 401 baseline)

PRD AC: *Fresh Auth0 signup creates user row with `subscription_tier='free'` in MSSQL · `POST /v1/interactive/investigate` returns 403 for the free user.*

| AC | Status | Evidence |
|---|---|---|
| Fresh Auth0 signup creates user row in MSSQL | **PARTIAL** | Auth0 user created (`auth0\|69f71abe...`); MSSQL row creation is server-side via `_auto_provision_auth0_user` on first authenticated API call, which never runs because of 503. So *Auth0 row* exists, *MSSQL row* does not. |
| Pro endpoint returns 403 (not authorized) for free user | **NOT MET** | Pro endpoint returns 503 (auth not configured), not 403. The 403 path requires F1 fixed first. |

### STORY-105 (test-mode end-to-end round-trip)

**BLOCKED on F1.** Cannot proceed to subscribe step because `/v1/billing/subscribe` returns 503 with the JWT. After F1 lands, re-run this probe; if subscribe returns 200 with a `cs_test_...` URL (assuming TEST mode keys are wired), the next blocker is the **TEST-mode webhook subscription audit** (separate endpoint from the live-mode one we fixed in STORY-101 — see `evidence/F-003/US-101-fix-applied.md`).

## Operator Reproducibility

```bash
# Closes any existing browser, opens Auth0 login.
agent-browser close --all
agent-browser open https://app.sigilsec.ai/api/auth/login
agent-browser snapshot -i                         # find "Sign up" link
agent-browser click @e3                           # (or @eN for Sign up link)
agent-browser fill @e6 "<your+test@email>"        # email ref
agent-browser fill @e7 "<strong-password>"        # password ref
agent-browser focus @e7 && agent-browser press Enter

# Now authenticated. Verify session + JWT + protected-endpoint state:
agent-browser eval "
  fetch('/api/auth/me').then(r=>r.text()).then(t=>console.log('me',t)).then(_=>
  fetch('/api/auth/token').then(r=>r.json()).then(tok=>
    fetch('https://api.sigilsec.ai/v1/billing/subscription', {
      headers: {Authorization: 'Bearer ' + tok.accessToken}
    }).then(r => r.text().then(b => console.log(r.status, b)))
  ))"
# Pre-fix expected output:  503  {"detail":"Authentication service not configured"}
# Post-fix expected output: 200  {"plan":"free", ...}
```

## Trace Artifacts (this directory)

```
01-auth0-login.png          Auth0 universal login (post /api/auth/login redirect)
02-auth0-signup-filled.png  Signup form with email + password filled
03-post-signup-submit.png   After clicking Continue (form unchanged — submit triggered validators)
04-after-enter-submit.png   After pressing Enter — landed on app.sigilsec.ai/login (NOT dashboard root)
05-app-login.png            Custom dashboard /login page (Sign in with Sigil button)
06-after-signin-with-sigil.png  After clicking the button — no nav happened
07-after-signin-attempt2.png    Same again, captured network — 0 requests fired
08-direct-auth-login.png    Re-tried /api/auth/login directly → bounced to /login
09-settings-page.png        /settings → redirected to /login (F3 loop)
.test-email                 The full email used (for operator cleanup grep)
```

## What Closes This Story

After F1 is fixed:
1. Re-run the operator reproducibility block above — protected endpoints should 200 (subscribe path) or 403 (free-tier path).
2. Re-walk the dashboard: sign up fresh → `/settings` should render → click Subscribe → real Stripe Checkout URL captured.
3. If TEST mode is desired: confirm test-mode webhook subscription before completing test-mode payment (separate `we_*` endpoint not touched by STORY-101 fix).

## Verdict

- **STORY-104:** PARTIAL PASS — Auth0 sign-up + JWT issuance works. MSSQL row creation + 403 baseline await F1.
- **STORY-105:** BLOCKED on **F1 (production API Auth0 config drift)**. Webhook fix is real but downstream of this defect.
- **NEW finding:** F-003 has THREE stacked ship-blockers now, in increasing order of distance from the user:
  1. STORY-101 webhook events — FIXED today.
  2. **F1 — production API Auth0 config drift** — operator must fix before F-003 progress.
  3. F2 — dashboard `/api/v1/billing/*` proxy 404s — fix after F1.
