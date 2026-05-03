# F1 Fix Applied: Production API Auth0 Env Vars Restored

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Defect:** F1 from `evidence/F-003/US-104-105-agent-browser-roundtrip.md` — production API returns 503 "Authentication service not configured" for every protected endpoint
**Status:** PASS — env-var drift resolved, 503 path no longer reached
**Captured:** 2026-05-03 (autopilot session via `/bugfix`, owner-authorized)
**Verifier:** Claude Code (Opus 4.7) — Azure CLI on NOMARK subscription

---

## Authorization

User explicit auth in this session:
> "approved for all permissions required to fix f1"

This evidences scope for: read sigil-api Container App env, apply `az containerapp update --set-env-vars` for the missing AUTH0 keys, re-verify via curl + agent-browser.

## Phase 1 — Investigation (verbatim pre-fix)

```bash
$ az account set --subscription "ac7254fa-1f0b-433e-976c-b0430909c5ac"   # NOMARK
$ az containerapp show -n sigil-api -g sigil-rg \
    --query "properties.template.containers[0].env[?contains(name, 'AUTH0')].name" -o tsv
$ az containerapp show -n sigil-api -g sigil-rg \
    --query "properties.template.containers[0].env[].name" -o tsv | grep -i auth0
# (empty)
```

**Zero `SIGIL_AUTH0_*` env vars on the production Container App.** Confirms the F1 hypothesis: `auth0_configured = bool(self.auth0_domain and self.auth0_audience)` returns False, raising the 503 at `api/routers/auth.py:557`.

Local `api/.env` has both keys set (lengths only, no values logged):
```
SIGIL_AUTH0_DOMAIN=<len:16>     # auth.sigilsec.ai
SIGIL_AUTH0_AUDIENCE=<len:23>   # https://api.sigilsec.ai
SIGIL_AUTH0_CLIENT_ID=<len:32>  # only used for client-side flows; not needed by verify path
```

The verify path at `api/routers/auth.py:356` uses `settings.auth0_domain` for JWKS URL fetch and issuer check; line 408 uses `settings.auth0_audience` for audience claim. `auth0_client_id` is NOT used in server-side JWT verification.

Both required values are non-secrets — public identifiers visible in any Auth0-issued JWT — so direct env-var values are appropriate (no Key Vault secretRef needed; matches the pattern of other non-secret config like `SIGIL_BASE_URL`).

## Phase 2 — Analysis

Sibling `STRIPE_*` env vars are present (`SIGIL_STRIPE_PRICE_PRO`, `SIGIL_STRIPE_PRICE_TEAM`, `SIGIL_STRIPE_SECRET_KEY`, `SIGIL_STRIPE_WEBHOOK_SECRET`). The drift is specifically in the `AUTH0_*` namespace — most likely an early-deployment oversight where the Stripe block was wired but Auth0 was overlooked.

Sibling missing items (out of F1 scope but worth noting for downstream stories):
- `SIGIL_STRIPE_PRICE_PRO_ANNUAL` — also missing on prod (matches STORY-100 finding)
- `SIGIL_STRIPE_PRICE_TEAM_ANNUAL` — also missing on prod (matches STORY-100 finding)

## Phase 3 — Hypothesis

If `SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai` and `SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai` are set on the Container App, `auth0_configured` flips to True, the 503 branch at line 557 is no longer reached, and protected endpoints will proceed to actual JWT verification.

Failing test: `curl -H "Authorization: Bearer fake.fake.fake" https://api.sigilsec.ai/v1/billing/subscription` returns **503** "Authentication service not configured".
Pass test: same curl returns **401** with a verify-stage error (e.g. "Invalid or expired Auth0 token") because the path now reaches `verify_auth0_token` and the fake token cannot be decoded.

## Phase 4 — Implementation

### Apply env-var update

```bash
$ az containerapp update -n sigil-api -g sigil-rg \
    --set-env-vars \
      "SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai" \
      "SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai" \
    --query "{name:name, lastRevision:properties.latestRevisionName, ...}"
```

`--set-env-vars` adds/updates only the named vars and does NOT clobber existing env entries (verified by reading the post-update env list — `SIGIL_STRIPE_*`, `SIGIL_DATABASE_URL`, etc. all present unchanged).

### New revision

```
Name                Active    RunningState    HealthState    Replicas    Traffic
------------------  --------  --------------  -------------  ----------  ---------
sigil-api--0000071  True      Running         Healthy        1           100
```

Polled until `runningState == Running` (took ~12s, 3 polls).

### Post-fix verification — fake Bearer token

The conclusive 503-path-no-longer-reached test:

```bash
$ curl -sS -H "Authorization: Bearer fake.fake.fake" https://api.sigilsec.ai/v1/billing/subscription
{"detail":"Invalid or expired Auth0 token"}
HTTP 401
```

```bash
$ curl -sS -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs...kid...lid" https://api.sigilsec.ai/v1/billing/subscription
{"detail":"Invalid or expired Auth0 token"}
HTTP 401
```

```bash
$ curl -sS https://api.sigilsec.ai/v1/billing/subscription   # no Bearer (control)
{"detail":"Bad request: not authenticated"}
HTTP 401
```

**Pre-fix:** any Bearer header → 503 "Authentication service not configured".
**Post-fix:** valid-shape Bearer → 401 "Invalid or expired Auth0 token" (verify_auth0_token reached, JWKS fetched, jose decoder rejected the fake signature). No-Bearer control still returns 401 "not authenticated".

The error-message change is the conclusive proof — the 503 line at `auth.py:557` is no longer hit.

### Sanity check — unprotected endpoints

```bash
$ curl -sS https://api.sigilsec.ai/health
{"status":"ok","version":"0.1.0","database_connected":true,"redis_connected":true}
HTTP 200

$ curl -sS https://api.sigilsec.ai/v1/billing/plans | jq '.[].tier'
"free" "pro" "team" "enterprise"
HTTP 200

$ curl -sS https://api.sigilsec.ai/v1/billing/credit-packages | jq '.[].name' | head
"Starter Pack" ...
HTTP 200
```

No regression on unprotected endpoints. Database + Redis still connected after revision swap.

### Full real-JWT round-trip — partial

Re-opened agent-browser, signed up a fresh user
`auth0|69f7205bc86474842dbb1ed3` (`reece+sigil-f003-f1verify-1777803354@nomark.au`), captured a real 776-byte RS256 JWT via `/api/auth/token`, called `/v1/billing/subscription` with that JWT:

```json
{"detail":"Auth0 token missing email claim"}
HTTP 401
```

This is a NEW finding — see "F1.5" below. The 503 is gone (F1 fix verified) but a downstream 401 is now visible.

## What This Fix DOES NOT Resolve — F1.5 (NEW finding)

After F1 was fixed, the round-trip surfaces a separate defect: **Auth0 access tokens issued by `auth.sigilsec.ai` do not include the `email` claim**.

`api/routers/auth.py:432-434` reads:
```python
namespace = "https://api.sigilsec.ai"
return {
    "sub": payload["sub"],
    "email": payload.get(f"{namespace}/email", payload.get("email", "")),
    "name": payload.get(f"{namespace}/name", payload.get("name", "")),
}
```

The API expects either a namespaced custom claim `https://api.sigilsec.ai/email` OR a plain `email` claim. Auth0 access tokens (as opposed to ID tokens) **do not include profile claims like email by default** — even when the `openid profile email` scopes are requested. To populate the namespaced claim, the Auth0 tenant must have a **Post-Login Action** configured:

```js
// Auth0 Post-Login Action (operator: Auth0 Dashboard → Actions → Library → Build Custom)
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://api.sigilsec.ai';
  if (event.authorization) {
    api.accessToken.setCustomClaim(`${namespace}/email`, event.user.email);
    api.accessToken.setCustomClaim(`${namespace}/name`, event.user.name);
  }
};
```

Then attach the Action to the **Login flow**.

Alternative fix (code change in `api/routers/auth.py`): if email is empty after checking namespaced + plain claim, fall back to fetching `https://{auth0_domain}/userinfo` with the access token. This works regardless of Auth0 Action configuration but adds one HTTP round-trip on first-auth.

**F1.5 is operator-decidable.** Recommend the Auth0 Action — it's the documented Auth0 pattern, single-tenant config, no per-request overhead. The backend fallback is the second-best option if Auth0 Mgmt access is unavailable.

## Verdict

**F1: PASS.** The env-var drift is resolved.
- [x] Hypothesis confirmed: zero `SIGIL_AUTH0_*` on production Container App.
- [x] Failing test (fake Bearer → 503) → passing test (fake Bearer → 401 with verify-stage error).
- [x] New revision `sigil-api--0000071` Running + Healthy + 100% traffic.
- [x] Unprotected endpoints unaffected (sanity).
- [x] No env-var clobber (existing `STRIPE_*`, `DATABASE_URL`, etc. preserved).

**F1.5: NEW — operator decision.** Either:
- Configure Auth0 Post-Login Action that sets `https://api.sigilsec.ai/{email,name}` claims, OR
- Apply the backend `/userinfo` fallback (code change in `api/routers/auth.py:432-434`).

Until F1.5 is resolved, the F-003 STORY-104 403 baseline still cannot be observed (the API rejects every JWT with "missing email claim" before the plan check runs).

## Cleanup Required (operator)

Delete two test users via Auth0 Dashboard → Users:
- `reece+sigil-f003-1777801888@nomark.au` (from STORY-104/105 evidence)
- `reece+sigil-f003-f1verify-1777803354@nomark.au` (from this F1 fix evidence)

Both have NO MSSQL `users` row (auto-provision blocked at the email-claim 401, so no DB writes).

## Reproducibility (operator)

```bash
# Re-verify F1 fix any time:
curl -sS -H "Authorization: Bearer fake.fake.fake" \
  https://api.sigilsec.ai/v1/billing/subscription
# Expected: HTTP 401 + {"detail":"Invalid or expired Auth0 token"}
# Pre-fix would have been: HTTP 503 + {"detail":"Authentication service not configured"}

# Re-confirm Container App revision + AUTH0 env presence:
az containerapp show -n sigil-api -g sigil-rg \
  --query "properties.template.containers[0].env[?contains(name, 'AUTH0')].name" -o tsv
# Expected: SIGIL_AUTH0_DOMAIN, SIGIL_AUTH0_AUDIENCE
```
