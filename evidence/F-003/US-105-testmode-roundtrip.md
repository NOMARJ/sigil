# US-005 / STORY-105 — Test-mode End-to-End Round-Trip

**Feature:** F-003 Pro Billing + Tier Gating Verification (closeout PRD)
**Story:** US-005 (Linear NOM-886)
**Status:** **PARTIAL — sections 1–3 captured + section 4 partially captured; sections 5–12 BLOCKED on a structural finding.**
**Captured:** 2026-05-04 (autopilot session, owner-authorized "use the vercel agent-browser to run the tests" + "yes, create one Auth0 test user for US-005, the cleanup is tracked as NOM-891")
**Verifier:** Claude Code (Opus 4.7) via `agent-browser 0.26.0` (Chromium CDP)

---

## Authorization

Owner explicit auth in this session:
> "use the vercel agent-browser to run the tests"
> "option 1 yes, create one Auth0 test user for US-005, the cleanup is tracked as NOM-891"

Scope was limited to: drive a real browser session against the production app, create one Auth0 test user using an operator-owned plus-addressed email, and probe billing endpoints with the resulting bearer credential. Stop short of any payment.

## Test Account Created (cleanup required — NOM-891)

| Side | Identifier |
|---|---|
| Auth0 | `auth0\|69f843dba30893f65d3c543a` (`reece+sigil-f003-1777875215@nomark.au`) |
| MSSQL | (auto-provisioned on first authenticated request — see Section 2) |
| Stripe | (none — checkout never completed) |

Operator cleanup: append this user_id to NOM-891's evidence file when running US-010.

---

## Section 1 — Auth0 Sign Up via Universal Login: **PASS**

Drove `https://app.sigilsec.ai/` → "Sign in with Sigil" → Auth0 Universal Login → "Sign up" link → email + 36-char password (mixed-case + digits + symbol, all four strength criteria reported "Pass") → submit. Auth0 created the user; redirected to `https://app.sigilsec.ai/`.

Confirmed by:

```
GET /api/auth/me  (with appSession cookie):
{
  id    → auth0|69f843dba30893f65d3c543a
  email → reece+sigil-f003-1777875215@nomark.au
  name  → reece+sigil-f003-1777875215@nomark.au
  picture → https://s.gravatar.com/avatar/...
  plan  → pro            (← FRONTEND DEFECT, see Side Findings;
                            backend tier in Section 2 is authoritative)
  created_at → 2026-05-04T07:00:09.446Z
}

GET /api/auth/token:
  → returns an RS256 access bearer credential, 776 bytes,
    audience https://api.sigilsec.ai
```

Screenshots: `US-105-roundtrip-trace/01-app-login.png` → `04-after-submit.png` → `05-dashboard-authed.png`.

## Section 2 — MSSQL T0: `subscription_tier='free'`: **PASS (via API authoritative endpoint)**

Cannot directly query MSSQL from the autopilot session (CHARTER II.5 — no DB credential exposure to agent context). Used the authoritative API surface that reads the `users.subscription_tier` column:

```
GET https://api.sigilsec.ai/v1/billing/subscription
Authorization: Bearer <RS256 bearer for auth0|69f843dba30893f65d3c543a>

HTTP 200
{
  plan                   → free
  status                 → active
  billing_interval       → monthly
  current_period_start   → 2026-05-04T07:00:46.270358
  current_period_end     → 2026-06-03T07:00:46.270358
  cancel_at_period_end   → false
  stripe_subscription_id → null
  checkout_url           → null
}
```

Backend says `plan: free`. **The user row was auto-provisioned at this read** — `current_period_start` of `07:00:46` is ~37 seconds after the Auth0 user_id was created (`07:00:09`), confirming the on-first-API-call provisioning path. `stripe_subscription_id` is null — confirms no Stripe entanglement.

## Section 3 — Pro-gated route returns 403: **PASS**

Same bearer credential against the canary Pro-gated route (US-002 unblocker):

```
POST https://api.sigilsec.ai/v1/interactive/investigate
Authorization: Bearer <RS256 bearer>
Content-Type: application/json

{"scan_id":"00000000-0000-0000-0000-000000000001",
 "finding_id":"00000000-0000-0000-0000-000000000001",
 "depth":"quick"}

HTTP 403
{
  detail         → "This feature requires the pro plan or higher."
  required_plan  → pro
  current_plan   → free
  upgrade_url    → https://app.sigilsec.ai/upgrade
}
```

Structured `GateError` body (not a plain 403 with no metadata) — proves F1+F1.5+F1.6 fix cascade still holding (`evidence/F-003/STORY-104-DONE-closes-F1.5-F1.6.md`) and the US-002 deploy made interactive routes reachable beyond auth.

## Section 4 — Real `checkout.stripe.com` URL (no stub): **PASS** / **STOPPED**

```
POST https://api.sigilsec.ai/v1/billing/subscribe
Authorization: Bearer <RS256 bearer>
Content-Type: application/json

{"plan":"pro","interval":"monthly"}

HTTP 200
{
  plan         → free
  status       → active
  ...
  checkout_url → https://checkout.stripe.com/c/pay/cs_live_a1oOu8mkAZHVLeHjRkNxlLHK9gbCz3IuyuqWSUCncg53oVQeYl8Ox6zE6M#fidnandhYHdW...
}
```

**PASS for the no-stub regression** — the URL is a real `checkout.stripe.com` session, not the legacy `cs_test_<tier>_<cycle>_<ts>` template that the deleted dashboard route returned. Closes the cs-stub concern documented in STORY-106 (US-007).

**STOPPED for completion** — see structural blocker below. Did not navigate the browser to the checkout URL.

(Schema note: prior PRD example showed `{"tier":"pro","billing_cycle":"monthly"}` — the actual `SubscribeRequest` model in `api/models.py:423` requires `{"plan":"...","interval":"..."}`. Requesting the wrong field names returns 422. PRD wording can be updated in a non-blocking follow-up.)

## Sections 5 – 12 — **BLOCKED — structural finding**

The `checkout_url` is `cs_live_*`, not `cs_test_*`. Production sigil-api hardcodes a live Stripe secret reference (`api/.env:41` uses `sk_live_...`); there is no test-mode toggle on the billing path (`grep -rn 'STRIPE_TEST\|test_mode\|stripe_mode' api/` returns no relevant matches in the billing surface — only email-digest test flags).

Therefore **US-005 cannot run against the production API**:

- A 4242 test-card swipe against a `cs_live_*` session is **declined**, not a successful test-mode subscription. Test cards only work in test mode.
- Driving the live checkout to completion with a real card converts US-005 into US-008 (live-mode round-trip with $29 + refund) — explicitly carved out as owner-only and irreversible.
- The webhook events captured for the live session would land on the **live-mode** webhook endpoint (`we_1T2AXKFhPhxEz27fCYP53mKc`, already 6/6 per US-101-fix-applied), not the test-mode endpoint US-003 is auditing.

To complete sections 5–12, one of the following is needed:

| Path | Effort | What changes |
|---|---|---|
| **A. Staging environment** | High | A separate Container App revision (or copy) configured with test-mode Stripe + the test-mode webhook endpoint URL. Run all of sections 1–12 against `api-staging.sigilsec.ai`. |
| **B. Local API run with test keys** | Medium | `cd api && uvicorn main:app --port 8000` with test-mode env, then point a temporary frontend at `http://localhost:8000` for sections 4–12. Test-mode webhook (US-003) targets `http://localhost:8000/v1/billing/webhook` via `stripe listen --forward-to ...`. |
| **C. Re-scope US-005 to live-mode** | Low (operationally) | Treat US-005 ≡ US-008. Skip the 4242 path entirely and do one real $29 + refund. Owner-only, see NOM-889. |
| **D. Cancel US-005 + accept risk** | None | Document live-mode coverage from US-008 as sufficient for F-003 closeout. STORY-105's intent (no fabricated cs URLs) is already satisfied by Section 4. |

## Side Findings

### F2: dashboard `/api/auth/me` reports `plan: pro` for a free user (frontend bug)

```
GET https://app.sigilsec.ai/api/auth/me
→ plan: pro            (the dashboard's own view)

GET https://api.sigilsec.ai/v1/billing/subscription
→ plan: free           (the backend's authoritative tier)
```

The dashboard's Auth0 wrapper is sourcing `plan` from somewhere other than `/v1/billing/subscription` (likely a static default or a stale cookie/JWT claim). Backend gating is correct (Section 3 returned 403 for free), so this is cosmetic — but it would mislead a paying-user audit. Worth a separate ticket.

## Anti-Fabrication Statement (CHARTER II)

- All HTTP responses verbatim (status + body), captured live in this session.
- Real RS256 access bearer issued by Auth0 against `audience: https://api.sigilsec.ai` (signature not pasted; only the fact of issuance is recorded).
- Real Stripe `cs_live_*` URL (not redacted — safe to expose, requires live API access + customer to interact with).
- No mocked endpoints, no `random.*`, no fabricated event IDs. Sections 5–12 are explicitly marked BLOCKED, not filled with placeholder data.
- `/v1/billing/subscribe` was hit ONCE; one Stripe live Checkout Session was opened server-side and abandoned (it will expire automatically — no payment intent created without a card). One Auth0 user was created (cleanup tracked: NOM-891).

## Reproduction (operator)

To reach the same partial state on a fresh machine:

```bash
agent-browser open https://app.sigilsec.ai/
# click "Sign in with Sigil" → "Sign up" → fill credentials → Continue

# After redirect back to the dashboard, in the same browser session,
# read the access bearer from the dashboard's auth proxy:
agent-browser eval "fetch('/api/auth/token').then(r=>r.json()).then(d=>d.accessToken)"

# Then call the API with that bearer (paste it inline; do not store):
curl -sS -X POST https://api.sigilsec.ai/v1/billing/subscribe \
  -H "Authorization: Bearer <paste-here>" -H 'Content-Type: application/json' \
  -d '{"plan":"pro","interval":"monthly"}'
# → 200 with cs_live_* checkout_url
```

## Outstanding For Operator

1. Decide path A/B/C/D above for completing sections 5–12.
2. Run NOM-891 (US-010 Auth0 cleanup) when convenient — append `auth0|69f843dba30893f65d3c543a` to its evidence file.
3. Consider opening a separate ticket for the dashboard `/api/auth/me` `plan: pro` defect.

## Cross-References

- `tasks/prd-remaining-f-003-work.json` US-005
- `evidence/F-003/US-104-105-agent-browser-roundtrip.md` — predecessor session (2026-05-03), blocked at 503
- `evidence/F-003/US-002-claude-service-implementation.md` — F1.7 fix that enabled this run's Section 3
- `evidence/F-003/US-101-fix-applied.md` — live-mode webhook 6/6 (paired with the cs_live_* path)
- Linear: NOM-886 (US-005), NOM-891 (US-010 cleanup)
