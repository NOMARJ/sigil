# PRD: Pro Billing + Tier Gating Verification

**Feature:** F-003
**Epic:** EP-003 — Sigil Pro commercial launch
**Status:** approved
**Created:** 2026-05-03
**Approved:** 2026-05-03
**Source brief:** `docs/plans/2026-05-03-sigil-pro-launch-readiness-first-principles.md`

---

## Introduction

Pro subscription infrastructure has been built and is partially deployed: real Stripe Checkout (`api/routers/billing.py:394`), webhook handler with signature verification (`api/routers/billing.py:724`), customer portal, 18 Pro endpoints gated by `require_plan(PlanTier.PRO)` in `api/routers/interactive.py`, plan limits in `api/gates.py`, secrets injected from Azure Key Vault to Container Apps. The pricing page and `/v1/billing/plans` API expose the new $29/mo Pro tier with the AI features.

What has not been done: the round-trip from signup → paid checkout → webhook delivery → DB tier flip → unlocked Pro endpoint → portal cancellation has never been observed end-to-end. Plumbing existing is not the same as plumbing carrying water.

This PRD defines the work to *prove* the path works in both Stripe test mode and live mode, fix any breaks discovered, and remove dead-code disconnects (notably `dashboard/src/app/api/billing/create-checkout/route.ts`). It does not introduce new billing features, change pricing, or build new gates.

---

## Goals

- Prove signup → paid Pro access → cancel-to-free works end-to-end in Stripe test mode
- Prove the same path works in Stripe live mode with one real $29 charge (refunded after)
- Confirm production env points at live-mode Stripe Price IDs, not test
- Confirm Stripe Dashboard webhook subscriptions cover all events the handler dispatches on
- Eliminate the dead `dashboard/src/app/api/billing/create-checkout/route.ts` returning fake `cs_test_…` URLs
- Resolve free-trial copy: either confirm trial works or remove the CTA
- Produce evidence artifacts (logs, SQL queries, screenshots) sufficient to satisfy CHARTER Article II "no false completion" before declaring F-003 done

---

## User Stories

### US-001: Test-mode end-to-end round-trip
**Description:** As the launch operator, I want to run the full signup → Pro → cancel loop in Stripe test mode so that I can verify every component without spending real money.

**Acceptance Criteria:**
- [ ] Fresh Auth0 signup creates user row with `subscription_tier='free'` in MSSQL
- [ ] `POST /v1/interactive/investigate` (or any `require_plan(PlanTier.PRO)` route) returns 403 for the free user
- [ ] `POST /v1/billing/subscribe` with `plan=pro, interval=monthly` returns a real `checkout.stripe.com` URL (not the dashboard's mock `cs_test_<tier>_<cycle>_<ts>` stub)
- [ ] Completing checkout with `4242 4242 4242 4242` triggers a Stripe `customer.subscription.created` webhook to `/v1/billing/webhook`
- [ ] Webhook handler updates `users.subscription_tier` to `'pro'` in MSSQL within 30 seconds
- [ ] Same Pro endpoint now returns 200 with a real LLM-backed response
- [ ] `POST /v1/billing/portal` returns a working Stripe portal URL
- [ ] Portal cancellation triggers `customer.subscription.deleted` webhook
- [ ] `users.subscription_tier` flips back to `'free'`
- [ ] Pro endpoint returns 403 again
- [ ] Evidence captured: Stripe event IDs, MSSQL `SELECT id, email, subscription_tier, stripe_customer_id, stripe_subscription_id FROM users WHERE id = ?` snapshots at each stage, API request/response logs

### US-002: Live-mode round-trip with one real payment
**Description:** As the launch operator, I want to confirm test mode and live mode behave identically so that real customers will not hit unforeseen breaks.

**Acceptance Criteria:**
- [ ] One real Auth0 account completes the full US-001 loop using Stripe live mode and a real card charged $29
- [ ] Charge appears in Stripe Dashboard as a successful $29 subscription invoice
- [ ] User row reflects active Pro tier with `stripe_subscription_id` matching the live subscription
- [ ] One Pro endpoint call from this user returns 200
- [ ] Refund issued from Stripe Dashboard within 24h; webhook updates tier back to free
- [ ] Refund event IDs and final user-row state captured

### US-003: Production Stripe configuration audit
**Description:** As the launch operator, I want to confirm production env vars and Stripe Dashboard config are aligned so that test-mode success is not invalidated when traffic flips to live.

**Acceptance Criteria:**
- [ ] `az containerapp show -n sigil-api -g sigil-rg --query 'properties.template.containers[0].env'` confirms `STRIPE_SECRET_KEY` value reference resolves to a `sk_live_...` key (verify by Stripe Dashboard key fingerprint, do not log)
- [ ] `STRIPE_PRICE_PRO`, `STRIPE_PRICE_TEAM`, `STRIPE_PRICE_PRO_ANNUAL`, `STRIPE_PRICE_TEAM_ANNUAL` all start with `price_1...` and resolve to live-mode Stripe Products
- [ ] Stripe Dashboard → Developers → Webhooks shows an endpoint pointing at `https://api.sigilsec.ai/v1/billing/webhook` in live mode
- [ ] That endpoint subscribes to: `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, `invoice.payment_failed`, `checkout.session.completed`
- [ ] Webhook signing secret in Stripe Dashboard matches `STRIPE_WEBHOOK_SECRET` value reference in Container Apps (verified by webhook returning 200 on a Stripe Dashboard "Send test webhook" event, not by direct comparison)
- [ ] Audit findings recorded in `docs/internal/2026-05-stripe-config-audit.md`

### US-004: Eliminate dead checkout route
**Description:** As a maintainer, I want to remove the unused dashboard checkout stub so that no future contributor mistakes it for the real path.

**Acceptance Criteria:**
- [ ] `grep -rn "/api/billing/create-checkout" dashboard/src` confirms zero callers (or, if callers exist, they are migrated to the FastAPI `/v1/billing/subscribe` endpoint and verified working)
- [ ] `dashboard/src/app/api/billing/create-checkout/route.ts` is deleted
- [ ] `pnpm build` (or whatever the dashboard build command is) succeeds after deletion
- [ ] Pricing page subscribe/upgrade CTA round-trip still works (re-run US-001 step "checkout URL returned" subset)

### US-005: Resolve free-trial CTA
**Description:** As a launch operator, I want pricing-page free-trial copy to either reflect a working trial or be removed so that we do not advertise behavior we don't deliver.

**Acceptance Criteria:**
- [ ] Decide: free trial enabled or removed (owner decision, recorded in `SOLUTION.md` ADR log)
- [ ] If enabled: Stripe Price configured with `trial_period_days`, US-001 re-run shows `subscription.status='trialing'` for trial duration, tier still gates correctly during trial
- [ ] If removed: pricing page no longer shows "free trial" string in any Pro CTA
- [ ] Pricing-page production HTML re-grepped after dashboard redeploy to confirm

### US-006: Production CDN cache freshness
**Description:** As a launch operator, I want www.sigilsec.ai to serve the current pricing page so that visitors do not see a 21-day-old version on launch day.

**Acceptance Criteria:**
- [ ] Investigation note: why does `curl -I https://www.sigilsec.ai` return `age: ~1.8M` despite `cache-control: max-age=0, must-revalidate`? (Vercel build hash, edge config, or origin?)
- [ ] Cause documented; fix applied (cache purge, deploy refresh, or config change)
- [ ] Post-fix, `age` header is < 3600 seconds on a fresh probe
- [ ] Pricing-page HTML byte-equal between localhost build and prod fetch (or diff explained)

---

## Functional Requirements

- FR-1: All Stripe state changes (subscription create, update, cancel, payment success/failure) must propagate to `users.subscription_tier` in MSSQL within 30 seconds via webhook
- FR-2: A user whose `subscription_tier` is `'free'` must receive 403 from any route declaring `Depends(require_plan(PlanTier.PRO))`
- FR-3: A user whose `subscription_tier` is `'pro'` must receive 200 from those same routes (subject to per-feature credit availability, which is out of scope here)
- FR-4: Webhook handler must verify Stripe signatures using `STRIPE_WEBHOOK_SECRET` and reject unsigned/invalid events with HTTP 400
- FR-5: No production code path may return a fabricated `cs_test_…` URL after this PRD ships
- FR-6: All evidence required to verify the above must be reproducible by a future operator running the documented commands (no hand-curated screenshots without commands)

---

## Non-Goals (Out of Scope)

- Building new Pro features, new gates, or new billing endpoints
- Changing Pro pricing, plan structure, or feature mix
- Implementing Team or Enterprise tier billing flows beyond what is already built
- Distribution surface verification (covered by F-004)
- Public launch announcement, threat report, or in-CLI upgrade trigger (covered by F-005)
- Credit-system internals (separately maintained in `credit_service.py`; only invoked here, not modified)
- Auth0 production setup (assumed working; if discovered broken during US-001, file a separate blocker)

---

## Success Criteria (Feature-Level)

F-003 is DONE when:

1. US-001 evidence pack exists in repo (Stripe event IDs, SQL snapshots, API logs)
2. US-002 evidence pack exists with one real $29 charge round-trip and refund
3. US-003 audit doc lives at `docs/internal/2026-05-stripe-config-audit.md` with all checklist items signed off
4. US-004 grep confirms no dead route remains
5. US-005 owner decision recorded and reflected in production
6. US-006 cache `age` < 3600s on fresh probe
7. SOLUTION.md F-003 status flipped from `BUILT — pending end-to-end verification` to `DONE` with shipped date
8. `progress.md` story status DONE for each US-001 through US-006

---

## Dependencies and Constraints

- **Auth0 production**: assumed configured per `docs/internal/AUTH0_PRODUCTION_SETUP.md`. If broken, blocks US-001
- **MSSQL access**: launch operator needs read access to `sigil-sql-w2-46iy6y.database.windows.net` to run verification queries
- **Stripe Dashboard access**: launch operator needs ability to view live-mode webhook subscriptions and refund a real charge
- **Azure Container Apps env**: launch operator needs `az` CLI access scoped to `sigil-rg` to run env-var audit
- **No new infra**: this PRD does not provision anything new. If it requires new infra, that is a finding, not a story
- **CHARTER Article II**: all evidence must be real — no fabricated logs, no synthetic transactions described as real

---

## Open Questions

- **Q1:** Does Auth0 production callback URL match `https://www.sigilsec.ai/auth/callback` (or whatever the deployed dashboard expects)? Owner to confirm before US-001.
- **Q2:** Who handles the live-mode test charge — owner personally or a delegated launch operator? Determines US-002 timing.
- **Q3:** Free-trial decision (US-005) — owner intent: was the "free trial" CTA an aspiration or a built feature?

---

## Verification Commands (CHARTER §Verification Protocol)

Each story's evidence must be reproducible. Reference commands:

```bash
# Confirm webhook accepts signed events (returns 200 on Stripe Dashboard test send)
curl -sS -X POST https://api.sigilsec.ai/v1/billing/webhook -H "Stripe-Signature: <test>" -d '{}' | jq

# Confirm Pro plan API
curl -sS https://api.sigilsec.ai/v1/billing/plans | jq '.[] | select(.tier=="pro")'

# Confirm Container Apps Stripe env (key fingerprints, not values)
az containerapp show -n sigil-api -g sigil-rg \
  --query 'properties.template.containers[0].env[?contains(name, `STRIPE`)].name' -o tsv

# MSSQL tier-flip verification
sqlcmd -S sigil-sql-w2-46iy6y.database.windows.net -d sigil -U sigil_admin \
  -Q "SELECT id, email, subscription_tier, stripe_customer_id, stripe_subscription_id FROM users WHERE email='<test-email>'"

# Dead-route grep
grep -rn "/api/billing/create-checkout" /Users/reecefrazier/CascadeProjects/sigil/dashboard/src

# CDN freshness
curl -sS -I https://www.sigilsec.ai/pricing | grep -E '^(age|cache-control|x-vercel-cache):'
```

---

*PRD complete. Next step: decompose into atomic stories in `progress.md` via `/autopilot tasks/prd-pro-billing-gating-verification.md --dry-run` (or owner-driven manual decomposition).*
