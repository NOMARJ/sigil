# US-101 Fix Applied: Stripe Webhook Event Subscription Updated 4 → 6

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-101 (FAIL → PASS)
**Status:** PASS — P0 defect resolved
**Captured:** 2026-05-03 (autopilot session, owner-authorized live-key API write)
**Verifier:** Claude Code (Opus 4.7) — `api.stripe.com` POST + read-back

---

## Authorization

User explicit auth in `/bugfix all as recommended` reply:
> "authorized to POST /v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc with all 6 events (current 4 + checkout.session.completed + customer.subscription.created) using the live key in api/.env"

This evidences scope-bounded write authorization for the live Stripe API: a single endpoint, a single field, a named set of values.

## Pre-State (verbatim, before fix)

```json
{
  "id": "we_1T2AXKFhPhxEz27fCYP53mKc",
  "status": "enabled",
  "livemode": true,
  "api_version": "2025-06-30.basil",
  "enabled_events": [
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
    "invoice.payment_succeeded"
  ],
  "count": 4
}
```

Matches the verbatim audit captured in `evidence/F-003/US-101-webhook-subscription-audit.md` — 4 events, missing the 2 P0 events the handler in `api/routers/billing.py:782-794` dispatches on.

## Action

`POST https://api.stripe.com/v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc` with **the full union** of current + missing events (6 total). Stripe's `enabled_events` is a *replace* field, not a *merge* field — sending only the 2 missing events would have **dropped** the existing 4. The POST sends all 6.

```bash
curl -sS -X POST "https://api.stripe.com/v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc" \
  -H "Authorization: Bearer $SIGIL_STRIPE_SECRET_KEY" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=customer.subscription.created" \
  -d "enabled_events[]=customer.subscription.updated" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=invoice.payment_succeeded" \
  -d "enabled_events[]=invoice.payment_failed"
```

## Post-State (verbatim Stripe response)

```json
{
  "id": "we_1T2AXKFhPhxEz27fCYP53mKc",
  "status": "enabled",
  "livemode": true,
  "api_version": "2025-06-30.basil",
  "enabled_events": [
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_succeeded",
    "invoice.payment_failed"
  ],
  "count": 6
}
```

## Independent Re-Verify (separate GET)

```json
{
  "id": "we_1T2AXKFhPhxEz27fCYP53mKc",
  "status": "enabled",
  "livemode": true,
  "api_version": "2025-06-30.basil",
  "enabled_events": [
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.deleted",
    "customer.subscription.updated",
    "invoice.payment_failed",
    "invoice.payment_succeeded"
  ],
  "count": 6
}
```

(Sort order differs because the second GET sorts client-side; set membership is identical.)

## Coverage vs PRD §US-003 AC

| Required event | Subscribed (post-fix) | Status |
|---|---|---|
| `customer.subscription.created` | ✓ | OK |
| `customer.subscription.updated` | ✓ | OK |
| `customer.subscription.deleted` | ✓ | OK |
| `invoice.paid` (PRD literal) | (handler uses `payment_succeeded`) | naming mismatch only — see US-101 audit F2 |
| `invoice.payment_failed` | ✓ | OK |
| `checkout.session.completed` | ✓ | OK |

All 6 PRD-required events are now covered (with `invoice.payment_succeeded` standing in for `invoice.paid` per F2 of the audit — semantically correct for subscription billing).

## What This Unblocks

- **STORY-105 (test-mode round-trip):** the tier-flip path now has the events it depends on. A user completing test-mode Checkout will trigger `checkout.session.completed` → handler resolves user → `customer.subscription.created` → tier flips to Pro.
- **STORY-102 positive control:** the operator can now meaningfully run "Send test webhook" → `customer.subscription.created` from Stripe Dashboard and expect a 200 from `/v1/billing/webhook`. Pre-fix, that event would have been *received* by Dashboard's test-send (Dashboard test sends bypass the subscription filter for the endpoint), but live customer events of that type would have been *dropped*.

## What This Does NOT Resolve

- **Test-mode webhook subscription:** this fix is live-mode only. STORY-105 runs in TEST mode; if the test-mode webhook (separate endpoint, separate ID) has the same gap, the round-trip will still fail there. Operator should run the same audit against the test-mode endpoint:
  ```bash
  # Use the test secret key (not live), enumerate test-mode webhook endpoints, audit subscriptions.
  curl -sS https://api.stripe.com/v1/webhook_endpoints \
    -H "Authorization: Bearer $SIGIL_STRIPE_SECRET_KEY_TEST" \
    | jq ".data[] | {id,url,status,enabled_events}"
  ```
  If a test-mode endpoint exists, apply the same 6-event subscription. If no test-mode endpoint exists, create one pointing at a test-mode-aware URL (e.g., a tunneled local container, or a test-mode equivalent of `api.sigilsec.ai`).
- **Bot dispatch:** verified subscription membership only. Does not verify the running container actually invokes the handler dispatch with `STRIPE_WEBHOOK_SECRET` matching what Stripe signs with. STORY-102 positive control is still required to close that gap.

## Verdict

**PASS** — STORY-101 P0 defect resolved.
- [x] Endpoint exists at correct URL
- [x] `enabled: true`
- [x] `livemode: true`
- [x] Subscribes to all 6 required events (was 4, now 6)
- [x] Audit findings recorded in `evidence/F-003/US-101-webhook-subscription-audit.md` and this fix-applied file
- [x] Pre/post diff captured verbatim
- [x] Independent re-verify GET confirms post-state

This unblocks STORY-105 (test-mode round-trip) **for live-mode**. Test-mode round-trip itself still requires (a) a test-mode webhook endpoint with the same event subscription, and (b) operator to drive a browser-based Stripe Checkout signup-to-cancel flow.

## Reproducibility

```bash
# Re-verify any time:
bash -c '
ENVFILE=/Users/reecefrazier/CascadeProjects/sigil/api/.env
set -a; . "$ENVFILE" >/dev/null 2>&1; set +a
curl -sS "https://api.stripe.com/v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc" \
  -H "Authorization: Bearer $SIGIL_STRIPE_SECRET_KEY" \
  | jq "{enabled_events: (.enabled_events|sort), count:(.enabled_events|length)}"
'
# Expect: count:6, sorted set containing checkout.session.completed and customer.subscription.created.
```
