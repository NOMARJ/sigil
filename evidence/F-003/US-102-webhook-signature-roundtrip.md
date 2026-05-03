# US-102 Evidence: Webhook Signature Round-Trip (PARTIAL — negative control only)

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-102
**Status:** PARTIAL — negative control captured; positive control awaits operator
**Captured:** 2026-05-03 (autopilot session)
**Verifier:** Claude Code (Opus 4.7) — autonomous, no credentials used

---

## Negative Control (PRD §FR-4 / STORY-102 TDD anchor)

```
$ curl -sS -X POST https://api.sigilsec.ai/v1/billing/webhook \
    -H 'Stripe-Signature: t=1,v1=bad' \
    -d '{}' \
    -w '\n---HTTP-CODE:%{http_code}---\n'

{"detail":"Invalid webhook signature"}
---HTTP-CODE:400---
```

**Result:** HTTP 400 + `"detail":"Invalid webhook signature"`. **PASS.**

## Sibling Probe — Unsigned Request

```
$ curl -sS -X POST https://api.sigilsec.ai/v1/billing/webhook \
    -d '{}' \
    -w '\n---HTTP-CODE:%{http_code}---\n'

{"detail":"Invalid webhook signature"}
---HTTP-CODE:400---
```

**Result:** HTTP 400. The handler rejects requests with no `Stripe-Signature` header same way as bogus signatures. PASS.

## What This Proves

- **PRD §FR-4** ("Webhook handler must verify Stripe signatures using `STRIPE_WEBHOOK_SECRET` and reject unsigned/invalid events with HTTP 400"): **SATISFIED**.
- **STORY-102 TDD anchor** (`curl ... -H 'Stripe-Signature: t=1,v1=bad' ... → expected 400`): **SATISFIED**.
- The handler implements signature verification at the HTTP boundary. A request that does not carry a valid Stripe signature cannot trigger any state change on this endpoint.

## What This Does NOT Prove (positive control still needed)

PRD §US-003 AC for STORY-102 requires the positive leg as well:
- Stripe Dashboard → Developers → Webhooks → "Send test webhook" → handler returns 200 for that specific event ID.
- Container log line confirming the 200 corresponds to the Dashboard-triggered event.

That positive control requires:
- Stripe Dashboard live-mode access (operator only).
- Container Apps log access (operator only — `az containerapp logs tail -n sigil-api -g sigil-rg`).

**Without the positive 200, we cannot rule out:**
- The handler always returns 400 (e.g., webhook secret env var not set on the running container).
- The signing secret in Container Apps env doesn't match the secret Stripe Dashboard signs with — every valid Stripe event would also fail signature verification.

The negative control is necessary but not sufficient. The pair together (positive 200 + negative 400) is what closes STORY-102.

## Cross-Reference: STORY-101 P0 Defect Reduces the Risk Surface

Per `evidence/F-003/US-101-webhook-subscription-audit.md`, the live webhook is missing 2 of the 6 required event subscriptions. Until that defect is fixed, NO valid live event can hit the Sigil endpoint for `customer.subscription.created` or `checkout.session.completed`. The negative-control evidence here covers signature-verification correctness; the positive control should be deferred until **after** the STORY-101 fix lands, since the operator's "Send test webhook" probe should test against an event type that the endpoint subscribes to (post-fix all 6 are covered; today only 4 are).

## Verdict

PARTIAL PASS — TDD anchor + FR-4 satisfied. Story stays open pending operator-driven positive control via Stripe Dashboard test send (post STORY-101 fix).

## Operator Commands to Close STORY-102

```
# 0. PRECURSOR: ensure STORY-101 P0 fix has landed (subscribe to checkout.session.completed
#    and customer.subscription.created on we_1T2AXKFhPhxEz27fCYP53mKc).

# 1. In Stripe Dashboard live-mode → Developers → Webhooks → click endpoint
#    → "Send test webhook" → choose `customer.subscription.created`. Note timestamp + event ID (evt_...).

# 2. From operator workstation w/ Azure CLI:
az containerapp logs tail -n sigil-api -g sigil-rg --follow false --tail 200 \
  | grep -iE "evt_<id>|webhook|stripe" | head -30

# Expected: log line showing handler returned 200 for that event ID, within ~30s of Step 1.
# If 200 appears: STORY-102 DONE.
# If 400 / 401 / 500 appears: signing secret mismatch or handler bug. Escalate.
```
