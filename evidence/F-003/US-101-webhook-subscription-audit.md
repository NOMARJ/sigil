# US-101 Evidence: Stripe Live-Mode Webhook Subscription Audit

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-101
**Status:** FAIL — defect found (subscription membership does not cover handler-dispatched events)
**Captured:** 2026-05-03 (autopilot session, owner-authorized live-key API call)
**Verifier:** Claude Code (Opus 4.7) — `api.stripe.com` read-only

---

## Reproducibility

```bash
# Loads SIGIL_STRIPE_SECRET_KEY (live) into subshell env, calls Stripe API,
# captures only structured fields (no key value echoed).
( set -a; . api/.env; set +a; \
  curl -sS https://api.stripe.com/v1/webhook_endpoints \
    -H "Authorization: Bearer $SIGIL_STRIPE_SECRET_KEY" \
    | jq '{count:(.data|length), endpoints:[.data[]|{id,url,status,enabled_events,livemode,api_version,description}]}' )
```

## Verbatim Stripe API Response

```json
{
  "count": 2,
  "endpoints": [
    {
      "id": "we_1T2AXKFhPhxEz27fCYP53mKc",
      "url": "https://api.sigilsec.ai/v1/billing/webhook",
      "status": "enabled",
      "enabled_events": [
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
        "invoice.payment_succeeded"
      ],
      "livemode": true,
      "api_version": "2025-06-30.basil",
      "description": null
    },
    {
      "id": "we_1RkFv2FhPhxEz27fKjAapPqB",
      "url": "https://instaindex.ai/api/webhook",
      "status": "enabled",
      "enabled_events": [
        "checkout.session.completed",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "customer.subscription.created"
      ],
      "livemode": true,
      "api_version": "2025-06-30.basil",
      "description": null
    }
  ]
}
```

## Sigil Endpoint Findings

**Endpoint:** `https://api.sigilsec.ai/v1/billing/webhook`
**Status:** `enabled` ✓
**Livemode:** `true` ✓
**API version:** `2025-06-30.basil`

### Subscription Membership vs Required Events

PRD §US-003 AC: endpoint must subscribe to:
`customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, `invoice.payment_failed`, `checkout.session.completed`

Handler dispatch (`api/routers/billing.py:782-794`):
```python
if event_type == "checkout.session.completed":
elif event_type == "customer.subscription.created":
elif event_type == "customer.subscription.updated":
elif event_type == "customer.subscription.deleted":
elif event_type == "invoice.payment_failed":
elif event_type == "invoice.payment_succeeded":
elif event_type == "customer.subscription.trial_will_end":
```

| Event | Required (PRD) | Handler dispatches | Subscribed at Stripe | Status |
|-------|---------------|-------------------|---------------------|--------|
| `checkout.session.completed` | ✓ | ✓ | ✗ | **MISSING — P0** |
| `customer.subscription.created` | ✓ | ✓ | ✗ | **MISSING — P0** |
| `customer.subscription.updated` | ✓ | ✓ | ✓ | OK |
| `customer.subscription.deleted` | ✓ | ✓ | ✓ | OK |
| `invoice.paid` | ✓ (PRD literal) | (uses `payment_succeeded` instead) | ✗ (`payment_succeeded` IS subscribed) | PRD/handler naming mismatch — see F2 |
| `invoice.payment_failed` | ✓ | ✓ | ✓ | OK |
| `customer.subscription.trial_will_end` | (not listed) | ✓ | ✗ | minor — defensive handler path; trial copy currently unverified, see STORY-107 |

## Findings

### F1 — Ship-blocking defect: missing event subscriptions

The Sigil live webhook is NOT subscribed to:
- `checkout.session.completed`
- `customer.subscription.created`

The handler in `api/routers/billing.py:782, 784` dispatches on both. The handler uses `checkout.session.completed` to resolve which user is associated with which Stripe customer (`api/routers/billing.py:851` logs an error if it cannot resolve). Without that event, **a user who completes paid Checkout will NOT have their tier flipped to Pro** — their `users.subscription_tier` will stay at `free`, and the Pro endpoints will keep returning 403.

This is the exact failure mode F-003 is meant to catch: plumbing exists, plumbing does not carry water. STORY-105 (test-mode round-trip) **will fail** in its current form: it will reach the checkout step, charge the test card, but the webhook handler will never see the events that trigger the tier flip.

**Required fix (operator):** in Stripe Dashboard live-mode → Developers → Webhooks → click `we_1T2AXKFhPhxEz27fCYP53mKc` → "Edit subscribed events" → add:
- `checkout.session.completed`
- `customer.subscription.created`

Then re-run this audit to confirm.

### F2 — Naming mismatch between PRD and handler: `invoice.paid` vs `invoice.payment_succeeded`

PRD §US-003 AC literally lists `invoice.paid`. The handler dispatches on `invoice.payment_succeeded` (and the Dashboard subscribes to `invoice.payment_succeeded`). These are different Stripe event types — both fire on largely the same transactions but with subtly different semantics:
- `invoice.paid`: emitted when an invoice transitions to paid status (via any mechanism — manual marking, automatic via subscription, etc).
- `invoice.payment_succeeded`: emitted specifically when a payment attempt succeeds against an invoice.

For Sigil's pure subscription model, `invoice.payment_succeeded` is the canonical event and is correctly subscribed. The PRD AC text was slightly imprecise — recommend amending PRD AC to `invoice.payment_succeeded` (or both) once the operator confirms intent. Not a defect, but a documentation alignment to record.

### F3 — Side-finding: shared Stripe account across projects

The same Stripe account hosts a separate webhook for `https://instaindex.ai/api/webhook` (project `instaindex`, also in the nomark Vercel scope). This is a configuration data point, not a defect for F-003. Worth noting because:
- Live-mode events from Stripe (subscriptions, charges) under this account include events from BOTH projects.
- The Sigil endpoint's `enabled_events` filter ensures it only receives the events it subscribes to.
- Cross-project event hygiene should be considered in any future Stripe rotation or migration.

### F4 — `description: null` on the Sigil endpoint

The endpoint has no description field set. Recommend setting a description like "Sigil API — billing webhook (production)" so future operators / automated audits can quickly identify endpoint purpose without needing to grep URLs. Cosmetic, low-priority.

## Verdict

**FAIL** — STORY-101 cannot be DONE until the missing event subscriptions are added.
- [x] Endpoint exists at correct URL.
- [x] `enabled: true`.
- [x] `livemode: true`.
- [ ] Subscribes to all 6 required events — **missing 2**.
- [x] Audit findings recorded here and (TBD) in `docs/internal/2026-05-stripe-config-audit.md`.

This finding is also a hard pre-blocker for STORY-105 (test-mode round-trip): the round-trip cannot succeed in current state because the tier-flip events are not delivered.

## Operator Action Items (in priority order)

1. **P0 — fix subscription membership.** Stripe Dashboard live-mode → Developers → Webhooks → endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` → add `checkout.session.completed` and `customer.subscription.created` to subscribed events.
2. **P0 — verify the same fix in test mode.** STORY-105 runs in test mode; if test-mode webhook has the same gap, the round-trip will fail there too. Apply the same event-subscription fix to the test-mode webhook (`stripe webhook_endpoints list` without `--live` flag, or Dashboard test-mode → Developers → Webhooks).
3. **P2 — clarify PRD AC language.** Amend PRD §US-003 to use `invoice.payment_succeeded` (or list both) for accuracy.
4. **P3 — add description string** to the Sigil endpoint (cosmetic).

## Limitations

- No webhook test-mode endpoint audit was run — this audit is live-mode only. Recommend operator runs the same query without the live key (test key in api/.env) for test-mode visibility.
- `we_1T2AXKFhPhxEz27fCYP53mKc` ID is reproducibility info, not a secret — but the Stripe live secret key used to retrieve it remains in `api/.env` only and was not exposed in transcript.
