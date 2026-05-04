---
id: ADR-0001
title: "Pro/Team subscriptions ship with a 14-day free trial, set on Checkout Session and gated to first-time Stripe customers"
status: accepted
date: 2026-05-04
venture: sigil
tags: [billing, stripe, growth, story-107, f-003]
outcome: pending
---

## Context

The pricing page on `app.sigilsec.ai/pricing` advertised a free trial as part of the Pro CTA. Verification (STORY-100, evidence at `evidence/F-003/US-100-stripe-price-ids-live-confirmation.md`) using the Stripe MCP against the live production account `acct_1RkD8NFhPhxEz27f` confirmed that **none of the four Stripe Price objects** (`price_1T2AOLFhPhxEz27fs0Z2nU4y` Pro/mo, `price_1T2AnKFhPhxEz27fNp6Kt7O3` Pro/yr, `price_1T2AQCFhPhxEz27fOjCVsuwe` Team/mo, `price_1T2AlpFhPhxEz27f8tni554h` Team/yr) had `recurring.trial_period_days` set — every one returned `null`.

That left F-003 with three branches per US-005 acceptance criteria:

- **A. Remove the free-trial copy** — match code to the Stripe truth.
- **B. Configure a trial on the Stripe Price** — match Stripe to the copy. Requires creating four new Price objects since `recurring.trial_period_days` is immutable on existing Prices.
- **C. Configure a trial at the Checkout Session layer** — match the runtime to the copy without altering the Price catalogue.

## Decision

**Branch C, 14 days.** When `POST /v1/billing/subscribe` creates a Stripe Checkout Session for a user whose stored subscription record has no `stripe_customer_id`, the session is created with `subscription_data={"trial_period_days": 14}`. Returning customers (any non-null `stripe_customer_id` from a prior subscription, even cancelled) get no `subscription_data` and therefore no trial — preventing the cancel-and-resubscribe pattern from yielding repeated 14-day windows of free Pro access.

Trial length is held in a single module-level constant `_TRIAL_PERIOD_DAYS = 14` at `api/routers/billing.py:207` so future tuning is a one-line edit. Implementation landed in commit `7b60315` (live on `sigil-api--0000078`, image `:7b60315`, deployed 2026-05-03 23:56Z). Regression tests at `api/tests/test_billing_trial_period.py` (3 cases, pure-mock — runs without MSSQL).

14 days is the standard B2B SaaS default — long enough for a real evaluation cycle (typically 5-10 working days plus weekend bake-in), short enough that users feel pressure to convert before the renewal window.

## Consequences

**Positive**

- Pricing-page copy now matches runtime behaviour. STORY-107 closable.
- Trial mechanics are configurable in code: changing length, adding tier-specific durations, or sunsetting the trial entirely is a code change with no Stripe-side surgery.
- The four production Price objects stay clean — no proliferation of `..._with_trial` variants.
- Cancel/resubscribe abuse is structurally prevented by the `is_new_customer` gate.

**Negative / trade-offs**

- The trial gate is in code, not Stripe. A future engineer who sets `trial_period_days` on a Stripe Price (or on the Customer Portal config) without touching `billing.py` would create a second source of trial truth — drift risk. Mitigation: STORY-107 ADR (this document) is referenced in `_TRIAL_PERIOD_DAYS`'s commit message; the regression test asserts the exact `subscription_data` shape.
- Revenue lag: every new Pro/Team customer is now zero-revenue for 14 days post-conversion. Cash-flow assumptions in pricing models must reflect this.
- A user who churns within the trial window costs nothing but still consumed Pro features — the gating layer (`require_plan(PlanTier.PRO)` etc.) treats `subscription.status='trialing'` the same as `'active'`. This is intentional (trials are real Pro for evaluation purposes) but means trial-period abuse is bounded only by the `is_new_customer` gate, not by feature throttling.
- Marketing copy currently does not specify "14 days". If the pricing page later names a different duration (e.g. "30-day free trial"), drift returns from the opposite direction. Suggested follow-up: pull the trial duration into the `/v1/billing/plans` response and have the dashboard render it directly.

## Reversibility

To remove the trial: change `_TRIAL_PERIOD_DAYS` to `0` and gate the `subscription_data` block on `if is_new_customer and _TRIAL_PERIOD_DAYS > 0`, or simply delete the block. Tests in `test_billing_trial_period.py` would need their assertions inverted. Existing trialing subscriptions are unaffected — the change is a forward-only policy update.

## Evidence

- `evidence/F-003/US-100-stripe-price-ids-live-confirmation.md` — confirms `trial_period_days: null` on all four live Prices, motivating this ADR.
- Commit `7b60315` — implementation + tests.
- `api/tests/test_billing_trial_period.py` — three regression assertions: constant value, new-customer trial attached, returning-customer trial absent.
