# F2 Fix Applied: SubscriptionManager Routed Through Stripe Customer Portal

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Defect:** F2 from `evidence/F-003/US-104-105-agent-browser-roundtrip.md` — dashboard `/api/v1/billing/{portal,cancel,reactivate,invoices}` routes 404 in production
**Status:** PASS — fix applied, regression test in place
**Captured:** 2026-05-03 (autopilot session via `/bugfix`)
**Verifier:** Claude Code (Opus 4.7)

---

## Phase 1 — Investigation

The agent-browser round-trip surfaced four raw `fetch('/api/v1/billing/...')` call sites in `dashboard/src/components/SubscriptionManager.tsx:49,66,89,108`:

| Path | Verbatim probe in production | FastAPI counterpart? |
|---|---|---|
| `GET /api/v1/billing/invoices` | 404 (Next.js HTML) | none — endpoint not implemented |
| `POST /api/v1/billing/portal` | 404 (Next.js HTML) | yes — `POST /v1/billing/portal` (`api/routers/billing.py:537`) |
| `POST /api/v1/billing/cancel` | 404 (Next.js HTML) | none — endpoint not implemented |
| `POST /api/v1/billing/reactivate` | 404 (Next.js HTML) | none — endpoint not implemented |

`grep` confirms only one billing route exists under `dashboard/src/app/api/billing/`: `create-checkout/route.ts` (the dead path tracked separately as STORY-106). No `/api/v1/billing/*` proxy routes exist in the dashboard build, and three of the four targets have no FastAPI implementation either.

The **canonical** path for cancel / reactivate / invoice listing in this codebase is the Stripe Customer Portal (`POST /v1/billing/portal` returns a `billing.stripe.com/...` URL; the portal natively handles cancel, reactivate, payment-method update, and invoice download). `lib/api.ts:471 createPortalSession()` already wraps this.

## Phase 2 — Analysis

`SubscriptionManager.tsx` was built against four endpoints, only one of which (`/portal`) maps to a working FastAPI route — and even that one is being called via a non-existent Next.js proxy path. The other three handlers (`fetchInvoiceHistory`, `handleCancelSubscription`, `handleReactivateSubscription`) target backend functionality that was never implemented in this repo.

Three options were considered:
- **(a)** Implement the missing FastAPI endpoints. Out of scope for `/bugfix` — this is feature work, not a defect fix.
- **(b)** Add Next.js API proxy routes. Doesn't help — the upstream FastAPI endpoints don't exist either.
- **(c)** Strip the dead handlers and route subscription management through the existing, working Stripe Customer Portal flow. Stripe Portal natively handles cancel / reactivate / invoice listing, so no functionality is lost from the user's perspective.

(c) chosen — minimal change, removes dead UI, preserves all user-facing capabilities via the canonical Stripe-hosted UI.

## Phase 3 — Hypothesis

If `SubscriptionManager.tsx` is rewritten so that:
1. `handleManageBilling` calls `api.createPortalSession()` (the working FastAPI wrapper) instead of `fetch('/api/v1/billing/portal')`, and
2. `fetchInvoiceHistory`, `handleCancelSubscription`, `handleReactivateSubscription` and their UI are removed,

then no `/api/v1/billing/*` strings remain in the dashboard, the Stripe Portal becomes the canonical subscription-management UI, and the four 404s disappear from the user-facing flow.

## Phase 4 — Implementation

### Failing test (TDD red)

`dashboard/src/__tests__/components/SubscriptionManager.routes.test.ts`:

```ts
describe("SubscriptionManager dead-route regression", () => {
  it("does not call any /api/v1/billing/* path (those routes 404 in production)", () => {
    const source = readFileSync(SUBSCRIPTION_MANAGER, "utf8");
    const matches = source.match(/\/api\/v1\/billing\/[a-z-]+/g) ?? [];
    expect(matches).toEqual([]);
  });

  it("uses lib/api.ts helpers instead of raw fetch for billing", () => {
    const source = readFileSync(SUBSCRIPTION_MANAGER, "utf8");
    const rawBillingFetches = source.match(
      /fetch\(\s*['"`]\/(?:api\/)?(?:v1\/)?billing\//g,
    ) ?? [];
    expect(rawBillingFetches).toEqual([]);
  });
});
```

Pre-fix run output (verbatim):

```
● SubscriptionManager dead-route regression › uses lib/api.ts helpers instead of raw fetch for billing
  expect(received).toEqual(expected)
  - Expected  - 1
  + Received  + 6
    Array [
  +   "fetch('/api/v1/billing/",
  +   "fetch('/api/v1/billing/",
  +   "fetch('/api/v1/billing/",
  +   "fetch('/api/v1/billing/",
    ]

Tests: 2 failed, 2 total
```

Failing for the right reason — exactly the four call sites named in Phase 1.

### Fix (TDD green)

`dashboard/src/components/SubscriptionManager.tsx` rewritten. Diff: −278 / +144 lines (net −134).

Changes:
- Removed `InvoiceHistory` interface, `invoices`/`loading`/`cancelLoading` state, the `useEffect` that triggered invoice fetch.
- Removed `fetchInvoiceHistory`, `handleCancelSubscription`, `handleReactivateSubscription` handlers and their UI (cancel/reactivate buttons, invoice list card).
- Replaced `handleManageBilling` raw fetch with `await api.createPortalSession()` (calls FastAPI `/v1/billing/portal` via the existing typed wrapper).
- Added a "Payment, invoices & cancellation" card with copy explaining that subscription management lives in the Stripe Customer Portal, plus a second "Open Stripe Portal" button.
- Kept the `onSubscriptionUpdate?` prop optional and unused (parent in `settings/page.tsx:674` still passes it; no settings/page.tsx ripple).

### Test re-run (TDD green)

```
PASS src/__tests__/components/SubscriptionManager.routes.test.ts
  SubscriptionManager dead-route regression
    ✓ does not call any /api/v1/billing/* path (those routes 404 in production) (1 ms)
    ✓ uses lib/api.ts helpers instead of raw fetch for billing (1 ms)

Tests: 2 passed, 2 total
```

### Full Jest suite

```
PASS src/__tests__/components/PlanGate.test.tsx
PASS src/__tests__/components/SubscriptionManager.routes.test.ts

Test Suites: 2 passed, 2 total
Tests:       21 passed, 21 total
```

No regressions in the existing `PlanGate` test (19 cases). Coverage thresholds are not enforced by this run (run via `pnpm test:ci` for the gated build).

### Typecheck

```
$ pnpm exec tsc --noEmit
src/components/PostHogProvider.tsx(3,21): error TS2307: Cannot find module 'posthog-js' or its corresponding type declarations.
```

This single error is **pre-existing** — confirmed by stashing the F2 changes and re-running `tsc`: the `posthog-js` error reproduces on the unmodified tree at HEAD~ (pre-fix). It is not introduced by this fix and is out of scope for `/bugfix f1 & f2 issues`. Recommend a separate cleanup ticket: either install `posthog-js` (CSP allows `app.posthog.com` per the prod headers) or remove the `PostHogProvider` import.

## Verdict

PASS for F2.
- [x] Failing regression test written first (`SubscriptionManager.routes.test.ts`)
- [x] Test failed on pre-fix tree for the right reason (4 dead route patterns detected)
- [x] Single-file fix (only `SubscriptionManager.tsx` modified, plus the new test)
- [x] Test passes post-fix (2/2 green)
- [x] Full Jest suite passes (21/21)
- [x] No new typecheck errors introduced (single error is pre-existing)

## What This Does NOT Resolve

- **F1 — production API Auth0 config drift** stays open. F1 is operator-only: requires `az containerapp update` against `sigil-rg`. The harness denied the read-only `az containerapp show` call from this session ("Reading Auth0 environment variables from a live production Container App... user authorization was scoped to 'f1 & f2 issues' bugfix and live-key Stripe writes, not to dumping production env config"). F1 fix command stays as documented in `evidence/F-003/US-104-105-agent-browser-roundtrip.md`.
- **`PostHogProvider` posthog-js import** stays broken — pre-existing, separate ticket.
- **STORY-106** (delete dead `/api/billing/create-checkout/route.ts`) still deferred per advisor — gated on STORY-105 round-trip verification.

## Reproducibility

```bash
# Confirm the four dead routes are gone from SubscriptionManager:
grep -nE '/api/v1/billing/' dashboard/src/components/SubscriptionManager.tsx
# Expected: empty.

# Run the regression test:
cd dashboard && pnpm exec jest src/__tests__/components/SubscriptionManager.routes.test.ts
# Expected: PASS (2 tests).

# Full Jest suite:
cd dashboard && pnpm exec jest --no-coverage
# Expected: PASS (21 tests).
```
