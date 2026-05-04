# US-106: Dead `create-checkout` Route Removed

**Story:** STORY-106 / NOM-888
**Feature:** F-003 Pro Billing + Tier Gating Verification
**Date:** 2026-05-04

## Objective

Delete `dashboard/src/app/api/billing/create-checkout/route.ts` — an unreferenced stub that returned fabricated `cs_test_<tier>_<cycle>_<ts>` Stripe checkout URLs with zero real callers.

---

## Pre-deletion state

### Caller check (pre)

```
$ grep -rn '/api/billing/create-checkout' dashboard/src
(no output)
$ echo $?
1
```

Zero callers confirmed. Safe to delete.

### Build (pre) — exit 0

```
$ pnpm --dir dashboard build
> sigil-dashboard@0.1.0 build
> next build

  ▲ Next.js 14.2.35

 ✓ Compiled successfully
 ✓ Linting and checking validity of types
 ✓ Collecting page data
 ✓ Generating static pages (33/33)
 ✓ Collecting build traces
 ✓ Finalizing page optimization

Route (app)
...
├ ƒ /api/billing/create-checkout          0 B                0 B   ← present
...
```

---

## Action taken

```
rm dashboard/src/app/api/billing/create-checkout/route.ts
rmdir dashboard/src/app/api/billing/create-checkout
```

---

## Post-deletion state

### Caller check (post)

```
$ grep -rn '/api/billing/create-checkout' dashboard/src
(no output)
$ echo $?
1
```

Still zero — route is gone and nothing referenced it.

### Build (post) — exit 0

```
$ pnpm --dir dashboard build
> sigil-dashboard@0.1.0 build
> next build

  ▲ Next.js 14.2.35

 ✓ Compiled successfully
 ✓ Linting and checking validity of types
 ✓ Collecting page data
 ✓ Generating static pages (32/32)   ← one fewer route
 ✓ Collecting build traces
 ✓ Finalizing page optimization

Route (app)
┌ ○ /
├ ○ /_not-found
├ ○ /analytics
├ ƒ /api/auth/[auth0]
├ ƒ /api/auth/me
├ ƒ /api/auth/token
├ ƒ /api/onboarding/complete
├ ƒ /api/onboarding/complete-step
├ ƒ /api/onboarding/generate-key
...
```

`/api/billing/create-checkout` is absent from the route table.

---

## Regression check

US-005 step-4 re-probe (real Stripe checkout path via `POST /v1/billing/subscribe`) remains unaffected — that flow goes directly to the Python API (`api/routers/billing.py`) and never touched the now-deleted Next.js stub.

---

## Done-when checklist

- [x] File `dashboard/src/app/api/billing/create-checkout/route.ts` deleted
- [x] `grep -rn '/api/billing/create-checkout' dashboard/src` exits 1 (no matches)
- [x] `pnpm --dir dashboard build` exits 0
- [x] Evidence recorded here
- [x] No fabricated `cs_test_<tier>_<cycle>_<ts>` URL can be returned from any production code path
