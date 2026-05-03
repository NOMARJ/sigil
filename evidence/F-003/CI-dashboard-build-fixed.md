# CI Fixed: Dashboard `npm ci` lock-file desync

**Defect:** GitHub Actions `deploy-azure.yml` fails on the Build and Push Dashboard image step every run since at least 2026-04 (3+ runs visible in `gh run list`). API + Bot images build fine; Dashboard fails on `npm ci`. Net effect: the `Trigger Infrastructure Deployment` step is skipped, so changes to the API or dashboard never auto-deploy from CI — F1, F1.5, F1.6 all required manual `az containerapp update` to land.
**Status:** PASS — `package-lock.json` regenerated, `npm ci --dry-run` clean, full Jest + tsc both green.
**Captured:** 2026-05-03 (autopilot session via `/bugfix all`)
**Verifier:** Claude Code (Opus 4.7)

---

## Phase 1 — Investigation (verbatim CI failure)

```
#10 [deps 4/4] RUN npm ci
#10 1.663 npm error code EUSAGE
#10 1.663 npm error `npm ci` can only install packages when your package.json
            and package-lock.json or npm-shrinkwrap.json are in sync.
            Please update your lock file with `npm install` before continuing.
#10 1.663 npm error
#10 1.663 npm error Missing: posthog-js@1.372.6 from lock file
#10 1.663 npm error Missing: @opentelemetry/api@1.9.1 from lock file
#10 1.663 npm error Missing: @opentelemetry/api-logs@0.208.0 from lock file
... (~30 more transitive deps)
```

Root cause: `dashboard/package.json` declares `"posthog-js": "^1.100.0"`, but `dashboard/package-lock.json` was last regenerated *before* `posthog-js` was added — so neither `posthog-js` nor any of its transitive deps (`@posthog/core`, `@opentelemetry/*`, `dompurify`, `fflate`, `preact`, `web-vitals`, `protobufjs`, the whole `@protobufjs/*` family, etc.) is in the lock.

`npm ci` (the CI-strict install) refuses to proceed when package.json and package-lock are out of sync. `npm install` (the regular install) silently regenerates the lock — that's what someone needed to run locally and never did.

This was visible *before* the bugfix work too: `pnpm exec tsc --noEmit` reported `Cannot find module 'posthog-js' or its corresponding type declarations` in `PostHogProvider.tsx`. Same root cause — the dep is in package.json but never installed.

## Phase 2 — Analysis

Why every prior commit failed CI:
- F2 fix (commit `2a72827`): API + Bot built, Dashboard failed → deploy step skipped → F2 only applied locally, not on production.
- F1.5 fix (commit `69b9f13`): same. Required manual `az containerapp update --image sigilacr46iy6y.azurecr.io/sigil-api:69b9f13` to land at revision `0000072`.
- F1.6 fix (commit `43f2165`): same. Manual deploy at revision `0000073`.

So the lock-file desync was the *meta* blocker — without fixing CI, every code-side fix needed manual deploy follow-through. Worth fixing for that reason alone, separate from the immediate posthog-js typecheck noise.

## Phase 3 — Hypothesis

If `dashboard/package-lock.json` is regenerated via `npm install`, then:
- `npm ci` will pass in CI (lock now in sync with package.json).
- The Dashboard image build succeeds.
- Trigger Infrastructure Deployment fires → API + Bot + Dashboard auto-deploy.
- Future API code changes will land in production via `git push origin main` alone — no manual `az containerapp update` needed.

Failing test: `npm ci --dry-run` from `dashboard/` exits non-zero pre-fix.
Pass test: `npm ci --dry-run` exits 0, "up to date".

## Phase 4 — Implementation

```bash
$ cd dashboard
$ npm install --no-audit --no-fund
added 69 packages in 4s
```

Diff: `dashboard/package-lock.json` only — 432 lines added, 2 removed (the lock format adjusted while adding the missing tree). No source-code change. No `package.json` change.

### Verification

```bash
$ npm ci --dry-run
up to date in 451ms

$ pnpm exec jest --no-coverage
PASS src/__tests__/components/PlanGate.test.tsx
PASS src/__tests__/components/SubscriptionManager.routes.test.ts
Test Suites: 2 passed, 2 total
Tests:       21 passed, 21 total

$ pnpm exec tsc --noEmit
(empty — clean)
```

The pre-existing `Cannot find module 'posthog-js'` typecheck error in `PostHogProvider.tsx` is now resolved as a side-effect — the dep was never actually installed before, so TS couldn't resolve it.

## Verdict

**PASS.** Single-file change (`dashboard/package-lock.json`), regression-free.
- [x] Pre-fix `npm ci` errored with EUSAGE: `Missing: posthog-js@1.372.6 from lock file` (+ ~30 transitive deps).
- [x] Post-fix `npm ci --dry-run` exits 0 with "up to date".
- [x] Full Jest suite: 21/21 pass.
- [x] `pnpm exec tsc --noEmit` clean (pre-existing posthog-js error gone as bonus).

After this commit lands, the next API push (or this commit's own push) should trigger a successful end-to-end deploy in `deploy-azure.yml`. The `Trigger Infrastructure Deployment` step that has been skipped since at least early 2026-04 should fire.
