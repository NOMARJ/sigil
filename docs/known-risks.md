# Known Risks

Date: 2026-06-08

Reassessed: 2026-06-08 03:33 UTC

Reconciled: 2026-06-08 — each item below cross-checked against repo source.
Several "risks" describe **live production state that diverges from this
repo** (an externally-deployed marketing site and Vercel platform config),
so they are not fixable by a code change here. Status annotated per item.

## Critical

1. Public signup route returns 404.
   - Evidence: `curl -I https://app.sigilsec.ai/signup` -> `HTTP/2 404`.
   - Approval: owner required because this touches auth flow.
   - **Status (2026-06-08): FIXED IN SOURCE — pending deploy.** Root cause:
     the App Router had no `/signup` route; auth was reachable only via
     `/login`. Added `dashboard/src/app/signup/page.tsx` redirecting to
     `/api/auth/signup`, and a `signup` handler in the `[auth0]` route that
     issues Auth0 Universal Login with `screen_hint=signup`. Regression test:
     `dashboard/src/__tests__/app/signup.route.test.ts` (2 passing). Resolves
     once the dashboard redeploys.

2. Public pricing page is stale and contradicts billing API.
   - Evidence: browser probe shows 30-day trial and `$199` Team, while `/v1/billing/plans` returns Team `$99`.
   - Approval: operator/owner deployment required.
   - **Status (2026-06-08): NOT FIXABLE IN THIS REPO — external + tracked
     under F-003.** This repo's source is already correct: `api/routers/billing.py`
     returns Team `$99/mo` with a 14-day trial (`_TRIAL_PERIOD_DAYS = 14`),
     and `dashboard/src/app/pricing/page.tsx` renders prices dynamically from
     the API (no hardcoded `$199`/`30-day`). The stale `$199`/`30-day` copy
     lives on the externally-deployed marketing site (`www.sigilsec.ai`),
     which is **not in this repository** (`sigilsec/` contains only an admin
     page). Reconciliation is already tracked under F-003;
     `tasks/prd-launch-readiness.json` explicitly says do not duplicate.

3. Public installer URL serves private-development script.
   - Evidence: `curl https://www.sigilsec.ai/install.sh` prints "public CLI beta is coming soon".
   - Approval: operator/owner deployment required.
   - **Status (2026-06-08): NOT FIXABLE IN THIS REPO — external.** The
     repo's `install.sh` is the correct, functional installer (no "coming
     soon" text), and the dashboard (`app.sigilsec.ai`) already redirects
     `/install.sh` to the GitHub raw script (`dashboard/next.config.js`). The
     "coming soon" response is served by the external `www.sigilsec.ai`
     marketing site, which is not in this repository. Fix requires updating
     that site's deployment to serve the repo `install.sh`.

## High

1. Dashboard dependency audit remains high due to Next.js advisories.
   - Evidence: `npm audit --audit-level=high --omit=dev` exits 1.
   - Approval: planned framework upgrade required.
   - **Status (2026-06-08): UNCHANGED — out of scope for a bugfix.** Requires
     a Next.js major-version upgrade, not a minimal patch. Tracked separately.

## Medium

1. Live CSP still references legacy Cakewalk domains.
   - **Status (2026-06-08): NEEDS OWNER SIGN-OFF — Vercel platform config.**
     The CSP (`*.cakewalk.ai`, `cw-ai-prod.s3...`, `api.cakewalk.ai`) is set
     at the Vercel project level, not in git — there is no `vercel.json`,
     `middleware.ts`, or `headers()` block in `dashboard/`. It is fixable by
     adding an explicit `headers()` CSP to `next.config.js`, but doing so on a
     guess risks breaking the live site, since the full intended allowlist is
     unknown. Owner must supply the intended policy; change then needs a
     deploy. See `evidence/F-003/US-108-cdn-investigation.md`.
2. Dashboard build emits image/font optimization warnings.
   - **Status (2026-06-08): UNCHANGED — not yet triaged.**
3. `brew info sigil` resolves to an unrelated ebook-editor cask unless the tap-qualified `nomarj/tap/sigil` formula is used.
   - **Status (2026-06-08): FIXED IN SOURCE (docs).** Root cause of the
     wrong-cask resolution was `README.md` advertising the un-qualified
     `brew install nomarj/sigil` (missing `/tap`); corrected to
     `brew install nomarj/tap/sigil`. Note: a global `nomark` vs `nomarj`
     org-name inconsistency remains across docs (e.g.
     `SIGIL-DISTRIBUTION-ROADMAP.md`) — flagged for owner, not mass-edited
     here to avoid guessing the canonical org.

## Cleared In Reassessment

1. Full API suite now passes locally.
   - Evidence: `223 passed, 339 skipped, 6 warnings`.

2. Rust CLI can be verified locally.
   - Evidence: `cargo test --manifest-path cli/Cargo.toml` -> `6 passed`.
