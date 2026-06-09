# Known Risks

Date: 2026-06-08

Reassessed: 2026-06-09 01:05 UTC

Reconciled: 2026-06-09 — each item below cross-checked against fresh live probes and repo source. Prior live/source divergences for signup, pricing, and installer are now cleared.

## Critical

No active critical public-route risk remains from the June 9 reassessment.

## High

1. Paid billing journeys remain unverified.
   - Evidence: no fresh credentialed Stripe test/live round-trip evidence was produced in this reassessment.
   - Approval: owner/operator required for checkout, webhook, portal cancel, live payment, and refund evidence.

## Medium

1. Dashboard dependency audit still has moderate PostCSS findings nested under Next.js.
   - Evidence: `npm audit --audit-level=high --omit=dev` exits 0, but plain audit still reports 2 moderate PostCSS findings under `next@16.2.7`.
   - **Status (2026-06-09): HIGH CLEARED, MODERATE OPEN.** Do not run the suggested `npm audit fix --force`; it proposes an invalid downgrade to `next@9.3.3`.
2. Live CSP still references legacy Cakewalk domains.
   - **Status (2026-06-08): NEEDS OWNER SIGN-OFF — Vercel platform config.**
     The CSP (`*.cakewalk.ai`, `cw-ai-prod.s3...`, `api.cakewalk.ai`) is set
     at the Vercel project level, not in git — there is no `vercel.json`,
     `middleware.ts`, or `headers()` block in `dashboard/`. It is fixable by
     adding an explicit `headers()` CSP to `next.config.js`, but doing so on a
     guess risks breaking the live site, since the full intended allowlist is
     unknown. Owner must supply the intended policy; change then needs a
     deploy. See `evidence/F-003/US-108-cdn-investigation.md`.
3. Dashboard build emits image/font optimization warnings.
   - **Status (2026-06-08): UNCHANGED — not yet triaged.**
4. `brew info sigil` resolves to an unrelated ebook-editor cask unless the tap-qualified `nomarj/tap/sigil` formula is used.
   - **Status (2026-06-08): FIXED IN SOURCE (docs).** Root cause of the
     wrong-cask resolution was `README.md` advertising the un-qualified
     `brew install nomarj/sigil` (missing `/tap`); corrected to
     `brew install nomarj/tap/sigil`. Note: a global `nomark` vs `nomarj`
     org-name inconsistency remains across docs (e.g.
     `SIGIL-DISTRIBUTION-ROADMAP.md`) — flagged for owner, not mass-edited
     here to avoid guessing the canonical org.

## Cleared In Reassessment

1. Public signup route no longer returns 404.
   - Evidence: `curl -I https://app.sigilsec.ai/signup` -> `HTTP/2 200`; Playwright lands on `https://app.sigilsec.ai/login`.

2. Public pricing now matches the billing API for visible Pro/Team price and trial copy.
   - Evidence: pricing browser probe has `has14DayTrial=true`, `hasTeam99=true`, `hasTeam199=false`, `has30DayTrial=false`.

3. Public installer now serves the real installer via redirect.
   - Evidence: `curl -I https://www.sigilsec.ai/install.sh` -> `HTTP/2 307` to `https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh`; `curl -sSL` returns `#!/usr/bin/env sh`.

4. Full API suite now passes locally.
   - Evidence: `223 passed, 339 skipped, 6 warnings`.

5. Rust CLI can be verified locally.
   - Evidence: `cargo test --manifest-path cli/Cargo.toml` -> `6 passed`.

6. Dashboard high-severity dependency audit blocker is cleared.
   - Evidence: `npm ci`, `npm run lint`, `npx tsc --noEmit`, `npm test -- --runInBand`, `npm run build`, and `npm audit --audit-level=high --omit=dev` all exit 0 after the Auth0 v4/Next 16 migration.
