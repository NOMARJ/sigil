# Known Risks

Date: 2026-06-08

Reassessed: 2026-06-09 01:05 UTC

Reassessed: 2026-06-25 — F-008/F-009/F-010 cleared items added; billing risk entry updated to reflect live-mode webhook verified, test-mode still operator-gated (NOM-884).

Reconciled: 2026-06-09 — each item below cross-checked against fresh live probes and repo source. Prior live/source divergences for signup, pricing, and installer are now cleared.

## Critical

No active critical public-route risk remains from the June 9 reassessment.

## High

1. Paid billing journeys partially verified — test-mode round-trip still operator-gated.
   - Live-mode webhook endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` verified at 6/6 required events (STORY-101 — see `evidence/F-003/US-101-fix-applied.md`).
   - Test-mode webhook audit (NOM-884/US-003) remains operator-gated: Stripe CLI is configured for the wrong account (`acct_1TNsZTFvlPr69lA2` = exectables, not Sigil), and reading test secrets from Azure Key Vault is blocked by CHARTER II.5. Operator runbook is documented in `evidence/F-003/US-105a-test-mode-webhook-audit.md` (Option B: 30 seconds via Stripe Dashboard → Test mode → Developers → Webhooks).
   - Approval: owner/operator required to complete test-mode audit and for full end-to-end checkout, portal cancel, live payment, and refund evidence.

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

## Cleared Post-June-9 (F-008 / F-009 / F-010)

Reassessed: 2026-06-25. Items below cleared after June 9 baseline and confirmed in `.nomark/resources.json` and production revision history.

1. Sandbox fail-closed (F-008 BadHost fix) — CLEARED.
   - Evidence: production revision `sigil-api--0000096` deployed the sandbox fail-closed fix. Any unknown scheme (including `BadHost://`) now raises a hard error rather than silently passing to the host OS. CHARTER II.4 compliance confirmed.

2. Dashboard auth hardening (F-008) — CLEARED.
   - Evidence: Auth0 SDK migration from v3 to v4 complete (2026-06-09); `npm audit --audit-level=high --omit=dev` exits 0 on dashboard. High-severity auth vulnerability cleared.

3. Release hardening (F-008) — CLEARED.
   - Evidence: commit signing, dependency pinning, and SBOM generation phases of F-008 complete. All 7 phases A–G shipped.

4. Live-mode Stripe webhook (F-009 STORY-101) — CLEARED.
   - Evidence: `we_1T2AXKFhPhxEz27fCYP53mKc` confirmed at 6/6 required events: `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_succeeded`, `invoice.payment_failed`. See `evidence/F-003/US-101-fix-applied.md`.

5. Auth0 v4 migration (F-009) — CLEARED.
   - Evidence: Auth0 v4 client deployed to `sigil-api--0000108` (image tag `2eff98f`). Domain remains `auth.sigilsec.ai` (verified in `.nomark/resources.json`).

6. Pro/Team billing plans deployed (F-009) — CLEARED.
   - Evidence: `/v1/billing/plans` pricing matches public pricing page. Pro $29/mo, Team $99/mo, 14-day trial. Revision `sigil-api--0000108`.

7. Trust-ledger allowlisting (F-010) — CLEARED.
   - Evidence: all 3 F-010 stories DONE. Allowlist enforcement + trust-ledger storage operational.

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
