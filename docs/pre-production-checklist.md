# Pre-Production Checklist

Date: 2026-06-08

Reassessed: 2026-06-09 01:05 UTC

## Verdict

NOT READY

## Must Pass Before Launch

- [x] Dashboard component tests pass: `41 passed`.
- [x] Dashboard production build succeeds.
- [x] Production API health returns 200 with database and Redis connected.
- [x] Production protected interactive route returns 401 instead of 404 when unauthenticated.
- [x] API tests pass: `223 passed, 339 skipped, 6 warnings`.
- [x] Rust CLI tests pass locally: `6 passed`.
- [x] Public signup path works. Current: `https://app.sigilsec.ai/signup` returns 200 and browser lands on `/login`.
- [x] Public pricing page matches billing API. Current: page shows 14-day trial, Pro `$29`, Team `$99`.
- [x] Public installer works. Current: `https://www.sigilsec.ai/install.sh` redirects to the GitHub raw installer.
- [x] Dashboard dependency audit has no high vulnerabilities. Current: `npm audit --audit-level=high --omit=dev` exits 0 after Next.js 16.2.7, React 19.2.1, and Auth0 SDK 4.22.0 migration.
- [ ] Browser validation passes for credentialed login, dashboard, mobile, and paid billing journeys.
- [ ] Owner-gated Stripe test/live round trips are complete.
- [ ] Residual moderate PostCSS advisory is accepted or remediated when a patched Next.js release is available.

## Next Actions

1. Run full credentialed browser journey validation against the Auth0 v4 routes.
2. Complete owner-gated Stripe test/live round trips.
3. Decide whether to accept the residual moderate PostCSS advisory until a patched Next.js release is available.
4. Resolve governance telemetry drift: `.nomark/metrics/trust/ledger.jsonl` is missing and `node scripts/mee-event.cjs cold-start` fails because `.nomark/schemas/mee-event.schema.json` is missing.
