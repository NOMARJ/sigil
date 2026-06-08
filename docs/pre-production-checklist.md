# Pre-Production Checklist

Date: 2026-06-08

Reassessed: 2026-06-08 03:33 UTC

## Verdict

NOT READY

## Must Pass Before Launch

- [x] Dashboard component tests pass: `41 passed`.
- [x] Dashboard production build succeeds.
- [x] Production API health returns 200 with database and Redis connected.
- [x] Production protected interactive route returns 401 instead of 404 when unauthenticated.
- [x] API tests pass: `223 passed, 339 skipped, 6 warnings`.
- [x] Rust CLI tests pass locally: `6 passed`.
- [ ] Public signup path works. Current: `https://app.sigilsec.ai/signup` returns 404.
- [ ] Public pricing page matches billing API. Current: page shows 30-day trial and `$199` Team; API says Team `$99`.
- [ ] Public installer works. Current: `https://www.sigilsec.ai/install.sh` says private development/public beta coming soon.
- [ ] Dashboard dependency audit has no high vulnerabilities. Current: Next.js high advisory remains.
- [ ] Browser validation passes for signup, login, pricing, dashboard, mobile, and invalid input journeys.
- [ ] Owner-gated Stripe test/live round trips are complete.

## Next Actions

1. Owner approval: fix `/signup` to route to existing Auth0 signup/login flow.
2. Operator action: deploy current public web source or repair the marketing surface serving `www.sigilsec.ai`.
3. Plan and execute the Next.js upgrade path instead of `npm audit fix --force`.
4. Run full browser journey validation after public acquisition paths are repaired.
5. Complete owner-gated Stripe test/live round trips.
