# Pre-Production Checklist

Date: 2026-06-08

## Verdict

NOT READY

## Must Pass Before Launch

- [x] Dashboard component tests pass: `41 passed`.
- [x] Dashboard production build succeeds.
- [x] Production API health returns 200 with database and Redis connected.
- [x] Production protected interactive route returns 401 instead of 404 when unauthenticated.
- [ ] Public signup path works. Current: `https://app.sigilsec.ai/signup` returns 404.
- [ ] Public pricing page matches billing API. Current: page shows 30-day trial and `$199` Team; API says Team `$99`.
- [ ] Public installer works. Current: `https://www.sigilsec.ai/install.sh` says private development/public beta coming soon.
- [ ] API tests pass. Current: `25 failed, 31 errors`.
- [ ] Dashboard dependency audit has no high vulnerabilities. Current: Next.js high advisory remains.
- [ ] Rust CLI build/test can run. Current: no Rust toolchain configured.
- [ ] Browser validation passes for signup, login, pricing, dashboard, mobile, and invalid input journeys.
- [ ] Owner-gated Stripe test/live round trips are complete.

## Next Actions

1. Owner approval: fix `/signup` to route to existing Auth0 signup/login flow.
2. Operator action: deploy current public web source or repair the marketing surface serving `www.sigilsec.ai`.
3. Owner approval: address API test failures that touch auth/database behavior.
4. Plan Next.js upgrade path instead of `npm audit fix --force`.
5. Install/configure Rust toolchain and run CLI verification.
