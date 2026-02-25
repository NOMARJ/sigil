# Phase 7: Go-to-Market Readiness

**Status: Not Ready for Paid Launch (5/10)**

---

## Pro Tier ($29/mo) Feature Parity

| Feature | Advertised | Implemented | Working E2E | Notes |
|---------|------------|-------------|-------------|-------|
| Cloud threat intelligence | ✅ | ✅ | ✅ | `/v1/threat/<hash>`, signature sync |
| 90-day scan history | ✅ | ⚠️ Schema exists | ❌ | No retention enforcement |
| Web dashboard | ✅ | ✅ Built | ❌ | Shows no data (P0) |
| `sigil login` → auth | ✅ | ✅ | ✅ CLI only | Dashboard OAuth broken |
| 500 scans/month | ✅ | ✅ | ✅ | Quota enforcement works |

**Pro verdict:** 2 of 5 features work end-to-end.

---

## Team Tier ($99/mo) Feature Parity

| Feature | Advertised | Implemented | Working E2E | Notes |
|---------|------------|-------------|-------------|-------|
| Team management | ✅ | ✅ | ⚠️ | API works, dashboard needs auth |
| Invite/roles | ✅ | ✅ | ⚠️ | API endpoints complete |
| Policy controls | ✅ | ✅ | ⚠️ | Allowlist, blocklist, auto-approve |
| CI/CD integration | ✅ | ✅ | ✅ | GitHub Actions works, GitLab template |
| Slack/webhook alerts | ✅ | ✅ | ⚠️ | API works, dashboard needs auth |
| 5,000 scans/month | ✅ | ✅ | ✅ | Quota enforcement works |
| 1-year scan history | ✅ | ⚠️ Schema exists | ❌ | No retention enforcement |

**Team verdict:** CI/CD and quotas work. Everything else blocked by dashboard/auth issues.

---

## Billing Integration

**Status: REAL (not stubbed)**

- Stripe checkout: Real `stripe.Subscription.create()` calls
- Customer portal: Real `stripe.billing_portal.Session.create()`
- Webhook handling: Listens to `customer.subscription.updated`, `payment_failed`, etc.
- Stub fallback: When `STRIPE_NOT_CONFIGURED`, creates mock subscriptions
- Plan catalog: 4 tiers with correct pricing

**What's needed:**
- Set `SIGIL_STRIPE_SECRET_KEY`, `SIGIL_STRIPE_WEBHOOK_SECRET`
- Create Stripe products/prices matching the price IDs
- Configure Stripe webhook endpoint URL

---

## Comparison Table Accuracy

The README comparison table claims:

| Feature | Sigil | Snyk | Socket | Semgrep |
|---------|-------|------|--------|---------|
| Pre-install quarantine | ✅ | ❌ | ❌ | ❌ |
| Supply-chain focus | ✅ | ⚠️ | ✅ | ❌ |
| Install hook scanning | ✅ | ❌ | ⚠️ | ❌ |
| Multi-ecosystem | ✅ | ✅ | ✅ | ✅ |

**Assessment:** Claims are accurate and defensible. Sigil's quarantine-first workflow is genuinely differentiated.

---

## GTM Blockers (Ranked by Impact)

### Must Fix for ANY Paid Launch

1. **Dashboard shows no data** — Users paying $29/mo expect to see their scan results
2. **OAuth broken** — Users can't sign up via GitHub (the expected flow)
3. **New users get empty experience** — FREE tier sees nothing, no trial, no upgrade path
4. **No working signup → scan → see results flow** — The entire value proposition is broken

### Must Fix for Team Launch

5. **Team dashboard views need auth working** — Team management is API-only today
6. **Policy dashboard needs working** — Policy management is API-only
7. **Alert configuration needs dashboard** — Alert setup is API-only

### Nice to Have for Launch

8. Marketing site (sigilsec.ai) — Not verified if live
9. IDE plugin marketplace listings — Ready to submit, just need approval
10. Enterprise SSO/SAML — Roadmap item

---

## Minimum Viable Pro Launch Punch List

1. [ ] Fix all 10 P0 issues (type mismatches, plan gating, auth)
2. [ ] Configure Supabase with correct OAuth settings
3. [ ] Deploy API with production JWT secret and env vars
4. [ ] Deploy Dashboard with Supabase env vars
5. [ ] Configure Stripe with real price IDs
6. [ ] Create onboarding flow: signup → trial Pro (14 days) → first scan
7. [ ] Test full flow: GitHub login → scan via CLI → see results in dashboard
8. [ ] Ship VS Code extension to marketplace
9. [ ] Update docs to reflect working dashboard
10. [ ] Set up monitoring/alerting for API health
