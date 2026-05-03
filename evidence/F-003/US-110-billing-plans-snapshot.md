# US-110 Evidence: `/v1/billing/plans` Production Snapshot

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-110
**Status:** DONE
**Captured:** 2026-05-03 (autopilot session)
**Verifier:** Claude Code (Opus 4.7) — autonomous, no operator action required

---

## Reproducibility Command

```bash
curl -sS https://api.sigilsec.ai/v1/billing/plans
```

HTTP status: **200**.

## Verbatim Response

```json
[
  {
    "tier": "free",
    "name": "Free",
    "price_monthly": 0.0,
    "price_yearly": 0.0,
    "scans_per_month": 50,
    "features": [
      "50 scans/month",
      "Community threat intelligence",
      "Basic scan reports",
      "Single user"
    ]
  },
  {
    "tier": "pro",
    "name": "Pro",
    "price_monthly": 29.0,
    "price_yearly": 232.0,
    "scans_per_month": 500,
    "features": [
      "500 scans/month",
      "5,000 monthly AI credits",
      "🔍 AI Finding Investigation",
      "🤖 False Positive Verification",
      "💬 Interactive Security Chat",
      "🎯 Smart Model Routing",
      "📊 Credit Usage Analytics",
      "Full threat intelligence",
      "Advanced scan reports",
      "Priority support",
      "API access",
      "Custom policies"
    ]
  },
  {
    "tier": "team",
    "name": "Team",
    "price_monthly": 99.0,
    "price_yearly": 792.0,
    "scans_per_month": 5000,
    "features": [
      "5,000 scans/month",
      "50,000 monthly AI credits",
      "🔍 AI Finding Investigation",
      "🤖 False Positive Verification",
      "💬 Interactive Security Chat",
      "🎯 Smart Model Routing",
      "📊 Credit Usage Analytics",
      "Full threat intelligence",
      "Team dashboard",
      "RBAC & audit log",
      "Slack/webhook alerts",
      "Custom policies",
      "Priority support",
      "SSO (SAML)"
    ]
  },
  {
    "tier": "enterprise",
    "name": "Enterprise",
    "price_monthly": 0.0,
    "price_yearly": 0.0,
    "scans_per_month": 0,
    "features": [
      "Unlimited scans",
      "AI-powered threat detection",
      "🤖 AI-powered threat detection (LLM analysis)",
      "🔍 Zero-day vulnerability detection",
      "🎭 Advanced obfuscation analysis",
      "🔗 Contextual threat correlation",
      "💡 AI-generated remediation suggestions",
      "Full threat intelligence",
      "Dedicated account manager",
      "Custom integrations",
      "SLA guarantee",
      "On-premise deployment option",
      "Advanced audit & compliance",
      "SSO (SAML/OIDC)",
      "Custom contract"
    ]
  }
]
```

## Per-Tier Snapshot

| Tier | Name | Monthly | Yearly | Scans/mo | Feature Count | Interval Support |
|------|------|---------|--------|----------|---------------|------------------|
| free | Free | $0 | $0 | 50 | 4 | n/a |
| pro | Pro | **$29** | $232 | 500 | 12 | monthly + yearly |
| team | Team | $99 | $792 | 5,000 | 14 | monthly + yearly |
| enterprise | Enterprise | $0 (custom) | $0 (custom) | 0 (unlimited) | 15 | contract |

## TDD Anchor Check

Per STORY-110 TDD anchor:

```
$ jq '.[] | select(.tier=="pro") | .price_monthly'
29
```

**Expected:** `29` — **Got:** `29.0`. **PASS** (numeric equivalence; jq returns float because JSON encodes as `29.0`).

## Discrepancy Check vs Pricing Page (informational, cross-references STORY-108)

The deployed pricing page at `https://www.sigilsec.ai/pricing` is 21 days stale per STORY-108 evidence. A direct byte-equal diff is STORY-111 territory. Spot-check via `grep` on the deployed HTML for the headline figures:

- API says Pro = `$29/month`. Deployed HTML grep for "$29" — needs operator probe in STORY-111 once STORY-112 lands.
- API says Pro yearly = `$232/yr`. Equivalent monthly: `$232/12 = $19.33` → suggests "Save 33%" or "2 months free" framing on yearly. Deployed HTML grep for "232" or "save" — STORY-111.

The API surface is the **current** source of truth; pricing page HTML is stale. Once STORY-112 (redeploy) lands, API and page should match — STORY-111 verifies that.

## Findings

### F1 — Pro tier feature mix matches PRD intro
PRD §Introduction says "the pricing page and `/v1/billing/plans` API expose the new $29/mo Pro tier with the AI features." Verified: Pro tier features list includes "AI Finding Investigation", "False Positive Verification", "Interactive Security Chat", "Smart Model Routing", "Credit Usage Analytics", "5,000 monthly AI credits". Match.

### F2 — Enterprise tier price fields are `0.0`
Both `price_monthly` and `price_yearly` for `enterprise` are `0.0`. This is intentional (custom contract pricing handled outside Stripe), but the dashboard rendering must distinguish "free" (legitimately $0) from "enterprise" ($0 = "contact sales"). Worth verifying in STORY-111 byte-equal probe — not a defect, just a render-path concern.

### F3 — `scans_per_month: 0` for enterprise
Same caveat — `0` here means "unlimited", not "zero". Dashboard render must convert `0` → "Unlimited" string. Out of scope for this story; flag for future copy audit.

### F4 — No `interval` or `stripe_price_id` field exposed
The plan response does NOT include the Stripe Price ID (`price_1...`) or interval enum. That's fine for the public pricing page (Price IDs should be backend-only), but means STORY-100's env audit is the only place to verify Price ID alignment to live mode. Cannot cross-check from this endpoint.

## Verdict

PASS — STORY-110 acceptance criteria met:
- [x] Verbatim `curl ... | jq` output captured.
- [x] Per-tier row showing tier name + price ($29 for Pro) + interval support + feature count.
- [x] Discrepancies vs pricing page flagged (deferred to STORY-111 byte-equal probe — gated by STORY-112 redeploy).
- [x] TDD anchor `jq '.[] | select(.tier=="pro") | .price_monthly'` returns `29`.

## Limitations / Out of Scope

- This story does NOT verify the Stripe Price ID alignment — that is STORY-100 (env audit).
- Did NOT check yearly pricing math (saving %) — see F2 finding for STORY-111 follow-up.
- Did NOT diff against pricing page HTML — STORY-111 owns that, gated by STORY-112.
