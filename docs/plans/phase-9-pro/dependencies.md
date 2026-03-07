# Phase 9 Pro LLM Detection - Dependencies

## Overview
Phase 9 Pro introduces advanced LLM-specific security detection as a paid tier feature ($29/month). This document maps all cross-subsystem dependencies required for implementation.

## Direct Dependencies

### 1. Billing System (REQUIRED - Partially Complete)
**Status:** ✅ Stripe integration exists, needs Pro tier configuration
- **Location:** `api/routers/billing.py`
- **Required Changes:**
  - Add Pro tier price IDs to config
  - Configure $29/month and $232/year pricing in Stripe
  - Test subscription upgrade/downgrade flows
- **Blocking:** Yes - cannot launch without payment processing

### 2. Authentication System (COMPLETE)
**Status:** ✅ Auth0 fully integrated
- **Location:** `api/routers/auth.py`, `api/services/auth_service.py`
- **Required Changes:** 
  - Add Pro tier claim to Auth0 user metadata
  - Update JWT validation to include tier check
- **Used For:** User identity and tier authorization

### 3. Base Scanner Engine (COMPLETE)
**Status:** ✅ Phases 1-6 fully operational
- **Location:** `api/scanner/`
- **Required Changes:**
  - Add Phase 7-8 modules
  - Implement tier-based feature gating
  - Add weighted scoring for new phases
- **Blocking:** No - extends existing functionality

### 4. Forge API (COMPLETE)
**Status:** ✅ 17,937 tools classified
- **Location:** `api/routers/forge.py`
- **Required Changes:**
  - Add SKILL.md detection endpoint
  - Link Pro tier to skill analysis
- **Used For:** Detecting AI skill files in repositories

## Indirect Dependencies

### 5. Database Schema (MSSQL)
**Status:** ✅ Azure SQL Database operational
- **Tables Affected:**
  - `subscriptions` - stores Stripe subscription data
  - `scan_results` - needs phase_7_findings, phase_8_findings columns
  - `audit_log` - tracks Pro feature usage
- **Stored Procedures Required:**
  - `sp_UpdateSubscription` - Update user subscription tier
  - `sp_GetUserTier` - Check user's current tier
  - `sp_LogProUsage` - Audit Pro feature usage
  - `sp_ProcessStripeWebhook` - Handle Stripe events
- **Migration Required:** Yes - `009_pro_tier_schema.sql`

### 6. Redis Cache
**Status:** ✅ Operational
- **Used For:**
  - Caching subscription tier (TTL: 5 minutes)
  - Storing phase 7-8 rule patterns
  - Rate limiting Pro API calls

### 7. CLI Tool
**Status:** ⚠️ Bash script, Rust migration planned
- **Location:** `bin/sigil`
- **Required Changes:**
  - Add `--pro` flag for forcing Pro detection
  - Check API key tier before scanning
  - Display upgrade prompts for free users

### 8. Dashboard UI
**Status:** ✅ Next.js app deployed
- **Location:** `dashboard/`
- **Required Changes:**
  - Add Pro features page
  - Update pricing page
  - Show Phase 7-8 findings in scan results
  - Add upgrade CTAs

## External Dependencies

### 9. Stripe
**Status:** ⚠️ Account exists, Pro tier not configured
- **Required Actions:**
  1. Create Pro product in Stripe Dashboard
  2. Set up $29/month price
  3. Set up $232/year price
  4. Configure webhook endpoint
  5. Add price IDs to environment variables

### 10. Email Service
**Status:** ❌ Not configured
- **Provider:** SendGrid or AWS SES recommended
- **Used For:**
  - Pro welcome emails
  - Subscription confirmations
  - Payment failure notifications
- **Blocking:** No - can launch without email

## Implementation Order

To minimize blockers:

1. **Week 1:** Core Detection Engine
   - Implement Phase 7-8 detection rules
   - Add SKILL.md parser
   - Test with sample data

2. **Week 1:** Stripe Configuration
   - Create Pro product and prices
   - Test payment flow
   - Configure webhooks

3. **Week 2:** API Integration
   - Add tier checking middleware
   - Gate Phase 7-8 behind Pro tier
   - Update scan endpoints

4. **Week 2:** User Experience
   - Update CLI with Pro features
   - Add dashboard Pro pages
   - Create pricing page

## Risk Mitigations

### Dependency Failures

**If Stripe configuration delays:**
- Launch with manual Pro tier activation
- Process payments manually initially
- Add automated billing in phase 2

**If email service not ready:**
- Use in-app notifications only
- Add email in post-launch update

**If Rust CLI not ready:**
- Ship with enhanced Bash script
- Prioritize Rust migration after launch

## Testing Requirements

### Integration Points
1. **Billing → MSSQL → Scanner:** Pro tier enables Phase 7-8
2. **Auth0 → Billing:** User subscription lookup via MSSQL
3. **Stripe → MSSQL:** Webhook updates subscription status
4. **Scanner → Forge:** SKILL.md file detection
5. **CLI → API → MSSQL:** Pro tier validation
6. **Dashboard → API:** Pro feature display with Auth0 claims

### End-to-End Flows
1. Free user → Upgrade → Pro scan → See results
2. Pro user → Cancel → Downgrade → Limited scan
3. CLI scan → Pro detection → Dashboard view

## Environment Variables

Required for Pro tier launch:

```bash
# Stripe (Production)
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
STRIPE_PRICE_PRO_MONTHLY=price_xxx
STRIPE_PRICE_PRO_ANNUAL=price_xxx

# Auth0
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=xxx
AUTH0_CLIENT_SECRET=xxx
AUTH0_AUDIENCE=https://api.sigilsec.ai

# MSSQL Database
SIGIL_DATABASE_URL=mssql+pyodbc://user:pass@server/database
SQL_SERVER=your-server.database.windows.net
SQL_DATABASE=sigil
SQL_USERNAME=sigil_admin
SQL_PASSWORD=xxx

# Feature Flags
ENABLE_PRO_TIER=true
PHASE_7_8_ENABLED=true

# Rate Limits
PRO_SCANS_PER_MONTH=1000
PRO_API_RATE_LIMIT=100/minute
```

## Monitoring

Key metrics to track:

1. **Conversion:** Free → Pro upgrade rate
2. **Usage:** Phase 7-8 detection runs per user
3. **Performance:** Scan latency with Pro features
4. **Revenue:** MRR, churn, LTV
5. **Errors:** Payment failures, tier check errors

## Rollback Plan

If Pro tier launch has issues:

1. Feature flag `ENABLE_PRO_TIER=false`
2. All scans revert to Phase 1-6 only
3. Refund any Pro subscriptions
4. Fix issues and re-launch

---

**Status Summary:**
- ✅ **Ready:** Auth0, Scanner (1-6), Forge, MSSQL Database, Redis, Dashboard
- ⚠️ **Needs Work:** Stripe setup, MSSQL stored procedures, CLI updates
- ❌ **Missing:** Email service (non-blocking)

**Estimated Timeline:** 9 days from start to production launch