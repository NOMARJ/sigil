# Phase 9 Pro LLM Detection - Agent Team Implementation Plan

## Executive Summary

This document outlines the parallel execution strategy for implementing Phase 9 Pro LLM Detection, Sigil's $29/month Pro tier featuring AI-powered threat detection. The team consists of 5 specialized agents working in parallel across 4 implementation phases.

## Team Structure

### 1. Backend Engineer Agent
**Owner:** LLM Integration & Detection Engine  
**Files Owned:**
- `api/scanner/` (to be created)
- `api/services/llm_service.py` (new)
- `api/services/context_analyzer.py` (new)
- `api/services/threat_correlator.py` (new)
- `api/prompts/` (to be created)
- `api/models/llm_models.py` (new)

**Assigned Stories:**
- US-001: Add Phase 9 LLM detection to scanner API (10 hours)
- US-002: Implement LLM service integration (8 hours)
- US-005: Create LLM prompt templates (6 hours)
- US-006: Add contextual threat intelligence (6 hours)

**Key Responsibilities:**
- Integrate OpenAI/Azure OpenAI for threat analysis
- Design prompt engineering for security detection
- Implement contextual code analysis
- Create threat correlation engine

### 2. Database Engineer Agent
**Owner:** MSSQL/Azure SQL Database Layer  
**Files Owned:**
- `api/database/*.sql` (stored procedures)
- `api/migrations/` (schema updates)
- Database connection configurations

**Assigned Stories:**
- US-003: Database components for tier checking (2 hours)
- US-004: Subscription management procedures (2 hours)

**Key Responsibilities:**
- Create subscription management stored procedures
- Implement tier verification queries
- Design audit logging schema
- Optimize database performance for Pro features

### 3. Billing Engineer Agent
**Owner:** Stripe Integration & Subscription Management  
**Files Owned:**
- `api/routers/billing.py` (existing)
- `api/middleware/tier_check.py` (new)
- `api/services/subscription_service.py` (new)
- `api/services/stripe_service.py` (new)
- `api/services/analytics_service.py` (new)

**Assigned Stories:**
- US-003: API tier checking implementation (2 hours)
- US-004: Stripe checkout and webhook flow (2 hours)
- US-009: Usage tracking for Pro features (3 hours)

**Key Responsibilities:**
- Implement Stripe checkout for $29/month
- Create subscription webhook handlers
- Build tier verification middleware
- Track Pro feature usage metrics

### 4. Frontend Engineer Agent
**Owner:** Dashboard UI & User Experience  
**Files Owned:**
- `dashboard/src/app/pro/` (new)
- `dashboard/src/app/pricing/` (update)
- `dashboard/src/app/onboarding/pro/` (new)
- `dashboard/src/components/ProFeatures.tsx` (new)
- `dashboard/src/components/PricingCard.tsx` (update)

**Assigned Stories:**
- US-008: Pro features dashboard page (5 hours)
- US-010: Pricing page updates (2 hours)
- US-011: Pro onboarding flow (3 hours)

**Key Responsibilities:**
- Build Pro features UI showing LLM insights
- Update pricing page with Pro tier
- Create onboarding flow for new Pro users
- Implement upgrade CTAs for free users

### 5. Integration Engineer Agent
**Owner:** CLI Integration & Testing Suite  
**Files Owned:**
- `bin/sigil` (bash CLI)
- `api/tests/` (all test files)
- `api/routers/auth.py` (API key validation)
- Integration test configurations

**Assigned Stories:**
- US-007: CLI Pro features integration (4 hours)
- US-012: Comprehensive Pro tier tests (4 hours)

**Key Responsibilities:**
- Update CLI with --pro flag support
- Implement subscription tier caching
- Create comprehensive test coverage
- Validate end-to-end Pro workflows

## Implementation Phases

### Phase 1: Core Backend (Days 1-2) - PARALLEL
**Teams:** Backend, Database, Billing (setup)  
**Goal:** Establish LLM service and database foundation

- **Backend Engineer:** 
  - Start US-002 (LLM service integration)
  - Begin US-005 (prompt templates)
- **Database Engineer:** 
  - Create subscription procedures (US-003, US-004 DB parts)
- **Billing Engineer:** 
  - Configure Stripe products and pricing

### Phase 2: Integration Layer (Days 3-4) - SEQUENTIAL
**Teams:** Backend, Billing  
**Goal:** Connect detection to billing system

- **Backend Engineer:**
  - Complete US-001 (Phase 9 detector using LLM)
  - Finish US-006 (context analysis)
- **Billing Engineer:**
  - Implement US-003 (tier checking middleware)
  - Complete US-004 (Stripe checkout flow)

### Phase 3: User Features (Days 5-6) - PARALLEL
**Teams:** Frontend, Integration, Billing  
**Goal:** Build user-facing components

- **Frontend Engineer:**
  - Build US-008 (Pro dashboard)
  - Update US-010 (pricing page)
- **Integration Engineer:**
  - Implement US-007 (CLI updates)
- **Billing Engineer:**
  - Add US-009 (usage analytics)

### Phase 4: Polish & Launch (Days 7-8) - SEQUENTIAL
**Teams:** Frontend, Integration  
**Goal:** Complete testing and onboarding

- **Frontend Engineer:**
  - Create US-011 (Pro onboarding)
- **Integration Engineer:**
  - Complete US-012 (comprehensive tests)
  - Run full test suite

## Synchronization Points

### Critical Dependencies
1. US-001 requires US-002 completion (LLM service must exist)
2. US-003 API requires database procedures from US-003 DB
3. US-008 requires US-001 (need API returning LLM data)
4. US-012 requires all other stories (integration tests last)

### Daily Sync Requirements
- **Morning:** Status update and blocker identification
- **Midday:** Backend/Database sync on API contracts
- **Evening:** Progress review and next-day planning

## Success Metrics

### Story Completion
Each story must meet all acceptance criteria from PRD:
- ✅ Pro tier users receive LLM analysis
- ✅ Free users see upgrade prompts
- ✅ Stripe payment creates subscription
- ✅ Dashboard displays AI insights
- ✅ All tests achieve 90% coverage

### Performance Targets
- LLM analysis adds < 2s to scan time
- Subscription check cached < 50ms
- API response time < 1.5s with LLM
- Cache hit rate > 30%

### Business Goals
- 10% free-to-Pro conversion rate
- 40% trial conversion after 14 days
- < 5% monthly churn
- $2,900 MRR in month 1 (100 users)

## File Creation Strategy

### New Directories
```bash
api/scanner/        # Phase 9 detection engine
api/prompts/        # LLM prompt templates
api/database/       # MSSQL stored procedures
dashboard/src/app/pro/      # Pro features UI
dashboard/src/app/onboarding/pro/  # Onboarding flow
```

### New Core Files
```bash
# Backend (US-001, US-002, US-005, US-006)
api/scanner/phase9_llm_detector.py
api/services/llm_service.py
api/services/context_analyzer.py
api/services/threat_correlator.py
api/prompts/security_analysis_prompts.py
api/prompts/threat_detection_prompts.py
api/models/llm_models.py
api/config/llm_config.py

# Database (US-003, US-004)
api/database/mssql_procedures.sql
api/database/subscription_procedures.sql

# Billing (US-003, US-004, US-009)
api/middleware/tier_check.py
api/services/subscription_service.py
api/services/stripe_service.py
api/services/analytics_service.py

# Frontend (US-008, US-010, US-011)
dashboard/src/app/pro/page.tsx
dashboard/src/components/ProFeatures.tsx
dashboard/src/app/onboarding/pro/page.tsx

# Testing (US-012)
api/tests/test_pro_tier.py
api/tests/test_billing_integration.py
api/tests/test_phase9_llm.py
api/tests/test_llm_prompts.py
api/tests/test_context_analysis.py
```

### Modified Files
```bash
# Existing files to update
api/routers/scan.py        # Add Pro tier check
api/routers/billing.py     # Add Pro subscription
api/routers/auth.py        # API key validation
api/config.py              # Stripe price IDs
bin/sigil                  # CLI Pro support
dashboard/src/app/pricing/page.tsx  # Pricing update
dashboard/src/components/PricingCard.tsx
```

## NOMARK Team Discipline

### Pre-Implementation Checklist
- [ ] Read `/Users/reecefrazier/CascadeProjects/sigil/CLAUDE.md`
- [ ] Review existing patterns in codebase
- [ ] Verify Auth0 configuration exists
- [ ] Confirm MSSQL/Azure SQL setup
- [ ] Check Stripe API keys configured

### During Implementation
- [ ] Follow existing code patterns exactly
- [ ] Keep changes minimal and focused
- [ ] Only modify owned files
- [ ] Test locally before marking complete
- [ ] Document any API changes

### Post-Implementation
- [ ] Update story status with pass/fail
- [ ] Note any blockers encountered
- [ ] Document learnings for team
- [ ] Prepare change summary
- [ ] Run integration tests

## Risk Mitigation

### Technical Risks
1. **LLM API Rate Limits**
   - Implement caching (24-hour)
   - Fallback to static analysis
   - Queue management for bursts

2. **Database Performance**
   - Use stored procedures
   - Cache subscription status
   - Index optimization on tier checks

3. **Stripe Webhook Reliability**
   - Implement retry logic
   - Idempotent webhook handlers
   - Event deduplication

### Business Risks
1. **Low Conversion Rate**
   - A/B test pricing
   - 14-day free trial
   - Highlight unique AI detections

2. **High LLM Costs**
   - Monitor usage closely
   - Optimize prompts for efficiency
   - Set per-user limits

## Launch Readiness Checklist

### Technical Requirements
- [ ] Phase 7-8 detection tested on 1000+ samples
- [ ] LLM prompts validated against known threats
- [ ] Stripe integration tested with test cards
- [ ] Subscription upgrade/downgrade flows work
- [ ] 90% test coverage achieved

### Business Requirements
- [ ] Pricing page updated with Pro tier
- [ ] Pro features documented
- [ ] Support documentation ready
- [ ] Marketing materials prepared
- [ ] Analytics tracking configured

### Security Requirements
- [ ] API key scoping validated
- [ ] Audit logging functional
- [ ] Rate limiting configured
- [ ] Tier access controls verified
- [ ] MSSQL procedures secured

## Communication Protocol

### Team Channels
- **#phase-9-dev** - Development updates
- **#phase-9-blockers** - Urgent issues
- **#phase-9-testing** - Test results

### Status Updates
- Morning: Previous day summary
- Midday: Current progress
- Evening: Next day plan

### Escalation Path
1. Team member identifies blocker
2. Post in #phase-9-blockers
3. Team lead assigns resolution
4. Update shared memory with solution

## Conclusion

This plan enables 5 specialized agents to work in parallel on Phase 9 Pro LLM Detection, delivering a complete $29/month Pro tier in 8 days. Each agent has clear ownership, defined deliverables, and specific success criteria.

The phased approach ensures dependencies are managed while maximizing parallelization. With proper coordination at sync points and adherence to NOMARK discipline, the team can deliver production-ready Pro features by March 15, 2026.

**Next Steps:**
1. Each agent reviews their assigned stories
2. Verify development environment setup
3. Begin Phase 1 implementation immediately
4. Report progress in shared memory