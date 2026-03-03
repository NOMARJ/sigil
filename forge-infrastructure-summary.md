# Sigil Forge Infrastructure Summary

## Executive Summary

This deployment plan transforms the existing Sigil security platform into a comprehensive AI agent tooling ecosystem by adding the Forge discovery and curation layer. The architecture leverages proven Azure Container Apps infrastructure while adding minimal operational complexity and cost.

**Investment**: $25/month incremental infrastructure cost  
**Timeline**: 4-week staged deployment (March 3-31, 2026)  
**Risk**: LOW (builds on existing proven infrastructure)  
**ROI Target**: $500/month revenue by month 6  

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       DNS & CDN Layer                          │
│  *.sigilsec.ai (existing wildcard SSL)                        │
│  ├── api.sigilsec.ai    → sigil-api (+ forge routes)          │
│  ├── app.sigilsec.ai    → sigil-dashboard                     │
│  └── forge.sigilsec.ai  → sigil-dashboard (forge subdomain)   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              Azure Container Apps (existing)                   │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │     sigil-api       │  │  sigil-dashboard    │              │
│  │  FastAPI + Forge    │  │  Next.js + Forge    │              │
│  │  api.sigilsec.ai    │  │  forge.sigilsec.ai  │              │
│  │                     │  │                     │              │
│  │  NEW ROUTES:        │  │  NEW FEATURES:      │              │
│  │  /api/forge/*       │  │  Package discovery  │              │
│  │  Classification     │  │  Stack builder      │              │
│  │  Discovery feeds    │  │  Category browser   │              │
│  └─────────────────────┘  └─────────────────────┘              │
│                                                                 │
│  ┌─────────────────────┐                                       │
│  │ sigil-classification│  ← NEW Container Apps Job              │
│  │  LLM Pipeline       │                                       │
│  │  Claude Haiku       │                                       │
│  │  Batch processor    │                                       │
│  └─────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Database Layer (existing)                      │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │  Existing Tables    │  │   NEW Forge Tables  │              │
│  │                     │  │                     │              │
│  │  • scan_results     │  │  • forge_classific. │              │
│  │  • threat_intel     │  │  • forge_categories │              │
│  │  • publishers       │  │  • forge_stacks     │              │
│  │  • users/auth       │  │  • forge_analytics  │              │
│  └─────────────────────┘  └─────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│             Background Processing (existing)                   │
│  ┌─────────────────────┐  ┌─────────────────────┐              │
│  │    Sigil Bot        │  │   NEW Forge Jobs    │              │
│  │   (enhanced)        │  │                     │              │
│  │                     │  │  • Classification   │              │
│  │  • ClawHub scan     │  │  • Stack generation │              │
│  │  • GitHub MCP scan  │  │  • Weekly digest    │              │
│  │  • Threat intel     │  │  • Usage analytics  │              │
│  │  + MCP Watchdog     │  │                     │              │
│  │  + SkillGuard       │  │                     │              │
│  └─────────────────────┘  └─────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Deployment Components

### 1. Database Extensions (forge-schema.sql)
**Files**: `/Users/reecefrazier/CascadeProjects/sigil/forge-schema.sql`

- **forge_classification**: Package categorization and capabilities
- **forge_categories**: 12 predefined categories (database, API, code tools, etc.)
- **forge_stacks**: Curated skill+MCP combinations
- **forge_analytics**: Usage tracking and business metrics
- **forge_featured**: Revenue-generating featured listings

**Migration Strategy**: Additive only, no existing table changes

### 2. API Extensions (api/routers/forge.py)  
**Files**: `/Users/reecefrazier/CascadeProjects/sigil/api/routers/forge.py`

- **GET /api/forge/search**: Search packages by capability
- **GET /api/forge/categories**: Browse by category
- **GET /api/forge/stacks**: Get curated combinations
- **GET /api/forge/feed.json**: Agent-consumable JSON feed
- **GET /api/forge/stats**: Platform statistics

**Integration**: Registered in existing main.py, uses existing auth/rate-limiting

### 3. Classification Pipeline (classification-pipeline.py)
**Files**: `/Users/reecefrazier/CascadeProjects/sigil/classification-pipeline.py`, `Dockerfile.classification`

- **Hybrid approach**: Rule-based + LLM enhancement
- **Claude Haiku**: $0.001/request, ~$15-25/month total
- **Batch processing**: 50 packages at a time
- **Azure Container Apps Job**: Scheduled daily runs

### 4. CI/CD Extensions (.github/workflows/deploy-forge.yml)
**Files**: `/Users/reecefrazier/CascadeProjects/sigil/.github/workflows/deploy-forge.yml`

- **Component-based deployment**: API, dashboard, classification separate
- **Blue/green strategy**: Zero-downtime deployments
- **Automated rollback**: Triggers on health check failures
- **Database migration**: Backup → apply → verify → rollback if needed

### 5. Monitoring & Observability (forge-monitoring.yaml)
**Files**: `/Users/reecefrazier/CascadeProjects/sigil/forge-monitoring.yaml`

- **Azure Application Insights**: Custom events and metrics
- **Business KPIs**: DAU, search success rate, classification quality
- **Cost tracking**: LLM usage, infrastructure spend
- **Alert rules**: P0 (immediate) to P3 (24h response)

---

## Cost Analysis

### Monthly Infrastructure Costs

| Component | Current Cost | Forge Addition | Notes |
|-----------|-------------|----------------|--------|
| **Azure Container Apps** | $0 (free tier) | $0 | Within existing limits |
| **Azure SQL Database** | $X/month | $0 | Uses existing database |
| **Application Insights** | $X/month | $3/month | ~1GB additional data |
| **Azure Container Registry** | $0 (free tier) | $0 | Additional images within limits |
| **Claude Haiku API** | $0 | $15-25/month | 8K-12K classifications/month |
| **Email service (Resend)** | $0 | $10/month | Forge Weekly digest |
| **Total Incremental** | | **$25-40/month** | |

### Revenue Projections

| Revenue Stream | Month 1 | Month 3 | Month 6 | Notes |
|----------------|---------|---------|---------|--------|
| **Featured Listings** | $0 | $150 | $300 | $49/month × 6 publishers |
| **"Forged by Sigil" Badges** | $0 | $45 | $90 | $9/month × 10 publishers |
| **Forge Pro Subscriptions** | $0 | $60 | $200 | $19/month × 10 users |
| **Total Monthly Revenue** | $0 | $255 | $590 | |
| **Break-even Month** | | Month 2 | | |

---

## Risk Assessment

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| **Database migration failure** | LOW | HIGH | Automated backup before migration, tested rollback procedures |
| **API endpoint failures** | LOW | MEDIUM | Blue/green deployment, health checks, automatic rollback |
| **Classification pipeline costs** | MEDIUM | MEDIUM | Daily cost monitoring, automatic shutoff at $30/day |
| **Subdomain SSL issues** | LOW | LOW | Wildcard cert already covers *.sigilsec.ai |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| **Low user adoption** | MEDIUM | MEDIUM | Gradual rollout, user feedback integration, agent-first design |
| **Competition from ClawHub** | LOW | HIGH | First-mover advantage, focus on security/trust differentiation |
| **LLM API cost escalation** | LOW | MEDIUM | Multi-provider strategy, rule-based fallbacks |

### Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| **Team capacity shortage** | LOW | MEDIUM | Contractor augmentation available, 4-week timeline includes buffer |
| **Azure service outages** | LOW | HIGH | Multi-region deployment planned for Month 6 |

---

## Success Metrics

### Week 1 (Zero-Cost Features)
- [x] 3 products shipped (MCP Watchdog, SkillGuard Feed, MCP Permissions Map)
- [ ] 100+ page views across new features
- [ ] Zero impact on existing Sigil functionality
- [ ] Community engagement on launch announcement

### Week 4 (Full Platform)  
- [ ] forge.sigilsec.ai live with 7,700+ classified packages
- [ ] 100+ daily searches (human + agent)
- [ ] 25+ package detail views per day
- [ ] 3+ curated stacks published
- [ ] <2s API response time (P95)

### Month 3 (Growth Phase)
- [ ] 1,000+ monthly active users
- [ ] 10+ agent integrations using Forge API
- [ ] 50+ featured/verified packages
- [ ] $250+ monthly recurring revenue
- [ ] 95% classification accuracy

### Month 6 (Market Position)
- [ ] 5,000+ monthly searches
- [ ] Partnership with skills.sh or ClawHub
- [ ] $500+ monthly recurring revenue
- [ ] Recognition as authority on AI agent tooling security
- [ ] 25+ security-focused skills in marketplace

---

## Next Steps

### Immediate Actions (by March 5, 2026)
1. **Executive approval** for 4-week deployment plan
2. **Budget approval** for $2,525 contractor costs + $40/month infrastructure
3. **Team assignment** - primary and secondary engineers identified
4. **Secret configuration** - Anthropic API key, Azure credentials validated

### Week 1 Preparation (March 3-8)
1. **Contractor onboarding** - Product/PM and content/marketing
2. **Development environment setup** - staging database, API testing
3. **Monitoring configuration** - Application Insights, alert rules
4. **Internal testing** - Classification pipeline on sample data

### Week 1 Execution (March 8-15) 
1. **Deploy zero-cost features** (MCP Watchdog, SkillGuard, Permissions)
2. **Launch announcement** - coordinated marketing push
3. **Community engagement** - post in AI agent communities
4. **Feedback collection** - user interviews and analytics review

---

## Team Contacts

### Technical Implementation
- **Primary Engineer**: Responsible for API routes, database schema, classification pipeline
- **Secondary Engineer**: Frontend integration, monitoring setup, deployment validation
- **DevOps Lead**: CI/CD pipeline updates, Azure infrastructure configuration

### Business Implementation  
- **Product Manager**: User workflows, success metrics, feature prioritization
- **Marketing Lead**: Launch announcement, community engagement, content creation
- **Business Development**: Partnership outreach (skills.sh, ClawHub, agent platforms)

### Support and Operations
- **On-call Engineering**: 24/7 incident response for P0 issues
- **Customer Success**: User feedback collection and analysis
- **Finance**: Cost tracking and revenue projection validation

---

This comprehensive deployment plan provides a production-ready roadmap for launching Sigil Forge while maintaining the reliability and security standards of the existing Sigil platform. The staged approach minimizes risk while building toward a sustainable and profitable product extension that serves the growing AI agent ecosystem.