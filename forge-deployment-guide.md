# Sigil Forge Deployment Guide

## Overview

This guide covers the complete deployment process for Sigil Forge, including pre-deployment preparation, staged rollout procedures, monitoring setup, and rollback strategies.

**Deployment Timeline**: 4 weeks (March 3-31, 2026)  
**Deployment Strategy**: Blue/green with staged rollout  
**Rollback SLA**: < 15 minutes for critical failures  

---

## Pre-Deployment Checklist

### Week 0: Infrastructure Preparation

- [ ] **Azure credentials configured**
  - Verify `AZURE_CREDENTIALS` secret in GitHub
  - Confirm ACR access permissions
  - Test Azure CLI login from GitHub Actions

- [ ] **Database preparation**
  - [ ] Backup current production database
  - [ ] Test schema changes on staging environment
  - [ ] Validate migration rollback procedures
  - [ ] Confirm database connection strings are configured

- [ ] **Environment variables configured**
  ```bash
  # Required for classification pipeline
  ANTHROPIC_API_KEY=sk-... (in Azure Key Vault)
  
  # Forge-specific settings
  FORGE_ENABLED=true
  FORGE_CLASSIFICATION_BATCH_SIZE=50
  FORGE_MAX_DAILY_LLM_REQUESTS=1000
  
  # Monitoring
  APPLICATIONINSIGHTS_CONNECTION_STRING=InstrumentationKey=...
  ```

- [ ] **DNS and SSL preparation**
  - [ ] Configure `forge.sigilsec.ai` subdomain in DNS
  - [ ] Extend wildcard SSL certificate to cover `forge.sigilsec.ai`
  - [ ] Test subdomain resolution

- [ ] **Monitoring setup**
  - [ ] Configure Application Insights for Forge events
  - [ ] Set up custom dashboards using `forge-monitoring.yaml`
  - [ ] Configure alert rules for critical metrics
  - [ ] Test notification channels (email, Slack)

---

## Staged Deployment Process

### Week 1: Zero-Cost Features (March 3-10)

**Goal**: Ship MCP Watchdog, SkillGuard Feed, MCP Permissions Map  
**Risk**: LOW (no new infrastructure required)

#### Day 1-2: MCP Watchdog
```bash
# Deploy typosquat detection extension
git checkout -b forge/mcp-watchdog
# Extend existing Sigil Bot with MCP server monitoring
# Update bot/config to include popular MCP server names
git commit -m "feat: Add MCP server typosquat detection"
git push origin forge/mcp-watchdog
# Create PR and merge to main
```

**Rollback Procedure**:
1. Revert bot configuration to previous version
2. Restart Sigil Bot container
3. Verify existing functionality intact

#### Day 3-4: SkillGuard Feed  
```bash
# Add RSS feed filtering for prompt injection findings
# Update api/routers/feed.py to include Phase 7 findings
# Test feed generation locally
curl "http://localhost:8000/feed.rss?category=prompt_injection&ecosystem=skills"
```

**Rollback Procedure**:
1. Revert API changes if feed causes errors
2. API automatically falls back to standard feed

#### Day 5-7: MCP Permissions Map
```bash
# Create static site generator for MCP permissions
# Use existing Phase 3/4 findings data
# Deploy as subdomain: permissions.sigilsec.ai
```

**Rollback Procedure**:
1. Remove subdomain DNS entry
2. No impact on main services

### Week 2-3: Core Forge Platform (March 10-24)

**Goal**: Deploy full Forge discovery platform  
**Risk**: MEDIUM (new database tables, API endpoints)

#### Pre-deployment Steps

1. **Database backup**
   ```sql
   -- Automated via CI/CD pipeline
   az sql db export \
     --resource-group sigil-prod-rg \
     --server sigil-prod-sql \
     --name sigil-prod-db \
     --storage-uri "https://sigilbackups.blob.core.windows.net/backups/pre-forge-$(date +%Y%m%d).bacpac"
   ```

2. **Schema deployment** (Day 1)
   ```bash
   # Apply forge-schema.sql via CI/CD pipeline
   # Pipeline validates schema before applying
   # Creates: forge_classification, forge_categories, forge_stacks, etc.
   ```

3. **API deployment** (Day 2-3)
   ```bash
   # Deploy updated API with Forge routes
   # Blue/green deployment via Azure Container Apps
   # Test endpoints before switching traffic
   ```

4. **Initial classification** (Day 4-5)
   ```bash
   # Run classification pipeline on existing scan data
   # Batch process 5,700+ ClawHub skills + 2,000+ MCP servers
   # Monitor LLM costs and rate limits
   ```

5. **Frontend deployment** (Day 6-7)
   ```bash
   # Deploy forge.sigilsec.ai subdomain
   # Static site initially, dynamic features later
   ```

#### Rollback Procedures

**Level 1: API Rollback** (if endpoints fail)
```bash
# 1. Immediately switch Container App traffic back to previous revision
az containerapp revision set-mode \
  --name sigil-api \
  --resource-group sigil-prod-rg \
  --mode single \
  --revision sigil-api--<previous-revision>

# 2. Verify main API functionality
curl https://api.sigilsec.ai/health
curl https://api.sigilsec.ai/v1/scan -X POST -d '{"target":"test","target_type":"directory"}'

# 3. Remove Forge routes from load balancer (if causing issues)
# This would be done via Infrastructure repo
```

**Level 2: Database Rollback** (if schema causes issues)
```bash
# 1. Drop new Forge tables (if safe)
DROP TABLE forge_api_usage;
DROP TABLE forge_discovery_events;
DROP TABLE forge_usage_patterns;
DROP TABLE forge_publisher_subscriptions;
DROP TABLE forge_featured;
DROP TABLE forge_stacks;
DROP TABLE forge_classification;
DROP TABLE forge_categories;

# 2. Verify existing scan functionality
SELECT COUNT(*) FROM scan_results WHERE created_at > '2026-03-10';

# 3. Restore from backup if needed (LAST RESORT)
az sql db import \
  --resource-group sigil-prod-rg \
  --server sigil-prod-sql \
  --name sigil-prod-db \
  --storage-uri "https://sigilbackups.blob.core.windows.net/backups/pre-forge-20260310.bacpac"
```

**Level 3: Full Rollback** (if entire deployment fails)
```bash
# 1. Revert all Container App revisions
# 2. Restore database from backup
# 3. Remove DNS entries for forge.sigilsec.ai
# 4. Notify team and users of service restoration
```

### Week 3-4: Agent Integration (March 24-31)

**Goal**: Deploy MCP Server tools and agent interfaces  
**Risk**: LOW (additive features only)

#### Deployment Steps

1. **MCP Server deployment**
   ```bash
   # Add Forge tools to existing Sigil MCP Server
   # Tools: forge_search, forge_stack, forge_check
   # Deploy as part of existing MCP infrastructure
   ```

2. **Agent Card and llms.txt**
   ```bash
   # Deploy static files for agent discovery
   # Add to forge.sigilsec.ai/.well-known/agent-card.json
   # Add forge.sigilsec.ai/llms.txt
   ```

3. **JSON-LD structured data**
   ```bash
   # Add structured data to package pages
   # Enables agent parsing of package information
   ```

#### Rollback Procedures

**MCP Server Rollback**
```bash
# 1. Revert MCP Server to previous version without Forge tools
# 2. Test existing tools still work: sigil_scan, sigil_clone, etc.
# 3. Agents will gracefully degrade (Forge tools unavailable but other tools work)
```

**Static File Rollback**
```bash
# 1. Remove agent-card.json and llms.txt files
# 2. No impact on main functionality
```

---

## Monitoring and Health Checks

### Critical Health Checks

**API Health Check**
```bash
#!/bin/bash
# Run every 5 minutes via Azure Monitor

# Check main API
if ! curl -f "https://api.sigilsec.ai/health"; then
    echo "CRITICAL: Main API down"
    exit 1
fi

# Check Forge endpoints
if ! curl -f "https://api.sigilsec.ai/api/forge/stats"; then
    echo "WARNING: Forge API degraded"
    exit 2
fi

# Check database connectivity
if ! curl -f "https://api.sigilsec.ai/api/forge/categories"; then
    echo "WARNING: Forge database connectivity issues"
    exit 2
fi

echo "Health check passed"
```

**Classification Pipeline Health**
```bash
#!/bin/bash
# Run daily via Azure Container Apps Job

# Check recent classifications
RECENT_CLASSIFICATIONS=$(curl -s "https://api.sigilsec.ai/api/forge/stats" | jq '.total_packages')

if [ "$RECENT_CLASSIFICATIONS" -lt 1000 ]; then
    echo "WARNING: Classification pipeline appears stalled"
    # Trigger classification job restart
fi
```

### Key Metrics to Monitor

1. **Availability Metrics**
   - API response time (target: < 500ms P95)
   - Error rate (target: < 1%)
   - Uptime (target: 99.9%)

2. **Business Metrics**
   - Daily active users (searches + views)
   - Package discovery rate
   - Agent vs human usage ratio

3. **Cost Metrics**
   - LLM API costs (target: < $25/day)
   - Azure infrastructure costs
   - Cost per classification

### Alert Escalation

**P0 - Critical (Immediate Response)**
- API completely down
- Database connectivity lost
- Security breach detected

**P1 - High (Response within 1 hour)**
- High error rate (>5%)
- Performance degradation (>2s response time)
- Classification pipeline completely stopped

**P2 - Medium (Response within 4 hours)**
- Moderate error rate (1-5%)
- Individual endpoint failures
- Cost budget warnings

**P3 - Low (Response within 24 hours)**
- Performance warnings
- Usage pattern anomalies
- Non-critical feature degradation

---

## Disaster Recovery Procedures

### Scenario 1: Complete API Failure

**Immediate Actions** (0-5 minutes)
1. Check Azure Container Apps status
2. Verify database connectivity
3. Check DNS resolution for api.sigilsec.ai

**Escalation Actions** (5-15 minutes)
1. Switch to previous Container App revision
2. If still failing, restore from latest backup
3. Notify users via status page

**Recovery Actions** (15-60 minutes)
1. Investigate root cause
2. Apply fixes to current revision
3. Gradually roll forward again

### Scenario 2: Database Corruption

**Immediate Actions** (0-10 minutes)
1. Stop all write operations
2. Assess extent of corruption
3. Switch API to read-only mode if possible

**Recovery Actions** (10-30 minutes)
1. Restore database from latest backup
2. Replay recent transactions if possible
3. Validate data integrity before resuming writes

### Scenario 3: Classification Pipeline Runaway Costs

**Immediate Actions** (0-5 minutes)
1. Stop classification Container App Job
2. Check current day's LLM usage via Anthropic dashboard
3. Implement immediate rate limiting

**Prevention Actions** (5-30 minutes)
1. Adjust batch sizes to reduce costs
2. Implement stricter rate limiting
3. Resume classification with updated limits

### Scenario 4: Security Incident

**Immediate Actions** (0-10 minutes)
1. Isolate affected components
2. Preserve logs and evidence
3. Assess scope of potential data exposure

**Containment Actions** (10-60 minutes)
1. Patch security vulnerabilities
2. Rotate API keys and secrets
3. Review access logs for unauthorized access

**Recovery Actions** (1-24 hours)
1. Notify affected users if data was exposed
2. Implement additional security measures
3. Conduct post-incident review

---

## Post-Deployment Validation

### Week 1 Success Criteria

- [ ] All zero-cost features deployed and functional
- [ ] No impact on existing Sigil functionality
- [ ] MCP Watchdog detecting typosquats
- [ ] SkillGuard Feed generating valid RSS
- [ ] MCP Permissions Map accessible and useful

### Week 2-3 Success Criteria

- [ ] forge.sigilsec.ai accessible and functional
- [ ] All API endpoints responding with valid data
- [ ] Database schema deployed without issues
- [ ] Initial classification of 1000+ packages completed
- [ ] Search functionality working with results
- [ ] Cost tracking under $25/month

### Week 4 Success Criteria

- [ ] MCP Server tools functional and tested
- [ ] Agent Card and llms.txt deployed
- [ ] JSON-LD structured data on all package pages
- [ ] End-to-end agent workflow tested
- [ ] Monitoring dashboards populated with data

### Long-term Success Metrics (30 days)

- [ ] 100+ daily searches across all channels
- [ ] 25+ package views per day
- [ ] <2% error rate across all Forge endpoints
- [ ] 99.9% uptime for forge.sigilsec.ai
- [ ] Classification pipeline processing 50+ packages/day
- [ ] Cost remaining under $50/month total

---

## Team Responsibilities

### Development Team
- Code review and testing of all Forge components
- Database schema validation and migration testing
- API endpoint testing and documentation
- MCP Server integration testing

### DevOps Team  
- CI/CD pipeline configuration and testing
- Azure infrastructure provisioning and configuration
- Monitoring setup and alert configuration
- Deployment validation and rollback procedures

### Product Team
- User acceptance testing of Forge features
- Content creation for initial package classifications
- Documentation and user guides
- Success metrics tracking and analysis

### Support Team
- Incident response procedures and escalation
- User communication during outages
- Monitoring dashboard review
- Performance optimization recommendations

---

## Emergency Contacts

**P0 Incidents (24/7 Response)**
- On-call Engineer: [Pager/Phone]
- Engineering Manager: [Phone/Email]
- CTO: [Phone/Email for major incidents]

**P1-P2 Incidents (Business Hours)**
- DevOps Lead: [Email/Slack]
- Product Manager: [Email/Slack]
- Customer Success: [Email for user communications]

**External Dependencies**
- Azure Support: [Support case system]
- Anthropic API Support: [Email for Claude API issues]
- DNS Provider: [Support contact for domain issues]

---

## Post-Deployment Checklist

### Immediate (Day 1 after deployment)
- [ ] Verify all health checks passing
- [ ] Confirm monitoring dashboards populated
- [ ] Test primary user workflows
- [ ] Review error logs for any issues
- [ ] Validate cost tracking is accurate

### Week 1 Review
- [ ] Analyze usage patterns and user feedback
- [ ] Review performance metrics vs. targets
- [ ] Assess classification pipeline quality
- [ ] Check cost projections vs. actual spending
- [ ] Plan any necessary optimizations

### Month 1 Review
- [ ] Full success metrics review
- [ ] User feedback analysis and feature prioritization
- [ ] Performance optimization planning
- [ ] Cost optimization opportunities
- [ ] Roadmap planning for Month 2-3 features