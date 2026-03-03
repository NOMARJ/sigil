# Sigil API Production Runbooks

This document contains operational procedures for responding to production incidents and maintaining the Sigil API monitoring system.

## Table of Contents

1. [Incident Response Overview](#incident-response-overview)
2. [Critical Alerts](#critical-alerts)
3. [Performance Issues](#performance-issues)
4. [Security Incidents](#security-incidents)
5. [Database Issues](#database-issues)
6. [Infrastructure Problems](#infrastructure-problems)
7. [Monitoring System Maintenance](#monitoring-system-maintenance)

## Incident Response Overview

### Severity Levels

| Severity | Response Time | Description |
|----------|---------------|-------------|
| Critical | 15 minutes | Service down, data loss, security breach |
| High | 1 hour | Significant degradation, user impact |
| Medium | 4 hours | Minor degradation, limited impact |
| Low | Next business day | No user impact, housekeeping |

### Escalation Process

1. **Level 1**: On-call engineer
2. **Level 2**: Engineering team lead + DevOps lead
3. **Level 3**: CTO + Security team (for security incidents)

### Communication Channels

- **Slack**: `#incidents` channel
- **Email**: incidents@mail.sigilsec.ai
- **PagerDuty**: For critical/high severity alerts

## Critical Alerts

### Database Connectivity Failure

**Alert**: "Database Connectivity"
**Severity**: Critical

#### Immediate Actions (< 5 minutes)
1. Check Azure SQL Database status in Azure Portal
2. Verify connection string and credentials
3. Check network connectivity from Container Apps to database
4. Review recent deployments that might affect database

#### Investigation Steps
1. **Check Database Status**:
   ```bash
   # Check health endpoint
   curl -f https://api.sigilsec.ai/health/detailed
   
   # Check Azure SQL status
   az sql db show --server sigil-prod --name sigil-api --resource-group sigil-prod-rg
   ```

2. **Check Connection Pool**:
   - Review database connection pool metrics in Application Insights
   - Look for connection timeouts or pool exhaustion

3. **Check Network**:
   - Verify VNet peering between Container Apps and SQL Database
   - Check NSG rules and firewall settings

#### Recovery Actions
1. **If database is down**:
   - Contact Azure support
   - Consider failing over to backup region

2. **If connection issues**:
   - Restart Container Apps instances
   - Scale up to get fresh connections

3. **If pool exhaustion**:
   - Increase connection pool size in configuration
   - Deploy hotfix

#### Post-Incident
- Document root cause
- Update monitoring if gaps found
- Review capacity planning

---

### High Error Rate

**Alert**: "High Error Rate"
**Severity**: High

#### Immediate Actions (< 15 minutes)
1. Identify which endpoints are failing
2. Check recent deployments
3. Review error logs in Application Insights

#### Investigation Steps
1. **Analyze Error Distribution**:
   ```kusto
   requests 
   | where success == false
   | summarize count() by resultCode, url
   | order by count_ desc
   ```

2. **Check Recent Changes**:
   - Review last 24h of deployments
   - Check configuration changes

3. **Examine Error Details**:
   ```kusto
   exceptions
   | where timestamp > ago(1h)
   | summarize count() by type, outerMessage
   | order by count_ desc
   ```

#### Recovery Actions
1. **If caused by recent deployment**:
   - Rollback to previous version
   - Hot patch if possible

2. **If external dependency failure**:
   - Enable circuit breaker/fallback
   - Contact vendor if needed

3. **If capacity issue**:
   - Scale up instances
   - Review resource utilization

---

## Performance Issues

### High Response Time

**Alert**: "High Response Time"
**Severity**: Medium

#### Investigation Steps
1. **Identify Slow Endpoints**:
   ```kusto
   requests
   | where timestamp > ago(1h)
   | summarize avg(duration), percentile(duration, 95) by url
   | order by percentile_duration_95 desc
   ```

2. **Check Database Performance**:
   ```kusto
   dependencies
   | where type == "SQL"
   | summarize avg(duration), percentile(duration, 95) by name
   | order by percentile_duration_95 desc
   ```

3. **Review Resource Utilization**:
   - CPU usage in Container Apps
   - Memory utilization
   - Database DTU/vCore usage

#### Recovery Actions
1. **Scale horizontally**: Increase replica count
2. **Optimize queries**: Identify slow queries and add indexes
3. **Enable caching**: For frequently accessed data
4. **Review code**: Profile application for bottlenecks

---

### Memory Usage Alert

**Alert**: "High Memory Usage"
**Severity**: Medium

#### Investigation Steps
1. **Check Memory Metrics**:
   - Container Apps memory usage
   - Application Insights performance counters

2. **Identify Memory Leaks**:
   - Review object allocation patterns
   - Check for unreleased resources

#### Recovery Actions
1. **Immediate**: Restart affected instances
2. **Short-term**: Scale up instance size
3. **Long-term**: Fix memory leaks in code

---

## Security Incidents

### Security Alert Spike

**Alert**: "Security Alert Spike"
**Severity**: High

#### Immediate Actions (< 30 minutes)
1. **Assess Threat Level**:
   - Review security alert details
   - Determine if active attack in progress

2. **Initial Containment**:
   - Block suspicious IP addresses if needed
   - Enable additional rate limiting

#### Investigation Steps
1. **Analyze Alert Patterns**:
   ```kusto
   customMetrics
   | where name == "security_alerts_total"
   | extend alert_type = tostring(customDimensions.alert_type)
   | summarize count() by alert_type, bin(timestamp, 5m)
   ```

2. **Review Request Logs**:
   - Identify attack vectors
   - Trace request origins

3. **Check for Compromise**:
   - Review authentication logs
   - Check for privilege escalation

#### Response Actions
1. **Block Attack Sources**:
   - Update WAF rules
   - Add IP blocks to Azure Front Door

2. **Strengthen Defenses**:
   - Increase rate limiting
   - Enable additional security headers

3. **Monitor for Persistence**:
   - Watch for follow-up attacks
   - Review account activities

---

## Database Issues

### High Database Load

#### Symptoms
- Slow response times
- Connection timeouts
- High DTU usage

#### Investigation
1. **Identify Expensive Queries**:
   ```sql
   SELECT TOP 10
       qs.execution_count,
       qs.total_logical_reads,
       qs.last_execution_time,
       qt.text
   FROM sys.dm_exec_query_stats qs
   CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
   ORDER BY qs.total_logical_reads DESC
   ```

2. **Check Index Usage**:
   ```sql
   SELECT 
       object_name(i.object_id) as table_name,
       i.name as index_name,
       s.user_seeks,
       s.user_scans,
       s.user_lookups
   FROM sys.dm_db_index_usage_stats s
   JOIN sys.indexes i ON s.object_id = i.object_id AND s.index_id = i.index_id
   WHERE database_id = DB_ID()
   ORDER BY s.user_seeks + s.user_scans + s.user_lookups DESC
   ```

#### Actions
1. **Immediate**: Scale up database tier
2. **Short-term**: Optimize problematic queries
3. **Long-term**: Add missing indexes, partition large tables

---

## Infrastructure Problems

### Container Apps Down

#### Investigation Steps
1. **Check Container Status**:
   ```bash
   az containerapp show --name sigil-api --resource-group sigil-prod-rg
   az containerapp logs show --name sigil-api --resource-group sigil-prod-rg
   ```

2. **Review Recent Changes**:
   - Deployment history
   - Configuration changes
   - Infrastructure updates

#### Recovery Actions
1. **Restart instances**:
   ```bash
   az containerapp restart --name sigil-api --resource-group sigil-prod-rg
   ```

2. **Scale up if needed**:
   ```bash
   az containerapp update --name sigil-api --resource-group sigil-prod-rg --min-replicas 2 --max-replicas 10
   ```

3. **Deploy previous version if needed**:
   ```bash
   az containerapp update --name sigil-api --resource-group sigil-prod-rg --image <previous-image>
   ```

---

### Redis/Cache Issues

#### Symptoms
- Degraded performance
- Cache miss rate increase
- Connection errors

#### Actions
1. **Check Redis status**:
   - Azure Cache for Redis metrics
   - Connection count and memory usage

2. **Clear problematic keys if needed**:
   ```bash
   redis-cli --scan --pattern "problematic:*" | xargs redis-cli del
   ```

3. **Scale up cache if needed**

---

## Monitoring System Maintenance

### Health Check Maintenance

#### Verify Health Checks
```bash
# Test all health endpoints
curl -f https://api.sigilsec.ai/health
curl -f https://api.sigilsec.ai/health/detailed  
curl -f https://api.sigilsec.ai/health/ready
curl -f https://api.sigilsec.ai/health/live
```

#### Update Health Check Configuration
1. Add new health checks in `api/monitoring.py`
2. Test locally first
3. Deploy and verify

### Metrics Review

#### Weekly Metrics Review
1. **Performance Trends**:
   - Response time percentiles
   - Error rates by endpoint
   - Database query performance

2. **Capacity Planning**:
   - Resource utilization trends
   - Traffic growth patterns
   - Database size growth

3. **Alert Effectiveness**:
   - False positive rate
   - Alert response times
   - Coverage gaps

### Dashboard Maintenance

#### Monthly Dashboard Review
1. **Remove unused panels**
2. **Add new metrics for features**
3. **Update alert thresholds based on trends**
4. **Verify dashboard links and data sources**

### Alert Tuning

#### Quarterly Alert Review
1. **Analyze false positives**:
   - Adjust thresholds
   - Improve condition logic
   - Add context to alerts

2. **Coverage gaps**:
   - Add missing alerts
   - Improve detection accuracy

3. **Response effectiveness**:
   - Review mean time to resolution
   - Update runbooks based on incidents

---

## Emergency Contacts

| Role | Primary | Secondary | PagerDuty |
|------|---------|-----------|-----------|
| On-call Engineer | [Phone] | [Phone] | escalation-level-1 |
| DevOps Lead | [Phone] | [Phone] | escalation-level-2 |
| Engineering Lead | [Phone] | [Phone] | escalation-level-2 |
| CTO | [Phone] | [Phone] | escalation-level-3 |
| Security Team | [Phone] | [Phone] | security-incidents |

## Useful Commands

### Azure CLI Commands
```bash
# Check resource group status
az group show --name sigil-prod-rg

# Container Apps operations
az containerapp list --resource-group sigil-prod-rg
az containerapp logs show --name sigil-api --resource-group sigil-prod-rg --follow

# Database operations
az sql db list --server sigil-prod --resource-group sigil-prod-rg
az sql db show-usage --name sigil-api --server sigil-prod --resource-group sigil-prod-rg

# Cache operations  
az redis show --name sigil-cache --resource-group sigil-prod-rg
az redis list-keys --name sigil-cache --resource-group sigil-prod-rg
```

### Application Insights Queries
```kusto
// Error rate by endpoint
requests
| where timestamp > ago(1h)
| summarize 
    total = count(),
    errors = countif(success == false),
    error_rate = 100.0 * countif(success == false) / count()
    by url
| order by error_rate desc

// Slowest endpoints
requests  
| where timestamp > ago(1h)
| summarize
    avg_duration = avg(duration),
    p95_duration = percentile(duration, 95),
    p99_duration = percentile(duration, 99)
    by url
| order by p95_duration desc

// Recent exceptions
exceptions
| where timestamp > ago(1h)
| order by timestamp desc
| take 50
```

---

**Last Updated**: 2024-01-01  
**Next Review**: Quarterly  
**Document Owner**: DevOps Team