# Sigil API Monitoring System

## Overview

This document describes the comprehensive production monitoring, health checks, and observability system implemented for the Sigil API. The system provides full visibility into application health, performance metrics, business intelligence, and automated alerting.

## Architecture

The monitoring system consists of four main components:

1. **Health Checks** - Comprehensive health monitoring for all system components
2. **Metrics Collection** - Prometheus-compatible metrics with Azure Application Insights integration
3. **Alerting System** - Automated alert rules with multiple notification channels
4. **Observability** - Structured logging, correlation IDs, and distributed tracing

## Components

### Health Check System (`monitoring.py`)

#### Features
- **Multiple Health Endpoints**:
  - `/health` - Basic health check for load balancers
  - `/health/detailed` - Comprehensive health status with all components
  - `/health/ready` - Kubernetes readiness probe
  - `/health/live` - Kubernetes liveness probe

#### Health Checks Implemented
- **Database Connectivity** - Tests Azure SQL Database connection and basic queries
- **Cache Connectivity** - Validates Redis connection with read/write operations
- **External APIs** - Checks Anthropic API and GitHub API availability
- **Background Jobs** - Monitors registry stats updater and other background processes

#### Health Check Configuration
- Configurable timeouts (default 5-30 seconds)
- Critical vs non-critical classification
- Automatic retry and timeout handling
- Detailed error reporting and stack traces

### Metrics Collection (`monitoring.py`)

#### Prometheus Metrics
- **HTTP Metrics**:
  - `http_requests_total` - Request count by method, path, status, user type
  - `http_request_duration_seconds` - Request latency histograms
  - `active_connections_total` - Current active connections

- **Database Metrics**:
  - `db_operations_total` - Database operation count by table, operation, status
  - `db_query_duration_seconds` - Database query latency histograms
  - `db_connections_active` - Active database connections

- **Business Metrics**:
  - `tool_classifications_total` - Tool classifications by category and confidence
  - `api_usage_total` - API usage by consumer type and endpoint
  - `security_alerts_total` - Security alerts by type and severity
  - `search_queries_total` - Search queries by type and result count

- **System Metrics**:
  - `memory_usage_bytes` - Memory usage by type
  - `background_jobs_status` - Background job health status

#### Metrics Middleware
- **Request Tracking** - Automatic request/response metrics collection
- **Path Normalization** - Reduces metric cardinality by normalizing IDs and UUIDs
- **User Type Detection** - Classifies requests as human, agent, or AI agent
- **Business Metrics** - Automatic business intelligence collection
- **Correlation IDs** - Generates unique IDs for request tracing

### Alerting System (`alerting.py`)

#### Alert Rules
- **High Error Rate** - Triggers when error rate exceeds 5%
- **High Response Time** - Alerts on P95 response time > 2 seconds
- **Database Connectivity** - Critical alert for database connection failures
- **Security Alert Spike** - Detects unusual security activity
- **High Memory Usage** - Warns when memory usage exceeds 80%

#### Notification Channels
- **Email** - SMTP-based email notifications with HTML formatting
- **Slack** - Rich Slack notifications with color coding and metadata
- **PagerDuty** - Integration for critical incident management

#### Alert Management
- **Cooldown Periods** - Prevents alert spam with configurable cooldowns
- **Severity Levels** - Critical, High, Medium, Low, Info severity classification
- **Alert Categories** - Infrastructure, Application, Security, Business, Performance
- **Escalation** - Automatic escalation based on severity and response times

### Structured Logging

#### Features
- **JSON Format** - Structured logs for easy parsing and analysis
- **Correlation IDs** - Tracks requests across the entire system
- **Contextual Information** - Includes user type, IP address, duration, etc.
- **Error Tracking** - Complete stack traces with context
- **Performance Logging** - Automatic slow request/query detection

#### Log Levels
- **DEBUG** - Detailed debugging information (development only)
- **INFO** - General application flow and business events
- **WARNING** - Potential issues that don't affect functionality
- **ERROR** - Error conditions that may affect user experience
- **CRITICAL** - Severe errors that may cause service disruption

## Configuration

### Environment Variables
```bash
# Core monitoring settings
SIGIL_METRICS_ENABLED=true
SIGIL_HEALTH_CHECKS_ENABLED=true
SIGIL_STRUCTURED_LOGGING=true
SIGIL_PROMETHEUS_ENABLED=true

# Azure Application Insights
SIGIL_AZURE_INSIGHTS_KEY=your_insights_connection_string

# SMTP for email alerts
SIGIL_SMTP_HOST=smtp.yourdomain.com
SIGIL_SMTP_PORT=587
SIGIL_SMTP_USER=alerts@yourdomain.com
SIGIL_SMTP_PASSWORD=your_smtp_password
SIGIL_SMTP_FROM_EMAIL=alerts@sigilsec.ai

# Slack notifications (optional)
SIGIL_SLACK_WEBHOOK_URL=https://hooks.slack.com/your/webhook

# PagerDuty integration (optional)
SIGIL_PAGERDUTY_INTEGRATION_KEY=your_integration_key
```

### Configuration File
See `monitoring/config.yml` for detailed configuration options including:
- Health check timeouts and intervals
- Alert thresholds and cooldowns
- Metric collection settings
- Dashboard configurations
- Logging levels and formats

## Dashboards

### Azure Application Insights Dashboard
Located in `monitoring/dashboards.json`, includes panels for:
- Request volume and response times
- Error rates and top failing endpoints
- Database query performance
- API usage breakdown by consumer type
- Security alerts and trends
- Tool classification metrics
- Health check status
- Background job monitoring

### Grafana Dashboard (Prometheus)
Prometheus-compatible dashboard with panels for:
- HTTP request rates and latencies
- Database operation metrics
- System resource utilization
- Business intelligence metrics
- Alert status and trends

## Operational Procedures

### Runbooks
Comprehensive runbooks in `monitoring/runbooks.md` cover:
- Incident response procedures for each alert type
- Investigation steps and diagnostic queries
- Recovery actions and escalation procedures
- Azure CLI commands and Application Insights queries
- Emergency contact information

### Alert Response
1. **Critical Alerts** - 15-minute response time, immediate investigation
2. **High Alerts** - 1-hour response time, prioritized investigation  
3. **Medium Alerts** - 4-hour response time, scheduled investigation
4. **Low Alerts** - Next business day, maintenance window

### Escalation Process
1. **Level 1** - On-call engineer
2. **Level 2** - Engineering team lead + DevOps lead
3. **Level 3** - CTO + Security team (for security incidents)

## Testing

### Test Suite
Comprehensive test suite in `tests/test_monitoring.py` includes:
- Health check functionality tests
- Metrics collection validation
- Alert rule evaluation tests
- Notification channel tests
- Integration and performance tests

### Running Tests
```bash
# Run all monitoring tests
pytest api/tests/test_monitoring.py -v

# Run specific test categories
pytest api/tests/test_monitoring.py::TestHealthChecks -v
pytest api/tests/test_monitoring.py::TestMetrics -v
pytest api/tests/test_monitoring.py::TestAlerts -v
```

## Deployment

### Dependencies
All monitoring dependencies are included in `requirements.txt`:
- `prometheus-client` - Prometheus metrics
- `azure-monitor-opentelemetry` - Azure Application Insights integration
- `opentelemetry-*` - OpenTelemetry instrumentation
- `structlog` - Structured logging

### Azure Configuration
1. **Application Insights** - Create Application Insights resource and configure connection string
2. **Log Analytics** - Set up Log Analytics workspace for query capabilities
3. **Action Groups** - Configure Azure Monitor action groups for alerting
4. **Dashboards** - Import dashboard configurations from `dashboards.json`

### Container Apps Integration
The monitoring system is automatically enabled when the application starts:
```python
# In main.py lifespan function
if settings.metrics_enabled:
    # Start monitoring middleware
    app.add_middleware(MetricsMiddleware)
    
    # Start background alert evaluation
    asyncio.create_task(run_alert_evaluation_loop())
```

## Performance Impact

### Overhead Analysis
- **Health Checks** - ~1ms per basic health check, ~10-50ms for detailed checks
- **Metrics Collection** - <1ms overhead per request with middleware
- **Alert Evaluation** - Runs every 60 seconds, minimal CPU impact
- **Structured Logging** - ~2-3ms overhead per log entry

### Optimization Strategies
- Path normalization reduces metric cardinality
- Sampling configuration for high-volume environments
- Lazy loading of monitoring components
- Configurable health check intervals
- Efficient database metric collection with lazy imports

## Monitoring the Monitoring System

### Self-Monitoring
The monitoring system monitors itself:
- Health check for alert evaluation loop
- Metrics on notification success/failure rates
- Alerts for monitoring system failures
- Dashboard panels showing monitoring health

### Key Metrics to Watch
- Health check success rate and duration
- Alert evaluation frequency and errors
- Notification delivery success rate
- Metric collection overhead and performance
- Dashboard query performance

## Security Considerations

### Sensitive Data Protection
- No credentials or secrets in logs or metrics
- Request/response bodies excluded from default logging
- IP address logging configurable for privacy compliance
- Secure notification channel configurations

### Access Control
- Health endpoints accessible without authentication (for load balancers)
- Metrics endpoint may be restricted in production
- Alert notifications sent only to authorized channels
- Dashboard access controlled via Azure RBAC

## Maintenance

### Regular Tasks
- **Weekly** - Review alert effectiveness and false positive rates
- **Monthly** - Update dashboard configurations and add new metrics
- **Quarterly** - Tune alert thresholds based on historical data
- **Annually** - Review and update notification channels and escalation procedures

### Monitoring Drift
- Track metric cardinality growth over time
- Monitor storage costs for telemetry data
- Review and cleanup obsolete metrics and alerts
- Update health checks as system components change

## Troubleshooting

### Common Issues
- **Missing Metrics** - Check middleware configuration and Prometheus endpoint
- **Failed Health Checks** - Review component timeouts and network connectivity
- **Alert Not Firing** - Verify alert rule conditions and cooldown periods
- **Missing Notifications** - Check notification channel configurations

### Debug Mode
Enable debug logging for detailed monitoring information:
```bash
export SIGIL_LOG_LEVEL=DEBUG
export SIGIL_STRUCTURED_LOGGING=true
```

## Future Enhancements

### Planned Features
- **Distributed Tracing** - Full request tracing across microservices
- **Custom Dashboards** - User-configurable monitoring dashboards
- **ML-Based Anomaly Detection** - Automatic threshold adjustment
- **Integration Testing** - Synthetic transaction monitoring
- **Cost Optimization** - Intelligent sampling and retention policies

### Integration Roadmap
- **Kubernetes** - Native Kubernetes monitoring with service mesh integration
- **Multi-Region** - Cross-region monitoring and alerting
- **Third-Party Tools** - Integration with Datadog, New Relic, etc.
- **CI/CD Monitoring** - Deployment and pipeline monitoring

---

**Document Version**: 1.0  
**Last Updated**: 2024-01-01  
**Maintained By**: DevOps Team