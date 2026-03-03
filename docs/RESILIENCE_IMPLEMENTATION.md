# Sigil Error Handling and Resilience Implementation

## Overview

This document summarizes the comprehensive error handling, recovery mechanisms, and resilience patterns implemented for the Sigil API system. The implementation provides a robust foundation for handling failures gracefully while maintaining service availability.

## Components Implemented

### 1. Error Handling Framework (`api/errors.py`)

**Standardized Error Types and Responses:**
- Comprehensive error categorization (Transient, Permanent, User Error, System, External)
- Severity levels (Low, Medium, High, Critical)
- Standardized error codes for programmatic handling
- Correlation IDs for error tracking across services
- Contextual error information for debugging

**Key Features:**
- `SigilError` base class with rich metadata
- `ErrorTracker` for correlation and analysis
- Automatic error context extraction
- Time-based error cleanup

### 2. Circuit Breaker Patterns (`api/circuit_breakers.py`)

**Service-Specific Circuit Breakers:**
- GitHub API circuit breaker (high tolerance for rate limits)
- Claude API circuit breaker (standard settings for LLM calls)
- Database circuit breaker (fast recovery for critical service)
- Redis circuit breaker (very tolerant for cache failures)
- SMTP circuit breaker (email notification handling)

**Key Features:**
- Exponential backoff with configurable parameters
- Failure rate monitoring with sliding windows
- Automatic state transitions (Closed → Open → Half-Open)
- Manual circuit breaker reset capabilities
- Comprehensive status reporting

### 3. Retry Mechanisms (`api/retry.py`)

**Intelligent Retry Logic:**
- Exponential backoff with jitter to prevent thundering herd
- Service-specific retry configurations
- Retryable error detection (network, timeout, rate limit)
- Total timeout and per-attempt timeout controls
- Retry attempt tracking and reporting

**Predefined Configurations:**
- GitHub API: 5 attempts, high tolerance for rate limits
- Claude API: 3 attempts, longer timeouts for LLM processing
- Database: 5 attempts, quick recovery cycles
- Redis: 3 attempts, fast timeout for cache operations
- SMTP: 3 attempts, longer delays for email delivery

### 4. Database Resilience (`api/database_resilience.py`)

**Enhanced Database Connection Management:**
- Connection pool health monitoring
- Automatic connection recovery
- Performance metrics tracking (query times, success rates)
- Circuit breaker integration for database operations
- Background health monitoring with recovery attempts

**Key Features:**
- `ResilientDatabaseManager` with health monitoring
- `ResilientRedisManager` for cache operations
- Automatic retry on connection failures
- Graceful degradation to in-memory fallbacks
- Connection pool statistics and alerting

### 5. Background Job Resilience (`api/background_job_resilience.py`)

**Robust Job Processing System:**
- Dead letter queue for failed jobs
- Job state tracking with comprehensive metadata
- Priority-based job queuing
- Automatic job retry with exponential backoff
- Stalled job detection and recovery

**Job Management Features:**
- Job execution with circuit breaker protection
- Worker pool management with graceful shutdown
- Job requeuing from dead letter queue
- Background monitoring for job health
- Configurable retry policies per job type

### 6. Graceful Degradation (`api/graceful_degradation.py`)

**Service Degradation Patterns:**
- Dependency health tracking
- Graduated degradation levels (Full → Reduced → Minimal → Unavailable)
- Service-specific fallback responses
- Cached fallback data management
- Real-time degradation status updates

**Degradation Levels:**
- **Full**: All features available
- **Reduced**: Some advanced features disabled
- **Minimal**: Core features only
- **Unavailable**: Service completely down

### 7. Monitoring and Alerting (`api/monitoring.py`)

**Comprehensive System Monitoring:**
- Metrics collection (counters, gauges, histograms)
- Real-time alert management
- Configurable alert thresholds
- Multiple alert delivery channels (Log, Email, Webhook, Console)
- Alert suppression and resolution tracking

**Key Metrics:**
- Error rates with severity tracking
- Response time percentiles (P50, P90, P95, P99)
- Circuit breaker states
- Database connection health
- Job queue statistics

### 8. Integrated Resilience Middleware (`api/resilience_middleware.py`)

**Unified Error Handling:**
- Request correlation ID generation
- Automatic error tracking and classification
- Graceful degradation integration
- Comprehensive error response formatting
- Alert triggering for critical errors

**Enhanced Health Checks:**
- Multi-component health monitoring
- Resilience system status reporting
- Manual recovery trigger endpoints
- Detailed monitoring status API

## Integration Points

### Application Startup
```python
# In api/main.py lifespan function
await initialize_resilience_systems()
```

### Middleware Stack
```python
# Resilience middleware (should be early in the stack)
app.add_middleware(ResilienceMiddleware)

# Other middleware follows
app.add_middleware(CORSMiddleware, ...)
app.add_middleware(RateLimitMiddleware, ...)
```

### Service Usage Patterns

#### Circuit Breaker + Retry Protection
```python
from api.retry import protected

@protected("github_api", max_attempts=5)
async def fetch_repository_info(repo_url: str):
    # Function automatically protected by circuit breaker and retry
    return await github_client.get_repo(repo_url)
```

#### Database Operations with Resilience
```python
from api.database_resilience import with_database_resilience

@with_database_resilience(fallback_result=[])
async def get_user_scans(user_id: str):
    return await db.select("scans", {"user_id": user_id})
```

#### Background Job Processing
```python
from api.background_job_resilience import background_job

@background_job(priority=JobPriority.HIGH, max_attempts=5)
async def process_security_scan(repo_url: str):
    # Job automatically queued with retry and error handling
    return await perform_scan(repo_url)
```

## Health Check Endpoints

### Enhanced Health Check
```
GET /health
```
Returns comprehensive health status including:
- Database and cache connectivity
- Circuit breaker states
- Job queue statistics
- Degradation status
- Monitoring system health

### Simple Health Check (for load balancers)
```
GET /health/simple
```
Returns basic health status for load balancer checks.

### Manual Recovery Trigger
```
POST /admin/recovery
```
Manually triggers system recovery procedures:
- Reset open circuit breakers
- Attempt database connection recovery
- Clean up old error tracking data

### Monitoring Status
```
GET /admin/monitoring
```
Returns detailed monitoring system status and metrics.

## Configuration

### Environment Variables

Key environment variables for resilience configuration:

```bash
# Database resilience
SIGIL_DATABASE_URL=...

# Redis/Cache resilience
SIGIL_REDIS_URL=...

# Monitoring and alerting
SIGIL_METRICS_ENABLED=true
SIGIL_ALERT_CHANNELS=log,email

# SMTP for email alerts
SIGIL_SMTP_HOST=...
SIGIL_SMTP_USER=...
SIGIL_SMTP_PASSWORD=...
```

### Circuit Breaker Thresholds

Circuit breakers can be customized through configuration objects:

```python
# Example: Custom GitHub API circuit breaker
GITHUB_CONFIG = CircuitBreakerConfig(
    service_name="github_api",
    failure_threshold=10,
    success_threshold=3,
    timeout_duration=300.0,
    call_timeout=30.0,
)
```

### Alert Thresholds

Alert thresholds are configurable:

```python
alert_thresholds = AlertThresholds(
    error_rate_warning=10.0,      # errors per minute
    error_rate_critical=50.0,
    response_time_warning=2.0,    # seconds
    response_time_critical=10.0,
    circuit_breakers_open_warning=1,
    circuit_breakers_open_critical=3,
)
```

## Error Response Format

All errors follow a standardized format:

```json
{
  "error": {
    "code": "database_error",
    "message": "Database operation failed",
    "category": "transient",
    "severity": "high",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2023-12-07T10:30:00Z",
    "retry_after": 60,
    "context": {
      "endpoint": "/api/v1/scans",
      "request_id": "req-123",
      "operation": "select"
    }
  },
  "request_id": "req-123",
  "documentation_url": "https://docs.sigilsec.ai/errors"
}
```

## Monitoring and Alerting

### Metrics Collected

1. **Request Metrics:**
   - Response times (histogram)
   - Request counts by endpoint and status
   - Error counts by type and severity

2. **System Metrics:**
   - Circuit breaker states
   - Database connection health
   - Job queue statistics
   - Error rates

3. **Performance Metrics:**
   - Database query response times
   - External service response times
   - Cache hit/miss rates

### Alert Conditions

Automatic alerts are triggered for:

- Error rate exceeds threshold (10/min warning, 50/min critical)
- Response times exceed threshold (2s warning, 10s critical)
- Circuit breakers open (1 warning, 3+ critical)
- Database connectivity issues
- High number of failed background jobs

## Best Practices

### For Developers

1. **Use Resilience Decorators:**
   ```python
   @protected("external_service", max_attempts=3)
   async def call_external_api():
       # Your code here
   ```

2. **Handle Expected Errors:**
   ```python
   try:
       result = await protected_operation()
   except CircuitBreakerOpenError:
       # Provide fallback response
       return cached_fallback_data()
   ```

3. **Log with Context:**
   ```python
   logger.error("Operation failed", extra={
       "correlation_id": request.state.correlation_id,
       "user_id": user_id,
       "operation": "scan_repository"
   })
   ```

### For Operations

1. **Monitor Health Endpoints:**
   - Set up monitoring for `/health` endpoint
   - Alert on degraded health status
   - Use `/health/simple` for load balancer checks

2. **Alert Configuration:**
   - Configure SMTP for email alerts
   - Set up webhook endpoints for external alerting systems
   - Adjust alert thresholds based on traffic patterns

3. **Recovery Procedures:**
   - Use `/admin/recovery` endpoint for manual recovery
   - Monitor circuit breaker states
   - Check dead letter queue regularly

## Testing

The resilience system can be tested through:

1. **Chaos Engineering:**
   - Temporarily disable external services
   - Inject database connection failures
   - Simulate high error rates

2. **Load Testing:**
   - Monitor circuit breaker behavior under load
   - Verify graceful degradation
   - Test alert triggering

3. **Recovery Testing:**
   - Test manual recovery procedures
   - Verify automatic recovery mechanisms
   - Validate alert resolution

## Future Enhancements

Potential areas for future improvement:

1. **Advanced Monitoring:**
   - Integration with Prometheus/Grafana
   - Distributed tracing with OpenTelemetry
   - Custom metrics dashboards

2. **Enhanced Resilience:**
   - Bulkhead isolation patterns
   - Advanced fallback strategies
   - Predictive circuit breaking

3. **Automation:**
   - Automated recovery procedures
   - Self-healing capabilities
   - Adaptive threshold adjustment

## Conclusion

This comprehensive resilience implementation provides a solid foundation for handling failures gracefully while maintaining service availability. The system is designed to be:

- **Robust**: Multiple layers of protection against failures
- **Observable**: Comprehensive monitoring and alerting
- **Recoverable**: Automatic and manual recovery mechanisms
- **Maintainable**: Clear separation of concerns and standardized patterns
- **Scalable**: Configurable thresholds and distributed-friendly design

The implementation follows industry best practices and provides the operational visibility needed to maintain a reliable service in production.