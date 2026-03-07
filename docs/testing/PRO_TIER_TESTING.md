# Pro Tier Testing Guide

Comprehensive testing documentation for Sigil's Pro tier ($29/month) LLM-powered threat detection features.

## Overview

The Pro tier test suite ensures reliability and quality of premium features including:
- AI-powered threat analysis (LLM integration)
- Zero-day vulnerability detection
- Advanced obfuscation analysis  
- Contextual threat correlation
- Pro subscription management and billing
- Tier-based access control and gating

## Test Coverage Goals

- **90% code coverage** for all Pro-related modules
- **100% path coverage** for billing and tier gating logic
- **Integration testing** for all Pro API endpoints
- **Error scenario testing** for LLM failures and network issues
- **Performance testing** for response times and throughput

## Test Structure

### Core Test Files

```
api/tests/
├── test_pro_tier.py              # Comprehensive Pro tier integration tests
├── test_billing_integration.py   # Stripe billing and webhook testing
├── test_phase9_llm.py            # LLM service and Phase 9 analysis
├── test_analytics_service.py     # Analytics tracking and metrics
├── test_tier_gating.py           # Access control and tier validation
├── test_pro_performance.py       # Performance and load testing
├── fixtures/
│   └── pro_fixtures.py          # Reusable test fixtures and mock data
└── conftest.py                   # Base test configuration
```

### Test Categories

#### 1. **Core Pro Functionality** (`test_pro_tier.py`)
- Subscription upgrade/downgrade flows
- LLM analysis integration and gating
- Pro dashboard features and capabilities
- End-to-end Pro user journey testing
- Feature flag and tier validation

#### 2. **Billing Integration** (`test_billing_integration.py`)  
- Stripe Checkout Session creation and completion
- Webhook event processing (subscription lifecycle)
- Payment failure and retry scenarios
- Customer portal integration
- Billing edge cases and error handling

#### 3. **LLM Analysis Engine** (`test_phase9_llm.py`)
- LLM service configuration and API integration
- Threat analysis prompt generation and processing
- Zero-day vulnerability detection capabilities
- Context correlation and attack chain analysis
- Response parsing and insight extraction
- Caching and performance optimization
- Provider integration (OpenAI, Anthropic, Azure)

#### 4. **Analytics and Tracking** (`test_analytics_service.py`)
- LLM usage tracking and metrics collection
- Threat discovery analytics and categorization
- Pro feature usage monitoring
- Performance metrics and response time tracking
- Data retention and privacy compliance
- Aggregate statistics and reporting

#### 5. **Tier Gating and Access Control** (`test_tier_gating.py`)
- Middleware authentication and authorization
- Feature capability checking and reporting
- Subscription status validation
- Access denial responses and upgrade messaging
- Edge cases and error handling in tier checks

#### 6. **Performance and Load Testing** (`test_pro_performance.py`)
- LLM API response time and throughput
- Concurrent Pro user request handling
- Database performance for subscription checks
- Rate limiting behavior under load
- Memory usage and resource optimization
- Stress testing and breaking point analysis

## Running the Tests

### Prerequisites

```bash
cd api
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov pytest-mock httpx
```

### Basic Test Execution

```bash
# Run all Pro tier tests
pytest tests/test_pro_tier.py tests/test_billing_integration.py tests/test_phase9_llm.py tests/test_analytics_service.py tests/test_tier_gating.py -v

# Run specific test category
pytest tests/test_pro_tier.py -v

# Run with coverage
pytest tests/test_pro_tier.py --cov=services/llm_service --cov=middleware/tier_check --cov-report=html
```

### Advanced Test Options

```bash
# Run only Pro tier integration tests
pytest tests/test_pro_tier.py::TestProTierIntegration -v

# Run performance tests (slower)
pytest tests/test_pro_performance.py -v --tb=short

# Run with specific markers
pytest -m "pro_tier and not slow" -v

# Run load tests (requires environment flag)
SIGIL_PERFORMANCE_TESTS=1 pytest tests/test_pro_performance.py::TestStressTestingAndLimits -v
```

### CI/CD Integration

The test suite includes comprehensive CI/CD integration via GitHub Actions:

```bash
# Trigger Pro tier tests workflow
git push origin feature-branch

# Run load tests (requires label)
# Add "load-test" label to PR to trigger load testing
```

## Test Configuration

### Environment Variables

Required for testing:

```bash
export SIGIL_TEST_MODE=1
export SIGIL_LLM_PROVIDER=mock
export SIGIL_DB_TYPE=memory
export SIGIL_STRIPE_CONFIGURED=0  # Use stub mode for unit tests
```

For integration testing with real services:

```bash
export SIGIL_LLM_PROVIDER=openai
export SIGIL_LLM_API_KEY=your-test-api-key
export SIGIL_STRIPE_CONFIGURED=1
export SIGIL_STRIPE_SECRET_KEY=sk_test_...
export SIGIL_STRIPE_WEBHOOK_SECRET=whsec_test_...
```

### Test Markers

Use pytest markers to run specific test categories:

```bash
pytest -m "billing" -v           # Billing integration tests
pytest -m "llm" -v              # LLM service tests  
pytest -m "analytics" -v        # Analytics tracking tests
pytest -m "tier_gating" -v      # Access control tests
pytest -m "performance" -v      # Performance tests
pytest -m "integration" -v      # Integration tests
pytest -m "security" -v         # Security-focused tests
pytest -m "slow" -v             # Long-running tests
```

## Mock Data and Fixtures

### LLM Analysis Mocks

```python
# Comprehensive LLM insights for testing
from api.tests.fixtures.pro_fixtures import comprehensive_llm_insights, mock_context_analysis

# Sample usage in tests
def test_llm_analysis(comprehensive_llm_insights):
    insights = comprehensive_llm_insights
    assert len(insights) == 4
    assert insights[0]["threat_category"] == "code_injection"
```

### Stripe Webhook Data

```python
# Stripe webhook events for testing
from api.tests.fixtures.pro_fixtures import stripe_webhook_events

def test_webhook_processing(stripe_webhook_events):
    checkout_event = stripe_webhook_events["checkout_session_completed"]
    # Process webhook event...
```

### Subscription Data

```python
# Various subscription states for testing
from api.tests.fixtures.pro_fixtures import subscription_data

def test_subscription_states(subscription_data):
    pro_active = subscription_data["pro_active"]
    assert pro_active["has_pro_features"] is True
```

## Performance Benchmarks

### Response Time Targets

- **LLM Analysis**: < 5s end-to-end (excluding actual LLM latency)
- **Subscription Check**: < 100ms average
- **Tier Gating**: < 50ms average  
- **Billing Operations**: < 200ms average

### Throughput Targets

- **Concurrent LLM Requests**: 20+ requests/second
- **Subscription Checks**: 100+ checks/second
- **Analytics Tracking**: 50+ events/second

### Load Testing Scenarios

```python
# Test concurrent Pro users
pytest tests/test_pro_performance.py::TestLLMServicePerformance::test_concurrent_llm_requests_performance -v

# Test stress conditions
pytest tests/test_pro_performance.py::TestStressTestingAndLimits::test_high_concurrency_stress -v

# Test memory usage
pytest tests/test_pro_performance.py::TestMemoryAndResourceUsage::test_llm_service_memory_usage -v
```

## Error Scenarios and Edge Cases

### LLM Service Failures

- API timeouts and rate limiting
- Invalid response formats
- Provider unavailability
- Network connectivity issues
- Configuration errors

### Billing Edge Cases

- Invalid webhook signatures
- Orphaned Stripe customers
- Malformed subscription data
- Payment processing failures
- Subscription state inconsistencies

### Tier Gating Edge Cases

- Database connection failures
- Invalid tier data
- Concurrent access patterns
- Cache invalidation scenarios
- Authorization edge cases

## Debugging and Troubleshooting

### Common Issues

1. **LLM Tests Failing**
   ```bash
   # Check LLM configuration
   pytest tests/test_phase9_llm.py::TestLLMServiceConfiguration -v -s
   ```

2. **Billing Tests Failing**
   ```bash
   # Verify Stripe configuration
   export SIGIL_STRIPE_CONFIGURED=0  # Use stub mode
   pytest tests/test_billing_integration.py -v
   ```

3. **Performance Tests Slow**
   ```bash
   # Run with profiling
   pytest tests/test_pro_performance.py --profile -v
   ```

4. **Database Issues**
   ```bash
   # Use memory database for tests
   export SIGIL_DB_TYPE=memory
   pytest tests/test_tier_gating.py -v
   ```

### Verbose Logging

```bash
# Enable detailed logging
export SIGIL_LOG_LEVEL=DEBUG
pytest tests/test_pro_tier.py -v -s
```

### Test Data Inspection

```python
# Access test fixtures directly
from api.tests.fixtures.pro_fixtures import *

# Inspect mock data
insights = comprehensive_llm_insights()
print(json.dumps(insights, indent=2))
```

## Integration with Development Workflow

### Pre-Commit Testing

```bash
# Run essential Pro tier tests before committing
pytest tests/test_pro_tier.py::TestSubscriptionUpgradeFlow -v
pytest tests/test_tier_gating.py::TestTierGatingMiddleware -v
pytest tests/test_billing_integration.py::TestWebhookProcessing -v
```

### Feature Development Testing

When developing new Pro tier features:

1. **Start with Unit Tests**
   ```bash
   pytest tests/test_pro_tier.py -v --tb=short
   ```

2. **Add Integration Tests**
   ```bash
   pytest tests/test_billing_integration.py -v
   ```

3. **Validate Performance**
   ```bash
   pytest tests/test_pro_performance.py::TestLLMServicePerformance -v
   ```

4. **Security Testing**
   ```bash
   pytest tests/test_tier_gating.py::TestTierGatingEdgeCases -v
   ```

### CI/CD Pipeline Integration

The test suite is automatically executed in CI/CD:

- **Pull Request**: Core Pro tier tests + security validation
- **Main Branch**: Full test suite including performance tests  
- **Daily Schedule**: Complete test suite + load testing
- **Release Candidates**: Full test suite + stress testing

### Coverage Requirements

- **Minimum Coverage**: 85% for Pro tier modules
- **Critical Paths**: 100% coverage for billing and tier gating
- **Security Features**: 100% coverage for access control logic
- **Performance Critical**: 90% coverage for LLM and analytics services

## Future Enhancements

### Planned Test Improvements

1. **Enhanced Load Testing**
   - Multi-region load testing
   - Database performance under load
   - Network partition scenarios

2. **Advanced Security Testing**
   - Penetration testing automation
   - Fuzzing for API endpoints
   - Authorization bypass testing

3. **Monitoring Integration**
   - Real-time performance monitoring
   - Test result analytics
   - Automated performance regression detection

4. **Test Data Management**
   - Automated test data generation
   - Production data anonymization for testing
   - Test environment provisioning

## Resources

- [Pro Tier Feature Documentation](../features/pro-tier.md)
- [LLM Integration Guide](../integrations/llm-providers.md)
- [Billing Integration Docs](../integrations/stripe-billing.md)
- [Performance Optimization Guide](../performance/optimization.md)
- [Security Testing Checklist](../security/testing-checklist.md)

## Support

For questions about Pro tier testing:

1. Review this documentation
2. Check existing test examples in the test files
3. Examine test fixtures for mock data patterns
4. Run tests with verbose output for debugging
5. Contact the development team for complex scenarios

## Test Suite Maintenance

### Regular Maintenance Tasks

- Update test fixtures when Pro tier features evolve
- Review and update performance benchmarks
- Maintain compatibility with new LLM providers
- Update billing integration tests for Stripe API changes
- Refresh security testing scenarios based on threat landscape

### Adding New Tests

When adding new Pro tier functionality:

1. Add unit tests for core logic
2. Add integration tests for API endpoints
3. Add performance tests for critical paths
4. Update test fixtures with new mock data
5. Update this documentation with new test categories