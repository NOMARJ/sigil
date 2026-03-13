"""
Tests for Sigil API monitoring system.

Validates health checks, metrics collection, alerting, and observability
functionality to ensure production monitoring works correctly.
"""

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from api.main import app
from api.monitoring import (
    Alert,
    AlertCategory,
    AlertManager,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    EmailChannel,
    HealthCheck,
    HealthCheckManager,
    HealthStatus,
    ComponentType,
    MetricsMiddleware,
    MonitoringManager,
    SlackChannel,
)


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def test_client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def health_manager():
    """Health check manager for testing."""
    return HealthCheckManager()


@pytest.fixture
def monitoring_manager():
    """Monitoring manager for testing."""
    return MonitoringManager()


@pytest.fixture
def alert_manager():
    """Alert manager for testing."""
    return AlertManager()


@pytest.fixture
def sample_alert():
    """Sample alert for testing."""
    return Alert(
        id="test-alert-123",
        name="Test Alert",
        description="This is a test alert",
        severity=AlertSeverity.HIGH,
        category=AlertCategory.APPLICATION,
        status=AlertStatus.FIRING,
        timestamp=datetime.now(timezone.utc),
        value=10.5,
        threshold=5.0,
        tags={"component": "api", "environment": "test"},
        metadata={"request_id": "req-123", "user_id": "user-456"},
    )


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------


class TestHealthChecks:
    """Test health check functionality."""

    def test_basic_health_endpoint(self, test_client):
        """Test basic health endpoint."""
        response = test_client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "database_connected" in data
        assert "redis_connected" in data

    def test_detailed_health_endpoint(self, test_client):
        """Test detailed health endpoint."""
        response = test_client.get("/health/detailed")
        assert response.status_code in [200, 503]  # May be degraded

        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "environment" in data
        assert "summary" in data
        assert "checks" in data

        # Validate summary structure
        summary = data["summary"]
        assert "total_checks" in summary
        assert "healthy" in summary
        assert "degraded" in summary
        assert "unhealthy" in summary
        assert "critical_failures" in summary

    def test_readiness_probe(self, test_client):
        """Test Kubernetes readiness probe."""
        response = test_client.get("/health/ready")
        assert response.status_code in [200, 503]

        data = response.json()
        assert "ready" in data
        assert "timestamp" in data

    def test_liveness_probe(self, test_client):
        """Test Kubernetes liveness probe."""
        response = test_client.get("/health/live")
        assert response.status_code == 200

        data = response.json()
        assert data["alive"] is True
        assert "timestamp" in data
        assert "version" in data

    @pytest.mark.asyncio
    async def test_health_check_creation(self):
        """Test health check creation and execution."""

        async def mock_check():
            return {"status": "ok", "test": True}

        check = HealthCheck(
            name="test_check",
            component_type=ComponentType.DATABASE,
            check_function=mock_check,
            timeout=5.0,
            critical=True,
        )

        result = await check.run()

        assert result["name"] == "test_check"
        assert result["status"] == HealthStatus.HEALTHY
        assert result["component_type"] == ComponentType.DATABASE.value
        assert result["critical"] is True
        assert "duration" in result
        assert "timestamp" in result
        assert result["details"]["test"] is True

    @pytest.mark.asyncio
    async def test_health_check_timeout(self):
        """Test health check timeout handling."""

        async def slow_check():
            await asyncio.sleep(10)  # Longer than timeout
            return {"status": "ok"}

        check = HealthCheck(
            name="slow_check",
            component_type=ComponentType.EXTERNAL_API,
            check_function=slow_check,
            timeout=0.1,  # Very short timeout
            critical=False,
        )

        result = await check.run()

        assert result["name"] == "slow_check"
        assert result["status"] == HealthStatus.UNHEALTHY
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_health_check_exception(self):
        """Test health check exception handling."""

        async def failing_check():
            raise ValueError("Test error")

        check = HealthCheck(
            name="failing_check",
            component_type=ComponentType.CACHE,
            check_function=failing_check,
            timeout=5.0,
            critical=True,
        )

        result = await check.run()

        assert result["name"] == "failing_check"
        assert result["status"] == HealthStatus.UNHEALTHY
        assert "Test error" in result["error"]
        assert "traceback" in result

    @pytest.mark.asyncio
    async def test_health_check_manager(self, health_manager):
        """Test health check manager functionality."""

        # Add a mock check
        async def mock_check():
            return {"test": "passed"}

        check = HealthCheck(
            name="manager_test",
            component_type=ComponentType.DATABASE,
            check_function=mock_check,
            critical=True,
        )

        health_manager.register_check(check)

        result = await health_manager.run_all_checks()

        assert "status" in result
        assert "timestamp" in result
        assert "summary" in result
        assert "checks" in result

        # Find our test check
        test_check = next(
            (c for c in result["checks"] if c["name"] == "manager_test"), None
        )
        assert test_check is not None
        assert test_check["status"] == HealthStatus.HEALTHY


# ---------------------------------------------------------------------------
# Metrics Tests
# ---------------------------------------------------------------------------


class TestMetrics:
    """Test metrics collection functionality."""

    def test_prometheus_metrics_endpoint(self, test_client):
        """Test Prometheus metrics endpoint."""
        response = test_client.get("/metrics")
        assert response.status_code == 200
        assert (
            response.headers["content-type"]
            == "text/plain; version=0.0.4; charset=utf-8"
        )

        content = response.text
        assert "http_requests_total" in content
        assert "http_request_duration_seconds" in content

    @pytest.mark.asyncio
    async def test_metrics_middleware(self):
        """Test metrics middleware functionality."""
        # Create mock request and call_next
        request = Mock()
        request.method = "GET"
        request.url.path = "/test/endpoint"
        request.client.host = "127.0.0.1"
        request.headers = {"user-agent": "test-agent"}
        request.state = Mock()

        response = Mock()
        response.status_code = 200
        response.headers = {}

        call_next = AsyncMock(return_value=response)

        middleware = MetricsMiddleware(Mock())

        # Process request
        result = await middleware.dispatch(request, call_next)

        assert result == response
        assert hasattr(request.state, "correlation_id")
        assert "X-Correlation-ID" in response.headers

        call_next.assert_called_once_with(request)

    def test_path_normalization(self):
        """Test URL path normalization for metrics."""
        middleware = MetricsMiddleware(Mock())

        # Test UUID replacement
        path1 = middleware._normalize_path(
            "/api/v1/users/123e4567-e89b-12d3-a456-426614174000/profile"
        )
        assert path1 == "/api/v1/users/{uuid}/profile"

        # Test ID replacement
        path2 = middleware._normalize_path("/api/v1/scans/12345")
        assert path2 == "/api/v1/scans/{id}"

        # Test complex ID replacement
        path3 = middleware._normalize_path("/registry/packages/abcdef123456789012345")
        assert path3 == "/registry/packages/{id}"

    def test_user_type_detection(self):
        """Test user type detection from user agent."""
        middleware = MetricsMiddleware(Mock())

        # Test different user agents
        request_human = Mock()
        request_human.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        assert middleware._determine_user_type(request_human) == "human"

        request_curl = Mock()
        request_curl.headers = {"user-agent": "curl/7.68.0"}
        assert middleware._determine_user_type(request_curl) == "agent"

        request_claude = Mock()
        request_claude.headers = {"user-agent": "Claude/1.0"}
        assert middleware._determine_user_type(request_claude) == "ai_agent"

        request_python = Mock()
        request_python.headers = {"user-agent": "python-httpx/0.24.0"}
        assert middleware._determine_user_type(request_python) == "agent"

    def test_endpoint_categorization(self):
        """Test API endpoint categorization."""
        middleware = MetricsMiddleware(Mock())

        assert middleware._categorize_endpoint("/v1/scan/submit") == "scan"
        assert middleware._categorize_endpoint("/api/threat/lookup") == "threat_intel"
        assert middleware._categorize_endpoint("/registry/packages") == "registry"
        # Forge endpoints removed - testing alternate path instead
        assert middleware._categorize_endpoint("/dashboard/tools") == "dashboard"
        assert middleware._categorize_endpoint("/auth/login") == "auth"
        assert middleware._categorize_endpoint("/billing/subscribe") == "billing"
        assert middleware._categorize_endpoint("/some/other/path") == "other"

    @pytest.mark.asyncio
    async def test_business_metrics_recording(self, monitoring_manager):
        """Test business metrics recording."""
        # Test tool classification recording
        await monitoring_manager.record_tool_classification("security", 0.9)
        await monitoring_manager.record_tool_classification("productivity", 0.6)
        await monitoring_manager.record_tool_classification("unknown", 0.3)

        # Test security alert recording
        await monitoring_manager.record_security_alert("typosquatting", "high")
        await monitoring_manager.record_security_alert("prompt_injection", "medium")

        # Test search query recording
        await monitoring_manager.record_search_query("package_search", 25)
        await monitoring_manager.record_search_query("tool_search", 0)
        await monitoring_manager.record_search_query("threat_search", 150)

        # Verify metrics were recorded (would check actual values in real implementation)


# ---------------------------------------------------------------------------
# Alert Tests
# ---------------------------------------------------------------------------


class TestAlerts:
    """Test alerting functionality."""

    def test_alert_creation(self, sample_alert):
        """Test alert model creation."""
        assert sample_alert.id == "test-alert-123"
        assert sample_alert.name == "Test Alert"
        assert sample_alert.severity == AlertSeverity.HIGH
        assert sample_alert.category == AlertCategory.APPLICATION
        assert sample_alert.status == AlertStatus.FIRING
        assert sample_alert.value == 10.5
        assert sample_alert.threshold == 5.0
        assert sample_alert.tags["component"] == "api"

    @pytest.mark.asyncio
    async def test_alert_rule_evaluation(self):
        """Test alert rule evaluation."""

        # Mock condition that returns True (alert should fire)
        async def mock_condition():
            return True

        rule = AlertRule(
            name="Test Rule",
            description="Test alert rule",
            category=AlertCategory.PERFORMANCE,
            severity=AlertSeverity.MEDIUM,
            condition_func=mock_condition,
            threshold=5.0,
            cooldown_minutes=1,
        )

        alert = await rule.evaluate()

        assert alert is not None
        assert alert.name == "Test Rule"
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.status == AlertStatus.FIRING

    @pytest.mark.asyncio
    async def test_alert_rule_cooldown(self):
        """Test alert rule cooldown period."""
        call_count = 0

        async def mock_condition():
            nonlocal call_count
            call_count += 1
            return True

        rule = AlertRule(
            name="Cooldown Test",
            description="Test cooldown",
            category=AlertCategory.APPLICATION,
            severity=AlertSeverity.LOW,
            condition_func=mock_condition,
            cooldown_minutes=60,  # Long cooldown
        )

        # First evaluation should fire
        alert1 = await rule.evaluate()
        assert alert1 is not None

        # Second evaluation should be suppressed by cooldown
        alert2 = await rule.evaluate()
        assert alert2 is None

        assert call_count == 1  # Condition only called once

    @pytest.mark.asyncio
    async def test_email_channel(self):
        """Test email notification channel."""
        with patch("smtplib.SMTP") as mock_smtp:
            # Mock SMTP server
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            # Mock settings
            with patch("api.monitoring.alerting.settings") as mock_settings:
                mock_settings.smtp_configured = True
                mock_settings.smtp_host = "smtp.test.com"
                mock_settings.smtp_port = 587
                mock_settings.smtp_user = "test@test.com"
                mock_settings.smtp_password = "password"
                mock_settings.smtp_from_email = "alerts@test.com"

                channel = EmailChannel(["ops@test.com"])
                alert = Alert(
                    id="email-test",
                    name="Email Test",
                    description="Test email alert",
                    severity=AlertSeverity.HIGH,
                    category=AlertCategory.APPLICATION,
                    status=AlertStatus.FIRING,
                    timestamp=datetime.now(timezone.utc),
                )

                result = await channel.send(alert)

                assert result is True
                mock_server.starttls.assert_called_once()
                mock_server.login.assert_called_once()
                mock_server.sendmail.assert_called_once()

    @pytest.mark.asyncio
    async def test_slack_channel(self):
        """Test Slack notification channel."""
        with patch("httpx.AsyncClient") as mock_client:
            # Mock HTTP client
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status.return_value = None

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            channel = SlackChannel("https://hooks.slack.com/test", "#alerts")
            alert = Alert(
                id="slack-test",
                name="Slack Test",
                description="Test Slack alert",
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.SECURITY,
                status=AlertStatus.FIRING,
                timestamp=datetime.now(timezone.utc),
            )

            result = await channel.send(alert)

            assert result is True

    @pytest.mark.asyncio
    async def test_alert_manager_integration(self, alert_manager):
        """Test alert manager integration."""
        fired_alerts = []

        # Mock condition that fires an alert
        async def test_condition():
            return 15.0  # Above threshold

        # Create test rule
        rule = AlertRule(
            name="Integration Test",
            description="Test integration",
            category=AlertCategory.PERFORMANCE,
            severity=AlertSeverity.HIGH,
            condition_func=test_condition,
            threshold=10.0,
            cooldown_minutes=1,
        )

        # Mock channel that captures alerts
        class MockChannel:
            async def send(self, alert):
                fired_alerts.append(alert)
                return True

        alert_manager.register_rule(rule)
        alert_manager.register_channel(AlertSeverity.HIGH, MockChannel())

        # Evaluate rules
        await alert_manager.evaluate_all_rules()

        # Check that alert was fired and sent
        assert len(fired_alerts) == 1
        alert = fired_alerts[0]
        assert alert.name == "Integration Test"
        assert alert.value == 15.0
        assert alert.threshold == 10.0


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestMonitoringIntegration:
    """Test monitoring system integration."""

    def test_full_request_cycle_with_monitoring(self, test_client):
        """Test a complete request cycle with monitoring enabled."""
        # Clear any existing metrics
        REGISTRY._collector_to_names.clear()
        REGISTRY._names_to_collectors.clear()

        # Make several requests to generate metrics
        for i in range(5):
            response = test_client.get(f"/health?test={i}")
            assert response.status_code == 200

        # Check that metrics were recorded
        metrics_response = test_client.get("/metrics")
        assert metrics_response.status_code == 200

        content = metrics_response.text
        assert "http_requests_total" in content

    @pytest.mark.asyncio
    async def test_monitoring_system_startup(self):
        """Test monitoring system startup and configuration."""
        monitoring = MonitoringManager()

        # Verify health manager is initialized
        assert monitoring.health_manager is not None
        assert len(monitoring.health_manager.checks) > 0

        # Verify metrics are enabled
        assert monitoring.metrics_enabled is True

    def test_structured_logging_correlation(self, test_client):
        """Test structured logging with correlation IDs."""
        response = test_client.get("/health")

        # Check that correlation ID is returned
        assert "X-Correlation-ID" in response.headers
        correlation_id = response.headers["X-Correlation-ID"]

        # Verify UUID format
        import uuid

        try:
            uuid.UUID(correlation_id)
            assert True
        except ValueError:
            assert False, "Correlation ID is not a valid UUID"

    def test_error_handling_with_monitoring(self, test_client):
        """Test error handling with monitoring enabled."""
        # Make request to non-existent endpoint
        response = test_client.get("/nonexistent")
        assert response.status_code == 404

        # Verify correlation ID is still present
        assert "X-Correlation-ID" in response.headers

    @pytest.mark.asyncio
    async def test_health_check_endpoint_coverage(self, test_client):
        """Test that all monitoring endpoints are accessible."""
        endpoints = [
            "/health",
            "/health/detailed",
            "/health/ready",
            "/health/live",
            "/metrics",
        ]

        for endpoint in endpoints:
            response = test_client.get(endpoint)
            assert response.status_code in [200, 503], f"Endpoint {endpoint} failed"

    def test_monitoring_configuration_validation(self):
        """Test monitoring configuration validation."""
        from api.config import settings

        # Test monitoring flags
        assert hasattr(settings, "metrics_enabled")
        assert hasattr(settings, "health_checks_enabled")
        assert hasattr(settings, "structured_logging")
        assert hasattr(settings, "prometheus_enabled")

        # Test Azure Insights configuration
        assert hasattr(settings, "azure_insights_configured")


# ---------------------------------------------------------------------------
# Performance Tests
# ---------------------------------------------------------------------------


class TestMonitoringPerformance:
    """Test monitoring system performance impact."""

    def test_health_check_performance(self, test_client):
        """Test that health checks don't significantly impact performance."""

        # Time basic health check
        start = time.time()
        for _ in range(10):
            response = test_client.get("/health")
            assert response.status_code == 200
        basic_time = time.time() - start

        # Time detailed health check
        start = time.time()
        for _ in range(10):
            response = test_client.get("/health/detailed")
            assert response.status_code in [200, 503]
        detailed_time = time.time() - start

        # Basic health should be very fast
        assert basic_time < 1.0, f"Basic health checks too slow: {basic_time}s"

        # Detailed health should still be reasonable
        assert detailed_time < 10.0, (
            f"Detailed health checks too slow: {detailed_time}s"
        )

    def test_metrics_collection_overhead(self, test_client):
        """Test metrics collection overhead."""

        # Make requests and time them
        start = time.time()
        for i in range(100):
            response = test_client.get(f"/health?iteration={i}")
            assert response.status_code == 200
        total_time = time.time() - start

        # Should handle 100 requests reasonably quickly
        assert total_time < 10.0, (
            f"Metrics collection too slow: {total_time}s for 100 requests"
        )

        # Average request time should be reasonable
        avg_time = total_time / 100
        assert avg_time < 0.1, f"Average request time too high: {avg_time}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
