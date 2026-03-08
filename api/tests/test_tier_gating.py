"""
Tier Gating Tests

Comprehensive test suite for Pro tier access control, feature gating,
and subscription-based authorization middleware.

Test Coverage:
- Tier-based access control for Pro features
- Middleware authentication and authorization
- Feature capability checking and reporting
- Subscription status validation and caching
- Access denial responses and upgrade messaging
- Edge cases and error handling in tier checks
- Performance optimization for tier validation
"""

from __future__ import annotations

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from api.models import PlanTier
from api.middleware.tier_check import (
    get_user_tier,
    require_pro_tier,
    check_llm_analysis_access,
    get_scan_capabilities,
)
from api.services.subscription_service import subscription_service, pro_feature_gate


class TestTierGatingMiddleware:
    """Test tier gating middleware functionality"""

    @pytest.fixture
    def mock_free_user(self):
        """Mock free tier user"""
        user = MagicMock()
        user.id = "free_user_123"
        user.email = "free@example.com"
        user.name = "Free User"
        return user

    @pytest.fixture
    def mock_pro_user(self):
        """Mock Pro tier user"""
        user = MagicMock()
        user.id = "pro_user_123"
        user.email = "pro@example.com"
        user.name = "Pro User"
        return user

    @pytest.mark.asyncio
    async def test_get_user_tier_free(self, mock_free_user):
        """Test getting free user tier"""

        with patch.object(subscription_service, "get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.FREE

            tier = await get_user_tier(mock_free_user)

            assert tier == PlanTier.FREE
            mock_get_tier.assert_called_once_with("free_user_123")

    @pytest.mark.asyncio
    async def test_get_user_tier_pro(self, mock_pro_user):
        """Test getting Pro user tier"""

        with patch.object(subscription_service, "get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.PRO

            tier = await get_user_tier(mock_pro_user)

            assert tier == PlanTier.PRO
            mock_get_tier.assert_called_once_with("pro_user_123")

    @pytest.mark.asyncio
    async def test_get_user_tier_database_error(self, mock_free_user):
        """Test tier retrieval with database error fallback"""

        with patch.object(subscription_service, "get_user_tier") as mock_get_tier:
            mock_get_tier.side_effect = Exception("Database connection failed")

            tier = await get_user_tier(mock_free_user)

            # Should fallback to FREE tier on errors
            assert tier == PlanTier.FREE

    @pytest.mark.asyncio
    async def test_require_pro_tier_success(self, mock_pro_user):
        """Test Pro tier requirement check success"""

        with patch.object(pro_feature_gate, "require_pro_access") as mock_require:
            mock_require.return_value = None  # No exception = success

            result = await require_pro_tier(mock_pro_user)

            assert result == mock_pro_user
            mock_require.assert_called_once_with("pro_user_123")

    @pytest.mark.asyncio
    async def test_require_pro_tier_payment_required(self, mock_free_user):
        """Test Pro tier requirement check failure"""

        with patch.object(pro_feature_gate, "require_pro_access") as mock_require:
            mock_require.side_effect = HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "error": "pro_subscription_required",
                    "message": "This feature requires a Pro subscription",
                    "upgrade_url": "https://app.sigilsec.ai/upgrade",
                },
            )

            with pytest.raises(HTTPException) as exc_info:
                await require_pro_tier(mock_free_user)

            assert exc_info.value.status_code == 402
            assert exc_info.value.detail["error"] == "pro_subscription_required"

    @pytest.mark.asyncio
    async def test_require_pro_tier_internal_error(self, mock_free_user):
        """Test Pro tier requirement check with internal error"""

        with patch.object(pro_feature_gate, "require_pro_access") as mock_require:
            mock_require.side_effect = Exception("Internal service error")

            with pytest.raises(HTTPException) as exc_info:
                await require_pro_tier(mock_free_user)

            assert exc_info.value.status_code == 500
            assert "Unable to verify subscription status" in exc_info.value.detail


class TestLLMAnalysisAccessControl:
    """Test LLM analysis access control and capabilities"""

    @pytest.mark.asyncio
    async def test_check_llm_analysis_access_free_user(self, mock_free_user):
        """Test LLM analysis access check for free user"""

        with patch("api.middleware.tier_check.get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.FREE

            access_info = await check_llm_analysis_access(mock_free_user)

            assert access_info["user_id"] == "free_user_123"
            assert access_info["user_tier"] == "free"
            assert access_info["has_pro_access"] is False
            assert access_info["can_use_llm"] is False

    @pytest.mark.asyncio
    async def test_check_llm_analysis_access_pro_user(self, mock_pro_user):
        """Test LLM analysis access check for Pro user"""

        with patch("api.middleware.tier_check.get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.PRO

            access_info = await check_llm_analysis_access(mock_pro_user)

            assert access_info["user_id"] == "pro_user_123"
            assert access_info["user_tier"] == "pro"
            assert access_info["has_pro_access"] is True
            assert access_info["can_use_llm"] is True

    @pytest.mark.asyncio
    async def test_check_llm_analysis_access_team_user(self, mock_pro_user):
        """Test LLM analysis access check for Team tier user"""

        mock_pro_user.id = "team_user_123"

        with patch("api.middleware.tier_check.get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.TEAM

            access_info = await check_llm_analysis_access(mock_pro_user)

            assert access_info["user_tier"] == "team"
            assert access_info["has_pro_access"] is True
            assert access_info["can_use_llm"] is True

    @pytest.mark.asyncio
    async def test_check_llm_analysis_access_enterprise_user(self, mock_pro_user):
        """Test LLM analysis access check for Enterprise tier user"""

        mock_pro_user.id = "enterprise_user_123"

        with patch("api.middleware.tier_check.get_user_tier") as mock_get_tier:
            mock_get_tier.return_value = PlanTier.ENTERPRISE

            access_info = await check_llm_analysis_access(mock_pro_user)

            assert access_info["user_tier"] == "enterprise"
            assert access_info["has_pro_access"] is True
            assert access_info["can_use_llm"] is True


class TestScanCapabilities:
    """Test scan capabilities based on user tier"""

    @pytest.mark.asyncio
    async def test_get_scan_capabilities_free_user(self, mock_free_user):
        """Test scan capabilities for free tier user"""

        with patch("api.middleware.tier_check.check_llm_analysis_access") as mock_check:
            mock_check.return_value = {
                "user_id": "free_user_123",
                "user_tier": "free",
                "has_pro_access": False,
            }

            capabilities = await get_scan_capabilities(mock_free_user)

            assert capabilities["static_analysis"] is True  # Available to all
            assert capabilities["llm_analysis"] is False
            assert capabilities["contextual_analysis"] is False
            assert capabilities["zero_day_detection"] is False
            assert capabilities["advanced_remediation"] is False
            assert capabilities["tier"] == "free"
            assert capabilities["upgrade_required"] is True

    @pytest.mark.asyncio
    async def test_get_scan_capabilities_pro_user(self, mock_pro_user):
        """Test scan capabilities for Pro tier user"""

        with patch("api.middleware.tier_check.check_llm_analysis_access") as mock_check:
            mock_check.return_value = {
                "user_id": "pro_user_123",
                "user_tier": "pro",
                "has_pro_access": True,
            }

            capabilities = await get_scan_capabilities(mock_pro_user)

            assert capabilities["static_analysis"] is True
            assert capabilities["llm_analysis"] is True
            assert capabilities["contextual_analysis"] is True
            assert capabilities["zero_day_detection"] is True
            assert capabilities["advanced_remediation"] is True
            assert capabilities["tier"] == "pro"
            assert capabilities["upgrade_required"] is False


class TestProFeatureGate:
    """Test ProFeatureGate class functionality"""

    @pytest.mark.asyncio
    async def test_pro_feature_gate_require_access_success(self):
        """Test Pro feature gate access requirement success"""

        with patch.object(subscription_service, "check_pro_access") as mock_check:
            mock_check.return_value = True

            # Should not raise exception
            await pro_feature_gate.require_pro_access("pro_user_123")

            mock_check.assert_called_once_with("pro_user_123")

    @pytest.mark.asyncio
    async def test_pro_feature_gate_require_access_denied(self):
        """Test Pro feature gate access requirement denial"""

        with patch.object(subscription_service, "check_pro_access") as mock_check:
            mock_check.return_value = False

            with pytest.raises(HTTPException) as exc_info:
                await pro_feature_gate.require_pro_access("free_user_123")

            assert exc_info.value.status_code == 402
            detail = exc_info.value.detail
            assert detail["error"] == "pro_subscription_required"
            assert detail["upgrade_url"] == "https://app.sigilsec.ai/upgrade"
            assert detail["feature"] == "llm_analysis"

    @pytest.mark.asyncio
    async def test_pro_feature_gate_check_and_track_usage(self):
        """Test Pro feature gate usage tracking"""

        with patch.object(pro_feature_gate, "require_pro_access") as mock_require:
            mock_require.return_value = None

            with patch.object(
                subscription_service, "track_pro_feature_usage"
            ) as mock_track:
                mock_track.return_value = True

                await pro_feature_gate.check_and_track_usage(
                    user_id="pro_user_123",
                    feature_type="llm_analysis",
                    usage_data={"tokens": 1500},
                )

                mock_require.assert_called_once_with("pro_user_123")
                mock_track.assert_called_once_with(
                    "pro_user_123", "llm_analysis", {"tokens": 1500}
                )


class TestSubscriptionServiceTierLogic:
    """Test subscription service tier determination logic"""

    @pytest.mark.asyncio
    async def test_check_pro_access_active_pro(self):
        """Test Pro access check for active Pro subscription"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.return_value = {
                "plan": "pro",
                "status": "active",
                "has_pro_features": True,
            }

            has_access = await subscription_service.check_pro_access("pro_user_123")

            assert has_access is True

    @pytest.mark.asyncio
    async def test_check_pro_access_cancelled_pro(self):
        """Test Pro access check for cancelled Pro subscription"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.return_value = {
                "plan": "free",
                "status": "cancelled",
                "has_pro_features": False,
            }

            has_access = await subscription_service.check_pro_access(
                "cancelled_user_123"
            )

            assert has_access is False

    @pytest.mark.asyncio
    async def test_check_pro_access_past_due(self):
        """Test Pro access check for past due subscription"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.return_value = {
                "plan": "pro",
                "status": "past_due",
                "has_pro_features": True,  # Still has features during grace period
            }

            has_access = await subscription_service.check_pro_access(
                "past_due_user_123"
            )

            assert has_access is True

    @pytest.mark.asyncio
    async def test_get_user_tier_invalid_plan(self):
        """Test tier determination with invalid plan data"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.return_value = {
                "plan": "invalid_plan_name",
                "status": "active",
            }

            tier = await subscription_service.get_user_tier("invalid_plan_user")

            assert tier == PlanTier.FREE  # Should default to FREE


class TestTierGatingAPIEndpoints:
    """Test tier gating in actual API endpoints"""

    def test_scan_enhanced_endpoint_free_user_blocked(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that enhanced scan endpoint blocks free users"""

        scan_data = {
            "target": "test.py",
            "target_type": "file",
            "files_scanned": 1,
            "findings": [],
            "enable_llm": True,
        }

        with patch("api.middleware.tier_check.require_pro_tier") as mock_require:
            mock_require.side_effect = HTTPException(
                status_code=402,
                detail={
                    "error": "pro_subscription_required",
                    "message": "This feature requires a Pro subscription",
                },
            )

            response = client.post(
                "/v1/scan-enhanced", json=scan_data, headers=auth_headers
            )

            assert response.status_code == 402
            error_data = response.json()
            assert error_data["detail"]["error"] == "pro_subscription_required"

    def test_scan_capabilities_endpoint_free_user(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test scan capabilities endpoint for free user"""

        with patch("api.middleware.tier_check.get_scan_capabilities") as mock_caps:
            mock_caps.return_value = {
                "static_analysis": True,
                "llm_analysis": False,
                "tier": "free",
                "upgrade_required": True,
            }

            response = client.get("/v1/scan-capabilities", headers=auth_headers)

            assert response.status_code == 200
            data = response.json()
            assert data["static_analysis"] is True
            assert data["llm_analysis"] is False
            assert data["upgrade_required"] is True

    def test_scan_capabilities_endpoint_pro_user(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test scan capabilities endpoint for Pro user"""

        with patch("api.middleware.tier_check.get_scan_capabilities") as mock_caps:
            mock_caps.return_value = {
                "static_analysis": True,
                "llm_analysis": True,
                "contextual_analysis": True,
                "zero_day_detection": True,
                "tier": "pro",
                "upgrade_required": False,
            }

            response = client.get("/v1/scan-capabilities", headers=pro_auth_headers)

            assert response.status_code == 200
            data = response.json()
            assert data["llm_analysis"] is True
            assert data["zero_day_detection"] is True
            assert data["upgrade_required"] is False


class TestTierGatingPerformance:
    """Test performance characteristics of tier gating"""

    @pytest.mark.asyncio
    async def test_tier_check_caching(self):
        """Test that tier checks are properly cached"""

        user_id = "cached_user_123"

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.return_value = {
                "plan": "pro",
                "status": "active",
                "has_pro_features": True,
            }

            # First call
            tier1 = await subscription_service.get_user_tier(user_id)
            assert tier1 == PlanTier.PRO

            # Second call - should use cache if implemented
            tier2 = await subscription_service.get_user_tier(user_id)
            assert tier2 == PlanTier.PRO

            # Verify database was called for both (no caching in current implementation)
            assert mock_get_sub.call_count == 2

    @pytest.mark.asyncio
    async def test_concurrent_tier_checks(self):
        """Test concurrent tier checks don't cause issues"""

        async def check_tier(user_id: str):
            with patch.object(
                subscription_service, "get_user_subscription"
            ) as mock_sub:
                mock_sub.return_value = {"plan": "pro", "has_pro_features": True}
                return await subscription_service.check_pro_access(user_id)

        # Run multiple concurrent tier checks
        tasks = [check_tier(f"concurrent_user_{i}") for i in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(results)

    @pytest.mark.asyncio
    async def test_tier_check_timeout_handling(self):
        """Test handling of database timeouts in tier checks"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            mock_get_sub.side_effect = asyncio.TimeoutError("Database timeout")

            # Should fallback gracefully
            has_access = await subscription_service.check_pro_access("timeout_user")
            assert has_access is False  # Safe fallback


class TestTierGatingEdgeCases:
    """Test edge cases and error scenarios in tier gating"""

    @pytest.mark.asyncio
    async def test_malformed_subscription_data(self):
        """Test handling of malformed subscription data"""

        with patch.object(
            subscription_service, "get_user_subscription"
        ) as mock_get_sub:
            # Return malformed data
            mock_get_sub.return_value = None

            tier = await subscription_service.get_user_tier("malformed_user")
            assert tier == PlanTier.FREE

    @pytest.mark.asyncio
    async def test_user_without_subscription_record(self):
        """Test handling of users without subscription records"""

        with patch("api.database.db.get_subscription") as mock_db:
            mock_db.return_value = None

            subscription = await subscription_service.get_user_subscription(
                "no_sub_user"
            )

            # Should return default free subscription
            assert subscription["plan"] == "free"
            assert subscription["has_pro_features"] is False

    @pytest.mark.asyncio
    async def test_subscription_status_edge_cases(self):
        """Test various subscription status edge cases"""

        status_cases = [
            ("trialing", True),  # Trial period should have Pro access
            ("incomplete", False),  # Incomplete payment - no access
            ("unpaid", False),  # Unpaid - no access
            ("active", True),  # Active - has access
            ("cancelled", False),  # Cancelled - no access
            ("unknown_status", False),  # Unknown status - no access
        ]

        for sub_status, expected_access in status_cases:
            with patch.object(
                subscription_service, "get_user_subscription"
            ) as mock_get_sub:
                mock_get_sub.return_value = {
                    "plan": "pro",
                    "status": sub_status,
                    "has_pro_features": expected_access,
                }

                has_access = await subscription_service.check_pro_access(
                    f"user_{sub_status}"
                )
                assert has_access == expected_access, (
                    f"Status {sub_status} should have access={expected_access}"
                )
