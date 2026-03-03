"""
Test suite for Sigil Forge security and access control system.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from api.security.forge_access import (
    AuditAction,
    AuditLogger,
    DataAccessFilter,
    ForgeFeature,
    ForgeUser,
    SigilPlan,
    TeamRole,
    forge_security,
    get_plans_with_feature,
    has_forge_access,
    requires_forge_feature,
    requires_team_role,
)


# ---------------------------------------------------------------------------
# Test Plan-Based Access Control
# ---------------------------------------------------------------------------


class TestPlanAccess:
    """Test plan-based feature access control."""
    
    def test_free_plan_access(self):
        """Free plan should have no Forge features."""
        assert not has_forge_access(SigilPlan.FREE, ForgeFeature.TOOL_TRACKING)
        assert not has_forge_access(SigilPlan.FREE, ForgeFeature.PERSONAL_ANALYTICS)
        assert not has_forge_access(SigilPlan.FREE, ForgeFeature.TEAM_ANALYTICS)
    
    def test_pro_plan_access(self):
        """Pro plan should have personal features."""
        assert has_forge_access(SigilPlan.PRO, ForgeFeature.TOOL_TRACKING)
        assert has_forge_access(SigilPlan.PRO, ForgeFeature.PERSONAL_ANALYTICS)
        assert has_forge_access(SigilPlan.PRO, ForgeFeature.CUSTOM_STACKS)
        assert has_forge_access(SigilPlan.PRO, ForgeFeature.API_ACCESS)
        
        # But not team features
        assert not has_forge_access(SigilPlan.PRO, ForgeFeature.TEAM_ANALYTICS)
        assert not has_forge_access(SigilPlan.PRO, ForgeFeature.TEAM_STACKS)
    
    def test_team_plan_access(self):
        """Team plan should have all Pro features plus team features."""
        # All Pro features
        assert has_forge_access(SigilPlan.TEAM, ForgeFeature.TOOL_TRACKING)
        assert has_forge_access(SigilPlan.TEAM, ForgeFeature.PERSONAL_ANALYTICS)
        
        # Team features
        assert has_forge_access(SigilPlan.TEAM, ForgeFeature.TEAM_ANALYTICS)
        assert has_forge_access(SigilPlan.TEAM, ForgeFeature.TEAM_STACKS)
        assert has_forge_access(SigilPlan.TEAM, ForgeFeature.WEBHOOKS)
        
        # But not Enterprise features
        assert not has_forge_access(SigilPlan.TEAM, ForgeFeature.ORGANIZATION_ANALYTICS)
        assert not has_forge_access(SigilPlan.TEAM, ForgeFeature.COMPLIANCE_REPORTING)
    
    def test_enterprise_plan_access(self):
        """Enterprise plan should have all features."""
        assert has_forge_access(SigilPlan.ENTERPRISE, ForgeFeature.TOOL_TRACKING)
        assert has_forge_access(SigilPlan.ENTERPRISE, ForgeFeature.TEAM_ANALYTICS)
        assert has_forge_access(SigilPlan.ENTERPRISE, ForgeFeature.ORGANIZATION_ANALYTICS)
        assert has_forge_access(SigilPlan.ENTERPRISE, ForgeFeature.COMPLIANCE_REPORTING)
    
    def test_get_plans_with_feature(self):
        """Test getting plans that include a feature."""
        # Tool tracking is Pro+
        plans = get_plans_with_feature(ForgeFeature.TOOL_TRACKING)
        assert SigilPlan.FREE.value not in plans
        assert SigilPlan.PRO.value in plans
        assert SigilPlan.TEAM.value in plans
        assert SigilPlan.ENTERPRISE.value in plans
        
        # Team analytics is Team+
        plans = get_plans_with_feature(ForgeFeature.TEAM_ANALYTICS)
        assert SigilPlan.FREE.value not in plans
        assert SigilPlan.PRO.value not in plans
        assert SigilPlan.TEAM.value in plans
        assert SigilPlan.ENTERPRISE.value in plans
        
        # Compliance is Enterprise only
        plans = get_plans_with_feature(ForgeFeature.COMPLIANCE_REPORTING)
        assert SigilPlan.FREE.value not in plans
        assert SigilPlan.PRO.value not in plans
        assert SigilPlan.TEAM.value not in plans
        assert SigilPlan.ENTERPRISE.value in plans


# ---------------------------------------------------------------------------
# Test Feature Decorators
# ---------------------------------------------------------------------------


class TestFeatureDecorators:
    """Test access control decorators."""
    
    @pytest.mark.asyncio
    async def test_requires_forge_feature_with_access(self):
        """Test decorator allows access when user has feature."""
        
        @requires_forge_feature(ForgeFeature.TOOL_TRACKING)
        async def protected_function(forge_user: ForgeUser):
            return "success"
        
        # Create Pro user with access
        user = ForgeUser(
            id="test-user",
            email="test@example.com",
            name="Test User",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.PRO
        )
        
        result = await protected_function(forge_user=user)
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_requires_forge_feature_without_access(self):
        """Test decorator blocks access when user lacks feature."""
        
        @requires_forge_feature(ForgeFeature.TOOL_TRACKING)
        async def protected_function(forge_user: ForgeUser):
            return "success"
        
        # Create Free user without access
        user = ForgeUser(
            id="test-user",
            email="test@example.com",
            name="Test User",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.FREE
        )
        
        with pytest.raises(HTTPException) as exc:
            await protected_function(forge_user=user)
        
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
        assert "feature_not_available" in str(exc.value.detail)
    
    @pytest.mark.asyncio
    async def test_requires_forge_feature_with_override(self):
        """Test feature override flags."""
        
        @requires_forge_feature(ForgeFeature.TEAM_ANALYTICS)
        async def protected_function(forge_user: ForgeUser):
            return "success"
        
        # Free user with explicit feature override
        user = ForgeUser(
            id="test-user",
            email="test@example.com",
            name="Test User",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.FREE,
            enabled_features=[ForgeFeature.TEAM_ANALYTICS]
        )
        
        result = await protected_function(forge_user=user)
        assert result == "success"
        
        # Pro user with feature disabled
        user2 = ForgeUser(
            id="test-user2",
            email="test2@example.com",
            name="Test User 2",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.TEAM,
            disabled_features=[ForgeFeature.TEAM_ANALYTICS]
        )
        
        with pytest.raises(HTTPException) as exc:
            await protected_function(forge_user=user2)
        
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
        assert "has been disabled" in str(exc.value.detail)
    
    @pytest.mark.asyncio
    async def test_requires_team_role(self):
        """Test team role requirements."""
        
        @requires_team_role(TeamRole.ADMIN)
        async def admin_function(forge_user: ForgeUser):
            return "admin access"
        
        # User with admin role
        admin_user = ForgeUser(
            id="admin",
            email="admin@example.com",
            name="Admin",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.TEAM,
            team_id="team-123",
            team_role=TeamRole.ADMIN
        )
        
        result = await admin_function(forge_user=admin_user)
        assert result == "admin access"
        
        # User with member role
        member_user = ForgeUser(
            id="member",
            email="member@example.com",
            name="Member",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.TEAM,
            team_id="team-123",
            team_role=TeamRole.MEMBER
        )
        
        with pytest.raises(HTTPException) as exc:
            await admin_function(forge_user=member_user)
        
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin role or higher" in str(exc.value.detail)
        
        # User not in a team
        no_team_user = ForgeUser(
            id="solo",
            email="solo@example.com",
            name="Solo",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.PRO,
            team_id=None
        )
        
        with pytest.raises(HTTPException) as exc:
            await admin_function(forge_user=no_team_user)
        
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
        assert "must be part of a team" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Test Data Access Filters
# ---------------------------------------------------------------------------


class TestDataAccessFilters:
    """Test data isolation and filtering."""
    
    def test_apply_user_filter(self):
        """Test user-scoped SQL filtering."""
        query = "SELECT * FROM tools"
        filtered = DataAccessFilter.apply_user_filter(query, "user-123")
        assert "WHERE user_id = :user_id" in filtered
        
        query_with_where = "SELECT * FROM tools WHERE active = 1"
        filtered = DataAccessFilter.apply_user_filter(query_with_where, "user-123")
        assert "AND user_id = :user_id" in filtered
    
    def test_apply_team_filter(self):
        """Test team-scoped SQL filtering."""
        query = "SELECT * FROM stacks"
        
        # With team ID
        filtered = DataAccessFilter.apply_team_filter(query, "team-456")
        assert "WHERE team_id = :team_id" in filtered
        
        # Without team ID (no access)
        filtered = DataAccessFilter.apply_team_filter(query, None)
        assert "WHERE 1=0" in filtered
    
    @pytest.mark.asyncio
    async def test_filter_results(self):
        """Test result filtering based on access scope."""
        user = ForgeUser(
            id="user-123",
            email="test@example.com",
            name="Test",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.PRO,
            team_id="team-456",
            organization_id="org-789"
        )
        
        results = [
            {"id": 1, "user_id": "user-123", "team_id": "team-456"},
            {"id": 2, "user_id": "user-999", "team_id": "team-456"},
            {"id": 3, "user_id": "user-123", "team_id": "team-999"},
            {"id": 4, "user_id": "user-999", "team_id": "team-999"},
        ]
        
        # User scope - only user's data
        filtered = await DataAccessFilter.filter_results(results, user, "user")
        assert len(filtered) == 2
        assert all(r["user_id"] == "user-123" for r in filtered)
        
        # Team scope - only team's data
        filtered = await DataAccessFilter.filter_results(results, user, "team")
        assert len(filtered) == 2
        assert all(r["team_id"] == "team-456" for r in filtered)


# ---------------------------------------------------------------------------
# Test Audit Logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    """Test audit logging for Enterprise customers."""
    
    @pytest.mark.asyncio
    async def test_audit_log_enterprise_only(self):
        """Test that audit logs are only created for Enterprise users."""
        
        with patch('api.security.forge_access.get_user_subscription_info') as mock_sub:
            with patch('api.database.db.insert') as mock_insert:
                # Enterprise user - should log
                mock_sub.return_value = {"subscription_plan": SigilPlan.ENTERPRISE}
                await AuditLogger.log_action(
                    user_id="enterprise-user",
                    action=AuditAction.TOOL_TRACKED,
                    resource_type="tool",
                    resource_id="tool-123"
                )
                assert mock_insert.called
                
                # Pro user - should not log
                mock_insert.reset_mock()
                mock_sub.return_value = {"subscription_plan": SigilPlan.PRO}
                await AuditLogger.log_action(
                    user_id="pro-user",
                    action=AuditAction.TOOL_TRACKED,
                    resource_type="tool",
                    resource_id="tool-456"
                )
                assert not mock_insert.called
    
    @pytest.mark.asyncio
    async def test_audit_action_decorator(self):
        """Test automatic audit logging decorator."""
        from fastapi import Request
        
        @forge_security.audit_action_decorator(AuditAction.STACK_CREATED, "stack")
        async def create_stack(request: Request, forge_user: ForgeUser):
            return {"id": "stack-123", "name": "My Stack"}
        
        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = {"User-Agent": "Test Client"}
        
        # Enterprise user
        enterprise_user = ForgeUser(
            id="enterprise-user",
            email="enterprise@example.com",
            name="Enterprise",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.ENTERPRISE
        )
        
        with patch('api.security.forge_access.AuditLogger.log_action') as mock_log:
            result = await create_stack(mock_request, forge_user=enterprise_user)
            assert result["id"] == "stack-123"
            
            # Should have logged the action
            mock_log.assert_called_once()
            call_args = mock_log.call_args[1]
            assert call_args["user_id"] == "enterprise-user"
            assert call_args["action"] == AuditAction.STACK_CREATED
            assert call_args["resource_type"] == "stack"
            assert call_args["resource_id"] == "stack-123"
    
    @pytest.mark.asyncio
    async def test_get_audit_logs_access_control(self):
        """Test audit log retrieval with proper access control."""
        
        # Non-Enterprise user should be denied
        pro_user = ForgeUser(
            id="pro-user",
            email="pro@example.com",
            name="Pro",
            created_at=datetime.utcnow(),
            subscription_plan=SigilPlan.PRO
        )
        
        with pytest.raises(HTTPException) as exc:
            await AuditLogger.get_audit_logs(forge_user=pro_user)
        
        assert exc.value.status_code == status.HTTP_403_FORBIDDEN
        assert "only available for Enterprise" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Test Rate Limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Test plan-based rate limiting."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_by_plan(self):
        """Test different rate limits per plan."""
        from api.security.forge_access import RATE_LIMITS, apply_rate_limit
        from fastapi import Request
        
        mock_request = MagicMock(spec=Request)
        
        # Test each plan's limits
        for plan, limit in RATE_LIMITS.items():
            user = ForgeUser(
                id=f"user-{plan.value}",
                email=f"{plan.value}@example.com",
                name=f"{plan.value.title()} User",
                created_at=datetime.utcnow(),
                subscription_plan=plan,
                api_calls_this_period=0
            )
            
            with patch('api.database.cache.get', return_value=0):
                with patch('api.database.cache.incr', return_value=1):
                    # First request should succeed
                    await apply_rate_limit(mock_request, user)
            
            # Simulate hitting the limit
            user.api_calls_this_period = limit
            
            with patch('api.database.cache.get', return_value=limit):
                with pytest.raises(HTTPException) as exc:
                    await apply_rate_limit(mock_request, user)
                
                assert exc.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
                assert "rate_limit_exceeded" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Test Integration with API Endpoints
# ---------------------------------------------------------------------------


class TestAPIIntegration:
    """Test security integration with API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client with mocked dependencies."""
        from fastapi import FastAPI
        from api.routers.forge_secure import router
        
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_endpoint_requires_authentication(self, client):
        """Test that endpoints require authentication."""
        response = client.get("/v1/forge/my-tools")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_endpoint_requires_feature_access(self, client):
        """Test that endpoints check feature access."""
        # Mock authenticated user without required feature
        with patch('api.routers.forge_secure.get_forge_user') as mock_get_user:
            mock_user = ForgeUser(
                id="free-user",
                email="free@example.com",
                name="Free User",
                created_at=datetime.utcnow(),
                subscription_plan=SigilPlan.FREE
            )
            mock_get_user.return_value = mock_user
            
            # Try to access Pro feature
            response = client.get("/v1/forge/my-tools")
            assert response.status_code == status.HTTP_403_FORBIDDEN
            assert "feature_not_available" in response.text


# ---------------------------------------------------------------------------
# Test Security Headers
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """Test security headers middleware."""
    
    @pytest.mark.asyncio
    async def test_security_headers_added(self):
        """Test that security headers are added to responses."""
        from api.security.forge_access import add_security_headers
        from fastapi import Response
        
        # Mock request and response
        mock_request = MagicMock()
        mock_response = Response()
        
        async def mock_call_next(request):
            return mock_response
        
        # Apply middleware
        response = await add_security_headers(mock_request, mock_call_next)
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in response.headers


# ---------------------------------------------------------------------------
# Test Data Retention
# ---------------------------------------------------------------------------


class TestDataRetention:
    """Test data retention policies per plan."""
    
    def test_retention_limits(self):
        """Test data retention limits are properly defined."""
        from api.security.forge_access import DATA_RETENTION
        
        assert DATA_RETENTION[SigilPlan.FREE] == 7  # 1 week
        assert DATA_RETENTION[SigilPlan.PRO] == 90  # 3 months
        assert DATA_RETENTION[SigilPlan.TEAM] == 365  # 1 year
        assert DATA_RETENTION[SigilPlan.ENTERPRISE] == -1  # Unlimited


# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    pytest.main([__file__, "-v"])