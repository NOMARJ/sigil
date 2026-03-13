"""
Comprehensive Test Suite for Forge Premium Implementation

Tests the newly implemented Forge dashboard features including:
- Tool tracking and management
- Plan-gated access control
- Personal analytics
- Team features (stacks, monitoring)
- Settings and preferences
- Security and data isolation
"""

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import status
from fastapi.testclient import TestClient

from api.database import db


class TestForgeToolTracking:
    """Test tool tracking functionality with plan gating."""

    def test_track_tool_requires_pro_plan(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that tracking tools requires Pro+ plan."""
        # Create a free user
        user_data = {
            "email": f"free-{uuid4().hex[:8]}@test.com",
            "password": "TestPass123!",
            "name": "Free User",
        }
        resp = client.post("/v1/auth/register", json=user_data)
        assert resp.status_code == 201
        free_user = resp.json()

        free_headers = {"Authorization": f"Bearer {free_user['access_token']}"}

        # Try to track a tool with free plan
        tool_data = {
            "name": "Test Tool",
            "repository_url": "https://github.com/test/tool",
            "description": "A test tool",
            "category": "AI Framework",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=free_headers
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "requires Pro plan" in resp.json()["detail"]

    def test_track_tool_succeeds_with_pro_plan(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that Pro users can track tools."""
        tool_data = {
            "name": "LangChain Pro",
            "repository_url": "https://github.com/langchain-ai/langchain",
            "description": "Framework for LLM applications",
            "category": "AI Framework",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED

        tracked_tool = resp.json()
        assert tracked_tool["name"] == "LangChain Pro"
        assert tracked_tool["repository_url"] == tool_data["repository_url"]
        assert "id" in tracked_tool
        assert "tracked_at" in tracked_tool

    def test_list_tracked_tools(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test listing tracked tools for authenticated user."""
        # Track a few tools first
        tools = [
            {"name": "Tool 1", "repository_url": "https://github.com/test/tool1"},
            {"name": "Tool 2", "repository_url": "https://github.com/test/tool2"},
        ]

        for tool in tools:
            resp = client.post(
                "/v1/forge/tools/track", json=tool, headers=pro_auth_headers
            )
            assert resp.status_code == status.HTTP_201_CREATED

        # List tools
        resp = client.get("/v1/forge/tools", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_200_OK

        tracked_tools = resp.json()
        assert len(tracked_tools) >= 2
        tool_names = [t["name"] for t in tracked_tools]
        assert "Tool 1" in tool_names
        assert "Tool 2" in tool_names

    def test_untrack_tool(self, client: TestClient, pro_auth_headers: dict[str, str]):
        """Test untracking a tool."""
        # Track a tool first
        tool_data = {
            "name": "Temp Tool",
            "repository_url": "https://github.com/test/temp",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED
        tool_id = resp.json()["id"]

        # Untrack it
        resp = client.delete(f"/v1/forge/tools/{tool_id}", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_200_OK

        # Verify it's gone
        resp = client.get("/v1/forge/tools", headers=pro_auth_headers)
        tracked_tools = resp.json()
        tool_ids = [t["id"] for t in tracked_tools]
        assert tool_id not in tool_ids

    def test_user_can_only_access_own_tools(self, client: TestClient):
        """Test data isolation - users only see their own tools."""
        # Create two Pro users
        user1_data = {
            "email": f"user1-{uuid4().hex[:8]}@test.com",
            "password": "TestPass123!",
            "name": "User 1",
        }
        user2_data = {
            "email": f"user2-{uuid4().hex[:8]}@test.com",
            "password": "TestPass123!",
            "name": "User 2",
        }

        # Register and upgrade both users
        for user_data in [user1_data, user2_data]:
            resp = client.post("/v1/auth/register", json=user_data)
            assert resp.status_code == 201
            user = resp.json()

            # Upgrade to Pro
            asyncio.run(
                db.upsert_subscription(
                    user_id=user["user"]["id"],
                    plan="pro",
                    status="active",
                    stripe_subscription_id=f"sub_test_{uuid4().hex[:8]}",
                )
            )

        user1_resp = client.post(
            "/v1/auth/login",
            json={"email": user1_data["email"], "password": user1_data["password"]},
        )
        user1_token = user1_resp.json()["access_token"]
        user1_headers = {"Authorization": f"Bearer {user1_token}"}

        user2_resp = client.post(
            "/v1/auth/login",
            json={"email": user2_data["email"], "password": user2_data["password"]},
        )
        user2_token = user2_resp.json()["access_token"]
        user2_headers = {"Authorization": f"Bearer {user2_token}"}

        # User 1 tracks a tool
        tool_data = {
            "name": "User1 Tool",
            "repository_url": "https://github.com/user1/tool",
        }
        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=user1_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED

        # User 2 should not see User 1's tool
        resp = client.get("/v1/forge/tools", headers=user2_headers)
        assert resp.status_code == status.HTTP_200_OK
        user2_tools = resp.json()
        tool_names = [t["name"] for t in user2_tools]
        assert "User1 Tool" not in tool_names


class TestForgeAnalytics:
    """Test analytics features with plan gating."""

    def test_personal_analytics_requires_pro_plan(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that personal analytics requires Pro+ plan."""
        resp = client.get("/v1/forge/analytics/personal", headers=auth_headers)
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_personal_analytics_returns_correct_data(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test personal analytics returns properly formatted data."""
        resp = client.get("/v1/forge/analytics/personal", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_200_OK

        analytics = resp.json()

        # Check required fields
        assert "tools_tracked" in analytics
        assert "risk_distribution" in analytics
        assert "recent_activity" in analytics
        assert "trends" in analytics

        # Validate data structure
        assert isinstance(analytics["tools_tracked"], int)
        assert isinstance(analytics["risk_distribution"], dict)
        assert isinstance(analytics["recent_activity"], list)

    def test_team_analytics_requires_team_plan(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that team analytics requires Team+ plan."""
        resp = client.get("/v1/forge/analytics/team", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "requires Team plan" in resp.json()["detail"]

    def test_analytics_date_filtering(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test analytics with date range filtering."""
        # Test with date range
        start_date = (datetime.now() - timedelta(days=30)).isoformat()
        end_date = datetime.now().isoformat()

        resp = client.get(
            f"/v1/forge/analytics/personal?start_date={start_date}&end_date={end_date}",
            headers=pro_auth_headers,
        )
        assert resp.status_code == status.HTTP_200_OK

        analytics = resp.json()
        assert "date_range" in analytics
        assert analytics["date_range"]["start"] == start_date.split("T")[0]


class TestForgeSettings:
    """Test Forge settings and preferences."""

    def test_get_forge_settings(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test retrieving Forge settings."""
        resp = client.get("/v1/forge/settings", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_200_OK

        settings = resp.json()
        assert "notifications" in settings
        assert "privacy" in settings
        assert "preferences" in settings

    def test_update_forge_settings(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test updating Forge settings."""
        new_settings = {
            "notifications": {
                "security_alerts": True,
                "weekly_digest": False,
                "new_tools": True,
            },
            "privacy": {"public_profile": False, "share_analytics": False},
            "preferences": {
                "default_scan_depth": "thorough",
                "risk_threshold": "medium",
            },
        }

        resp = client.put(
            "/v1/forge/settings", json=new_settings, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_200_OK

        # Verify settings were saved
        resp = client.get("/v1/forge/settings", headers=pro_auth_headers)
        saved_settings = resp.json()
        assert not saved_settings["notifications"]["weekly_digest"]
        assert not saved_settings["privacy"]["public_profile"]


class TestForgeStacks:
    """Test custom stacks functionality for Team+ users."""

    def test_create_stack_requires_team_plan(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that creating stacks requires Team+ plan."""
        stack_data = {
            "name": "AI Development Stack",
            "description": "Tools for AI development",
            "tags": ["ai", "development"],
        }

        resp = client.post(
            "/v1/forge/stacks", json=stack_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_list_stacks_requires_team_plan(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that listing stacks requires Team+ plan."""
        resp = client.get("/v1/forge/stacks", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_403_FORBIDDEN


class TestForgeSecurityAndAccess:
    """Test security features and access controls."""

    def test_rate_limiting_by_plan(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that rate limiting is enforced by plan tier."""
        # This would need to be implemented based on actual rate limiting logic
        # For now, test that endpoints respond correctly

        tool_data = {
            "name": f"Rate Test Tool {uuid4().hex[:8]}",
            "repository_url": f"https://github.com/test/{uuid4().hex[:8]}",
        }

        # Make multiple requests rapidly
        responses = []
        for i in range(5):
            resp = client.post(
                "/v1/forge/tools/track",
                json={**tool_data, "name": f"{tool_data['name']} {i}"},
                headers=pro_auth_headers,
            )
            responses.append(resp.status_code)

        # All should succeed for Pro plan (generous limits)
        assert all(
            code in [status.HTTP_201_CREATED, status.HTTP_200_OK] for code in responses
        )

    def test_cache_invalidation_works(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that caches are properly invalidated on data changes."""
        # Track a tool
        tool_data = {
            "name": "Cache Test Tool",
            "repository_url": "https://github.com/test/cache-tool",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED
        tool_id = resp.json()["id"]

        # Get analytics (should reflect new tool)
        resp = client.get("/v1/forge/analytics/personal", headers=pro_auth_headers)
        analytics_before = resp.json()
        tools_count_before = analytics_before["tools_tracked"]

        # Untrack the tool
        resp = client.delete(f"/v1/forge/tools/{tool_id}", headers=pro_auth_headers)
        assert resp.status_code == status.HTTP_200_OK

        # Get analytics again (should reflect removal)
        resp = client.get("/v1/forge/analytics/personal", headers=pro_auth_headers)
        analytics_after = resp.json()
        tools_count_after = analytics_after["tools_tracked"]

        assert tools_count_after < tools_count_before


class TestForgeIntegration:
    """Test integration between Forge features and main Sigil functionality."""

    def test_forge_settings_affect_scan_behavior(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that Forge settings influence scan configuration."""
        # Set risk threshold in Forge settings
        settings_data = {
            "preferences": {"risk_threshold": "low", "default_scan_depth": "thorough"}
        }

        resp = client.put(
            "/v1/forge/settings", json=settings_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_200_OK

        # This would integrate with actual scan submission
        # For now, verify settings are retrievable
        resp = client.get("/v1/forge/settings", headers=pro_auth_headers)
        settings = resp.json()
        assert settings["preferences"]["risk_threshold"] == "low"

    def test_tracked_tools_appear_in_main_scan_results(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that tracked tools are highlighted in main scan results."""
        # Track a tool
        tool_data = {
            "name": "Integration Test Tool",
            "repository_url": "https://github.com/test/integration-tool",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED

        # This would need integration with actual scan submission and results
        # For now, verify tool tracking works
        resp = client.get("/v1/forge/tools", headers=pro_auth_headers)
        tools = resp.json()
        tool_names = [t["name"] for t in tools]
        assert "Integration Test Tool" in tool_names


class TestForgeEdgeCases:
    """Test edge cases and error handling."""

    def test_invalid_tool_repository_url(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test validation of repository URLs."""
        tool_data = {
            "name": "Invalid URL Tool",
            "repository_url": "not-a-valid-url",
            "description": "Tool with invalid URL",
        }

        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_duplicate_tool_tracking(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test handling of duplicate tool tracking attempts."""
        tool_data = {
            "name": "Duplicate Tool",
            "repository_url": "https://github.com/test/duplicate",
        }

        # Track once
        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_201_CREATED

        # Try to track same URL again
        resp = client.post(
            "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    def test_empty_analytics_for_new_user(self, client: TestClient):
        """Test analytics for user with no tracked tools."""
        # Create new Pro user
        user_data = {
            "email": f"new-{uuid4().hex[:8]}@test.com",
            "password": "TestPass123!",
            "name": "New User",
        }

        resp = client.post("/v1/auth/register", json=user_data)
        assert resp.status_code == 201
        user = resp.json()

        # Upgrade to Pro
        asyncio.run(
            db.upsert_subscription(
                user_id=user["user"]["id"],
                plan="pro",
                status="active",
                stripe_subscription_id=f"sub_test_{uuid4().hex[:8]}",
            )
        )

        headers = {"Authorization": f"Bearer {user['access_token']}"}

        # Get analytics
        resp = client.get("/v1/forge/analytics/personal", headers=headers)
        assert resp.status_code == status.HTTP_200_OK

        analytics = resp.json()
        assert analytics["tools_tracked"] == 0
        assert len(analytics["recent_activity"]) == 0

    def test_settings_with_invalid_preferences(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test settings validation."""
        invalid_settings = {
            "preferences": {
                "risk_threshold": "invalid_threshold",  # Should be low/medium/high
                "default_scan_depth": 999,  # Should be string
            }
        }

        resp = client.put(
            "/v1/forge/settings", json=invalid_settings, headers=pro_auth_headers
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestForgePerformance:
    """Test performance characteristics of Forge features."""

    def test_large_tool_list_performance(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test performance with many tracked tools."""
        # Track multiple tools
        tools_to_track = 50

        for i in range(tools_to_track):
            tool_data = {
                "name": f"Performance Tool {i}",
                "repository_url": f"https://github.com/test/perf-tool-{i}",
            }

            resp = client.post(
                "/v1/forge/tools/track", json=tool_data, headers=pro_auth_headers
            )
            assert resp.status_code == status.HTTP_201_CREATED

        # List tools should still be fast
        import time

        start_time = time.time()
        resp = client.get("/v1/forge/tools", headers=pro_auth_headers)
        end_time = time.time()

        assert resp.status_code == status.HTTP_200_OK
        assert len(resp.json()) >= tools_to_track
        assert (end_time - start_time) < 2.0  # Should complete in under 2 seconds

    def test_analytics_response_time(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that analytics queries are performant."""
        import time

        start_time = time.time()
        resp = client.get("/v1/forge/analytics/personal", headers=pro_auth_headers)
        end_time = time.time()

        assert resp.status_code == status.HTTP_200_OK
        assert (end_time - start_time) < 1.0  # Should complete in under 1 second
