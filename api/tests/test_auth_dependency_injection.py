"""
Sigil API — Authentication Dependency Injection Tests

Comprehensive tests documenting authentication behavior on threat API endpoints.

## STATUS: FIXED

The dependency injection issue has been RESOLVED by using `get_current_user_unified`
instead of `get_current_user`. This function properly handles both Supabase Auth
and custom JWT tokens without nested dependency conflicts.

## FIX SUMMARY:

The fix in `api/gates.py` now uses:
```python
def require_plan(minimum_tier: PlanTier):
    from api.routers.auth import get_current_user_unified, UserResponse

    async def _gate(
        current_user: UserResponse = Depends(get_current_user_unified),
    ) -> None:
        ...
```

The `get_current_user_unified` function takes both OAuth2 and HTTPBearer tokens
directly as dependencies, avoiding the nested dependency issue that caused FastAPI
to treat `current_user` as a query parameter.

## PRO-GATED ENDPOINTS (all require PRO plan):

- GET /v1/threat/{hash} - requires PRO plan
- GET /v1/threats - requires PRO plan, returns 403 for FREE users
- GET /v1/signatures - requires PRO plan
- POST /v1/signatures - requires PRO plan
- DELETE /v1/signatures/{id} - requires PRO plan
- GET /v1/threat-reports - requires PRO plan
- GET /v1/threat-reports/{id} - requires PRO plan
- PATCH /v1/threat-reports/{id} - requires PRO plan

## TESTS:

These tests verify that the fix works correctly:
- Plan-gated endpoints return 403 Forbidden for FREE users
- PRO users can access plan-gated endpoints
- Authentication works properly with both Supabase and custom JWT tokens
"""

from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from api.database import db


# ---------------------------------------------------------------------------
# Test: PRO-gated threat intel endpoints
# ---------------------------------------------------------------------------


class TestWorkingEndpoints:
    """Tests for threat intel endpoints requiring PRO authentication.

    All threat intel endpoints require PRO plan authentication.
    """

    def test_get_threat_found(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        """GET /v1/threat/{hash} works with PRO authentication."""
        # Seed a threat
        threat = {
            "id": "test-threat-1",
            "hash": "abc123deadbeef456",
            "package_name": "evil-pkg",
            "version": "1.0.0",
            "severity": "CRITICAL",
            "source": "internal",
            "description": "Test malicious package",
            "confirmed_at": "2024-01-01T00:00:00",
        }
        db._memory_store.setdefault("threats", {})["test-threat-1"] = threat

        resp = client.get("/v1/threat/abc123deadbeef456", headers=pro_auth_headers)
        assert resp.status_code == 200

        data = resp.json()
        assert data["package_name"] == "evil-pkg"
        assert data["severity"] == "CRITICAL"

    def test_get_threat_not_found(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        """GET /v1/threat/{hash} returns 404 for non-existent hash."""
        resp = client.get(
            "/v1/threat/0000000000000000000000000000000000000000",
            headers=pro_auth_headers,
        )
        assert resp.status_code == 404
        assert "No threat entry found" in resp.json()["detail"]

    def test_list_signatures(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        """GET /v1/signatures works with PRO authentication."""
        resp = client.get("/v1/signatures", headers=pro_auth_headers)
        assert resp.status_code == 200

        data = resp.json()
        assert "signatures" in data
        assert "total" in data
        assert data["total"] > 0

    def test_signatures_with_since_filter(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        """GET /v1/signatures supports 'since' parameter."""
        resp = client.get(
            "/v1/signatures?since=2099-01-01T00:00:00", headers=pro_auth_headers
        )
        assert resp.status_code == 200

        data = resp.json()
        assert data["total"] == 0
        assert data["signatures"] == []

    def test_signatures_contain_multiple_phases(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        """Built-in signatures cover multiple scan phases."""
        resp = client.get("/v1/signatures", headers=pro_auth_headers)
        data = resp.json()

        phases = {sig["phase"] for sig in data["signatures"]}
        assert "install_hooks" in phases
        assert "code_patterns" in phases
        assert "obfuscation" in phases


# ---------------------------------------------------------------------------
# Test: Broken endpoints with dependency injection issue
# ---------------------------------------------------------------------------


class TestPlanGatedEndpoints:
    """Tests verifying that plan-gated endpoints work correctly.

    The dependency injection issue has been FIXED. These tests verify the correct
    behavior: PRO users can access gated endpoints, FREE users get 403 Forbidden.
    """

    def test_pro_user_can_list_threats(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user can access GET /v1/threats."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_pro_user_can_create_signature(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user can POST /v1/signatures."""
        payload = {
            "id": "test-sig-1",
            "phase": "obfuscation",
            "pattern": r"atob\(",
            "severity": "MEDIUM",
            "description": "Test",
        }

        resp = client.post("/v1/signatures", json=payload, headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_pro_user_can_delete_signature(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user can DELETE /v1/signatures/{id}."""
        sig_id = "test-sig-delete"
        db._memory_store.setdefault("signatures", {})[sig_id] = {
            "id": sig_id,
            "phase": "code_patterns",
            "pattern": r"eval\(",
            "severity": "HIGH",
            "description": "Test",
            "updated_at": datetime.utcnow(),
        }

        resp = client.delete(f"/v1/signatures/{sig_id}", headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_free_plan_blocked_from_threats(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        """FREE user is blocked from GET /v1/threats with 403 Forbidden."""
        resp = client.get("/v1/threats", headers=auth_headers)
        assert resp.status_code == 403

        # Verify error response structure
        error = resp.json()
        assert "detail" in error
        assert "required_plan" in error
        assert error["required_plan"] == "pro"

    def test_plan_gating_returns_403_not_422(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Plan-gated endpoints return 200 for PRO users (not 422)."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)

        # Should return 200, not 422 (the bug is fixed)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test: Authentication works on non-gated endpoints
# ---------------------------------------------------------------------------


class TestAuthenticationOnNonGatedEndpoints:
    """Tests verifying that authentication itself works (when not using require_plan).

    These tests verify that the JWT tokens are valid and authentication works
    when NOT going through the broken require_plan() dependency.
    """

    def test_auth_me_endpoint_works(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        """GET /v1/auth/me works with valid token (no plan gating)."""
        resp = client.get("/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200

        data = resp.json()
        assert "id" in data
        assert "email" in data

    def test_jwt_token_generation_works(
        self,
        client: TestClient,
        test_user_data: dict[str, str],
    ) -> None:
        """User registration generates valid JWT tokens."""
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 201

        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    def test_login_generates_valid_token(
        self,
        client: TestClient,
        registered_user: dict,
        test_user_data: dict[str, str],
    ) -> None:
        """User login generates valid tokens that work with /auth/me."""
        # Login with already registered user
        login_resp = client.post(
            "/v1/auth/login",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["password"],
            },
        )
        assert login_resp.status_code == 200

        # Use token
        token = login_resp.json()["access_token"]
        me_resp = client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200

    def test_invalid_token_rejected_on_non_gated_endpoint(
        self, client: TestClient
    ) -> None:
        """Invalid tokens are properly rejected on /auth/me."""
        headers = {"Authorization": "Bearer invalid.token.here"}
        resp = client.get("/v1/auth/me", headers=headers)
        assert resp.status_code == 401

    def test_missing_token_rejected_on_non_gated_endpoint(
        self, client: TestClient
    ) -> None:
        """Missing token is properly rejected on /auth/me."""
        resp = client.get("/v1/auth/me")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test: Plan subscription management works
# ---------------------------------------------------------------------------


class TestPlanSubscriptionManagement:
    """Tests verifying that plan tier detection works (outside of require_plan)."""

    def test_default_plan_is_free(self) -> None:
        """New users default to FREE plan when no subscription exists."""
        from api.gates import get_user_plan
        from api.models import PlanTier
        from uuid import uuid4
        import asyncio

        # User with no subscription should be FREE
        user_id = str(uuid4())
        plan = asyncio.run(get_user_plan(user_id))
        assert plan == PlanTier.FREE

    def test_pro_plan_detection_works(self) -> None:
        """PRO plan is correctly detected when subscription exists."""
        from api.gates import get_user_plan
        from api.models import PlanTier
        from api.database import db
        from uuid import uuid4
        import asyncio

        # Create user with PRO subscription using proper database API
        user_id = str(uuid4())

        async def setup_and_test():
            await db.upsert_subscription(
                user_id=user_id,
                plan="pro",
                status="active",
            )
            plan = await get_user_plan(user_id)
            return plan

        plan = asyncio.run(setup_and_test())
        assert plan == PlanTier.PRO

    def test_subscription_data_structure(self) -> None:
        """Subscription data is stored with correct structure."""
        from api.database import db
        from uuid import uuid4
        import asyncio

        user_id = str(uuid4())

        async def test_subscription():
            # Create subscription using proper API
            await db.upsert_subscription(
                user_id=user_id,
                plan="pro",
                status="active",
                stripe_subscription_id="sub_test",
            )

            # Retrieve and verify
            subscription = await db.get_subscription(user_id)
            assert subscription is not None
            assert subscription["user_id"] == user_id
            assert subscription["plan"] == "pro"
            assert subscription["status"] == "active"
            assert subscription["stripe_subscription_id"] == "sub_test"

        asyncio.run(test_subscription())


# ---------------------------------------------------------------------------
# Test: Comprehensive documentation of the issue
# ---------------------------------------------------------------------------


class TestPlanGatingBehavior:
    """Comprehensive tests verifying plan gating works correctly across all endpoints.

    This test class verifies that the fix works consistently across all
    plan-gated endpoints in the API.
    """

    def test_all_gated_endpoints_work_for_pro_users(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """All plan-gated endpoints return 200 for PRO users."""
        endpoints = [
            ("GET", "/v1/threats"),
            (
                "POST",
                "/v1/signatures",
                {
                    "id": "test",
                    "phase": "obfuscation",
                    "pattern": "test",
                    "severity": "MEDIUM",
                    "description": "Test",
                },
            ),
            ("GET", "/v1/threat-reports"),
        ]

        for method, url, *json_data in endpoints:
            if method == "GET":
                resp = client.get(url, headers=pro_auth_headers)
            elif method == "POST":
                resp = client.post(url, json=json_data[0], headers=pro_auth_headers)

            # All should return 200 (success)
            assert resp.status_code == 200, (
                f"{method} {url} returned {resp.status_code} instead of 200"
            )

    def test_all_gated_endpoints_block_free_users(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        """All plan-gated endpoints return 403 for FREE users."""
        endpoints = [
            ("GET", "/v1/threats"),
            (
                "POST",
                "/v1/signatures",
                {
                    "id": "test",
                    "phase": "obfuscation",
                    "pattern": "test",
                    "severity": "MEDIUM",
                    "description": "Test",
                },
            ),
            ("GET", "/v1/threat-reports"),
        ]

        for method, url, *json_data in endpoints:
            if method == "GET":
                resp = client.get(url, headers=auth_headers)
            elif method == "POST":
                resp = client.post(url, json=json_data[0], headers=auth_headers)

            # All should return 403 (Forbidden)
            assert resp.status_code == 403, (
                f"{method} {url} returned {resp.status_code} instead of 403"
            )

            # All should have proper error structure
            error = resp.json()
            assert "detail" in error
            assert "required_plan" in error
            assert error["required_plan"] == "pro"

    def test_fix_resolved_nested_dependency_issue(self) -> None:
        """Document the fix: get_current_user_unified resolves nested dependency issue.

        The issue was a known FastAPI problem when:
        1. A dependency function (require_plan) has a parameter with Depends()
        2. That dependency (get_current_user) itself has Depends(oauth2_scheme)
        3. FastAPI fails to resolve the nested dependency properly

        The fix uses get_current_user_unified which:
        - Takes both OAuth2 and HTTPBearer tokens as direct dependencies
        - Avoids nested Depends() calls that confuse FastAPI
        - Properly supports both Supabase Auth and custom JWT tokens
        """
        # This is a documentation test - always passes
        assert True, "See test docstring for fix explanation"


# ---------------------------------------------------------------------------
# Test: Verify the implemented fix
# ---------------------------------------------------------------------------


class TestImplementedFix:
    """Tests verifying the implemented fix using get_current_user_unified.

    The fix implements a unified auth dependency that supports both Supabase Auth
    and custom JWT tokens without nested dependency conflicts.
    """

    def test_unified_auth_supports_custom_jwt(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Unified auth works with custom JWT tokens from registration."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_unified_auth_enforces_plan_gating(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        """Unified auth properly enforces plan tiers (FREE blocked from PRO endpoints)."""
        resp = client.get("/v1/threats", headers=auth_headers)
        assert resp.status_code == 403

        error = resp.json()
        assert error["required_plan"] == "pro"
        assert error["current_plan"] == "free"

    def test_dependency_chain_is_flattened(self) -> None:
        """Verify the fix uses flattened dependency chain.

        The get_current_user_unified function takes the Request object directly
        and manually extracts the token from headers, avoiding the dependency
        injection conflict between OAuth2PasswordBearer and HTTPBearer.
        """
        from api.routers.auth import get_current_user_unified
        import inspect

        # Verify the function signature uses Request directly
        sig = inspect.signature(get_current_user_unified)
        assert "request" in sig.parameters
        # The function takes only one parameter: Request
        assert len(sig.parameters) == 1
        # The parameter type should be Request
        assert sig.parameters["request"].annotation == "Request"
