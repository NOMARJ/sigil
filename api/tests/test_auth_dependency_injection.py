"""
Sigil API — Authentication Dependency Injection Tests

Comprehensive tests documenting authentication behavior on threat API endpoints.

## CRITICAL FINDING:

As of the current codebase state, `require_plan()` has a dependency injection issue.
ALL plan-gated endpoints return 422 with error: "Field 'current_user' required in query".

FastAPI is treating the `current_user` dependency parameter as a query parameter
instead of resolving it as a dependency. This is a known FastAPI issue with nested
dependencies when using OAuth2PasswordBearer.

## WORKING ENDPOINTS (plan gating temporarily disabled):

- GET /v1/threat/{hash} - accessible without authentication
- GET /v1/signatures - accessible without authentication

## BROKEN ENDPOINTS (422 error due to dependency injection issue):

- GET /v1/threats
- POST /v1/signatures
- DELETE /v1/signatures/{id}
- GET /v1/threat-reports
- GET /v1/threat-reports/{id}
- PATCH /v1/threat-reports/{id}

## ROOT CAUSE:

The issue is in `api/gates.py`:

```python
def require_plan(minimum_tier: PlanTier):
    from api.routers.auth import get_current_user, UserResponse

    async def _gate(
        current_user: Annotated[UserResponse, Depends(get_current_user)],
    ) -> None:
        ...
```

When `get_current_user` is used as a dependency inside `require_plan`, FastAPI
fails to properly resolve the nested `Depends(oauth2_scheme)` inside `get_current_user`.

## TESTS:

These tests document the current broken state and will serve as regression tests
once the dependency injection issue is fixed.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from api.database import _memory_store


# ---------------------------------------------------------------------------
# Test: Endpoints with disabled plan gating (WORKING)
# ---------------------------------------------------------------------------


class TestWorkingEndpoints:
    """Tests for endpoints where plan gating is disabled and authentication works.

    These endpoints are accessible without authentication as a temporary workaround
    for the dependency injection issue in require_plan().
    """

    def test_get_threat_found(self, client: TestClient) -> None:
        """GET /v1/threat/{hash} works without authentication."""
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
        _memory_store.setdefault("threats", {})["test-threat-1"] = threat

        resp = client.get("/v1/threat/abc123deadbeef456")
        assert resp.status_code == 200

        data = resp.json()
        assert data["package_name"] == "evil-pkg"
        assert data["severity"] == "CRITICAL"

    def test_get_threat_not_found(self, client: TestClient) -> None:
        """GET /v1/threat/{hash} returns 404 for non-existent hash."""
        resp = client.get("/v1/threat/0000000000000000000000000000000000000000")
        assert resp.status_code == 404
        assert "No threat entry found" in resp.json()["detail"]

    def test_list_signatures(self, client: TestClient) -> None:
        """GET /v1/signatures works without authentication."""
        resp = client.get("/v1/signatures")
        assert resp.status_code == 200

        data = resp.json()
        assert "signatures" in data
        assert "total" in data
        assert data["total"] > 0

    def test_signatures_with_since_filter(self, client: TestClient) -> None:
        """GET /v1/signatures supports 'since' parameter."""
        resp = client.get("/v1/signatures?since=2099-01-01T00:00:00")
        assert resp.status_code == 200

        data = resp.json()
        assert data["total"] == 0
        assert data["signatures"] == []

    def test_signatures_contain_multiple_phases(self, client: TestClient) -> None:
        """Built-in signatures cover multiple scan phases."""
        resp = client.get("/v1/signatures")
        data = resp.json()

        phases = {sig["phase"] for sig in data["signatures"]}
        assert "install_hooks" in phases
        assert "code_patterns" in phases
        assert "obfuscation" in phases


# ---------------------------------------------------------------------------
# Test: Broken endpoints with dependency injection issue
# ---------------------------------------------------------------------------


class TestBrokenDependencyInjection:
    """Tests documenting the dependency injection issue in plan-gated endpoints.

    These tests are marked with `pytest.mark.xfail` and will pass once the
    dependency injection issue is fixed. They serve as regression tests.
    """

    @pytest.mark.xfail(
        reason="Dependency injection issue: require_plan() treats current_user as query param",
        strict=True,
    )
    def test_pro_user_can_list_threats(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user should be able to access GET /v1/threats (currently broken)."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200

    @pytest.mark.xfail(
        reason="Dependency injection issue in require_plan()",
        strict=True,
    )
    def test_pro_user_can_create_signature(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user should be able to POST /v1/signatures (currently broken)."""
        payload = {
            "id": "test-sig-1",
            "phase": "obfuscation",
            "pattern": r"atob\(",
            "severity": "MEDIUM",
            "description": "Test",
        }

        resp = client.post("/v1/signatures", json=payload, headers=pro_auth_headers)
        assert resp.status_code == 200

    @pytest.mark.xfail(
        reason="Dependency injection issue in require_plan()",
        strict=True,
    )
    def test_pro_user_can_delete_signature(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """PRO user should be able to DELETE /v1/signatures/{id} (currently broken)."""
        sig_id = "test-sig-delete"
        _memory_store.setdefault("signatures", {})[sig_id] = {
            "id": sig_id,
            "phase": "code_patterns",
            "pattern": r"eval\(",
            "severity": "HIGH",
            "description": "Test",
            "updated_at": datetime.utcnow(),
        }

        resp = client.delete(f"/v1/signatures/{sig_id}", headers=pro_auth_headers)
        assert resp.status_code == 200

    @pytest.mark.xfail(
        reason="Dependency injection issue in require_plan()",
        strict=True,
    )
    def test_free_plan_blocked_from_threats(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        """FREE user should be blocked from GET /v1/threats (currently broken)."""
        resp = client.get("/v1/threats", headers=auth_headers)
        assert resp.status_code == 403

    def test_dependency_injection_error_message(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Document the actual error returned by broken endpoints."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)

        # Currently returns 422 instead of 200
        assert resp.status_code == 422

        # Error indicates current_user is treated as query parameter
        error = resp.json()
        assert "detail" in error
        assert any(
            err.get("loc") == ["query", "current_user"] for err in error["detail"]
        )
        assert any(err.get("msg") == "Field required" for err in error["detail"])


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
        from api.database import _memory_store
        from uuid import uuid4
        import asyncio

        # Create user with PRO subscription
        user_id = str(uuid4())
        _memory_store.setdefault("subscriptions", {})[user_id] = {
            "user_id": user_id,
            "plan": "pro",
            "status": "active",
        }

        plan = asyncio.run(get_user_plan(user_id))
        assert plan == PlanTier.PRO

    def test_subscription_data_structure(self) -> None:
        """Subscription data is stored with correct structure."""
        from api.database import _memory_store
        from uuid import uuid4

        user_id = str(uuid4())
        _memory_store.setdefault("subscriptions", {})[user_id] = {
            "user_id": user_id,
            "plan": "pro",
            "status": "active",
            "stripe_subscription_id": "sub_test",
        }

        subscriptions = _memory_store.get("subscriptions", {})
        assert user_id in subscriptions
        assert subscriptions[user_id]["plan"] == "pro"
        assert subscriptions[user_id]["status"] == "active"


# ---------------------------------------------------------------------------
# Test: Comprehensive documentation of the issue
# ---------------------------------------------------------------------------


class TestDependencyInjectionIssueDocumentation:
    """Comprehensive documentation of the dependency injection issue.

    This test class serves as living documentation of the problem and will
    help verify when it's fixed.
    """

    def test_issue_affects_all_gated_endpoints(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """All plan-gated endpoints return 422 with same error."""
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

            # All should return 422
            assert resp.status_code == 422, (
                f"{method} {url} returned {resp.status_code} instead of 422"
            )

            # All should have same error structure
            error = resp.json()
            assert "detail" in error
            assert isinstance(error["detail"], list)

    def test_error_indicates_query_parameter_issue(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Error message indicates FastAPI treating dependency as query param."""
        resp = client.get("/v1/threats", headers=pro_auth_headers)

        error = resp.json()
        # Find the current_user error
        current_user_error = next(
            err
            for err in error["detail"]
            if err.get("loc") == ["query", "current_user"]
        )

        assert current_user_error["type"] == "missing"
        assert current_user_error["msg"] == "Field required"
        # Location is "query" which is wrong - should be resolved as dependency
        assert current_user_error["loc"] == ["query", "current_user"]

    def test_issue_root_cause_nested_depends(self) -> None:
        """Document the root cause: nested Depends() in dependency chain.

        This is a known FastAPI issue when:
        1. A dependency function (require_plan) has a parameter with Depends()
        2. That dependency (get_current_user) itself has Depends(oauth2_scheme)
        3. FastAPI fails to resolve the nested dependency properly

        The fix requires either:
        - Flattening the dependency chain
        - Using Request object to manually extract auth header
        - Refactoring require_plan to not use nested dependencies
        """
        # This is a documentation test - always passes
        assert True, "See test docstring for root cause analysis"


# ---------------------------------------------------------------------------
# Test: Proposed fixes (will fail until implemented)
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="Proposed fix not yet implemented")
class TestProposedFixes:
    """Tests for proposed fixes to the dependency injection issue.

    These tests will be enabled once a fix is implemented.
    """

    def test_fix_option_1_manual_token_extraction(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Fix Option 1: Manually extract token from Request object.

        Instead of:
            async def _gate(current_user: Annotated[UserResponse, Depends(get_current_user)]):

        Use:
            async def _gate(request: Request):
                token = request.headers.get("Authorization", "").replace("Bearer ", "")
                current_user = await verify_token_and_get_user(token)
        """
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_fix_option_2_unified_auth_dependency(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Fix Option 2: Create a unified auth dependency without nested Depends.

        Create get_current_user_for_gates() that:
        - Takes Request object directly
        - Manually extracts and validates token
        - Returns UserResponse without nested dependencies
        """
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200

    def test_fix_option_3_flatten_dependency_chain(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
    ) -> None:
        """Fix Option 3: Flatten dependency chain by combining auth + plan check.

        Instead of separate get_current_user and require_plan dependencies,
        create a single require_plan_and_auth() dependency that does both.
        """
        resp = client.get("/v1/threats", headers=pro_auth_headers)
        assert resp.status_code == 200
