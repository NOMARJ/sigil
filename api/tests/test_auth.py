"""
Sigil API — Authentication Tests

Tests for the auth endpoints: register, login, and token validation.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


class TestRegistration:
    """Tests for POST /v1/auth/register."""

    def test_register_success(self, client: TestClient, test_user_data: dict[str, str]) -> None:
        """Successful registration returns 201 with a token."""
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 201

        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
        assert data["user"]["email"] == test_user_data["email"]
        assert data["user"]["name"] == test_user_data["name"]
        assert "id" in data["user"]

    def test_register_duplicate_email(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """Registering with an existing email returns 409."""
        # First registration
        resp1 = client.post("/v1/auth/register", json=test_user_data)
        assert resp1.status_code == 201

        # Duplicate registration
        resp2 = client.post("/v1/auth/register", json=test_user_data)
        assert resp2.status_code == 409
        assert "already exists" in resp2.json()["detail"]

    def test_register_short_password(self, client: TestClient) -> None:
        """Password shorter than 8 characters should be rejected."""
        resp = client.post("/v1/auth/register", json={
            "email": "short@sigil.dev",
            "password": "short",
            "name": "Short Password",
        })
        assert resp.status_code == 422

    def test_register_missing_email(self, client: TestClient) -> None:
        """Missing email should return 422."""
        resp = client.post("/v1/auth/register", json={
            "password": "ValidPassword123",
            "name": "No Email",
        })
        assert resp.status_code == 422

    def test_register_empty_name(self, client: TestClient) -> None:
        """Empty name should be allowed (defaults to empty string)."""
        resp = client.post("/v1/auth/register", json={
            "email": "noname@sigil.dev",
            "password": "ValidPassword123",
        })
        assert resp.status_code == 201
        assert resp.json()["user"]["name"] == ""


class TestLogin:
    """Tests for POST /v1/auth/login."""

    def test_login_success(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """Successful login returns a valid token."""
        # Register first
        client.post("/v1/auth/register", json=test_user_data)

        # Login
        resp = client.post("/v1/auth/login", json={
            "email": test_user_data["email"],
            "password": test_user_data["password"],
        })
        assert resp.status_code == 200

        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == test_user_data["email"]

    def test_login_wrong_password(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """Wrong password returns 401."""
        client.post("/v1/auth/register", json=test_user_data)

        resp = client.post("/v1/auth/login", json={
            "email": test_user_data["email"],
            "password": "WrongPassword999",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client: TestClient) -> None:
        """Login for a non-existent user returns 401."""
        resp = client.post("/v1/auth/login", json={
            "email": "ghost@sigil.dev",
            "password": "DoesNotMatter",
        })
        assert resp.status_code == 401


class TestTokenValidation:
    """Tests for GET /v1/auth/me (token validation)."""

    def test_me_with_valid_token(
        self, client: TestClient, auth_headers: dict[str, str], registered_user: dict[str, Any]
    ) -> None:
        """GET /me with a valid token returns the user profile."""
        resp = client.get("/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200

        data = resp.json()
        assert data["id"] == registered_user["user"]["id"]
        assert data["email"] == registered_user["user"]["email"]

    def test_me_without_token(self, client: TestClient) -> None:
        """GET /me without a token returns 401."""
        resp = client.get("/v1/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_token(self, client: TestClient) -> None:
        """GET /me with a garbage token returns 401."""
        headers = {"Authorization": "Bearer invalid.garbage.token"}
        resp = client.get("/v1/auth/me", headers=headers)
        assert resp.status_code == 401

    def test_me_with_expired_format_token(self, client: TestClient) -> None:
        """GET /me with a malformed token returns 401."""
        headers = {"Authorization": "Bearer not-even-three-parts"}
        resp = client.get("/v1/auth/me", headers=headers)
        assert resp.status_code == 401
