"""
Sigil API — Authentication Tests

Tests for the auth endpoints: register, login, and token validation.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.routers import auth as auth_router


class TestPasswordHashing:
    """Regression tests for local password hash compatibility helpers."""

    def test_new_password_hashes_use_versioned_pbkdf2(self) -> None:
        password = "ValidPassword123!"

        hashed = auth_router._hash_password(password)

        assert hashed.startswith("pbkdf2:sha256:310000:")
        assert auth_router._verify_password(password, hashed)
        assert not auth_router._verify_password("WrongPassword123!", hashed)

    def test_old_pbkdf2_hashes_still_verify(self) -> None:
        password = "ValidPassword123!"
        salt = "0123456789abcdef0123456789abcdef"
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
        )
        legacy_hash = f"pbkdf2:sha256:{salt}:{dk.hex()}"

        assert auth_router._verify_password(password, legacy_hash)
        assert not auth_router._verify_password("WrongPassword123!", legacy_hash)

    def test_legacy_bcrypt_hashes_still_verify_without_passlib(self) -> None:
        if auth_router._bcrypt is None:
            pytest.skip("bcrypt package is unavailable")

        password = "ValidPassword123!"
        bcrypt_hash = auth_router._bcrypt.hashpw(
            password.encode("utf-8"), auth_router._bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

        assert auth_router._verify_password(password, bcrypt_hash)
        assert not auth_router._verify_password("WrongPassword123!", bcrypt_hash)

    def test_malformed_pbkdf2_hashes_fail_closed(self) -> None:
        assert not auth_router._verify_password("ValidPassword123!", "pbkdf2:sha256")
        assert not auth_router._verify_password(
            "ValidPassword123!", "pbkdf2:sha256:not-an-int:salt:hash"
        )


class TestRegistration:
    """Tests for POST /v1/auth/register."""

    def test_register_success(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """POST /v1/auth/register is deprecated (410 Gone) post-Auth0 migration.

        Registration moved to the Auth0 Database Connection; the legacy endpoint
        now returns 410. See api/routers/auth.py:605-621 (register, deprecated=True,
        HTTP_410_GONE) and the Auth0 migration (docs/internal/AUTH0_SETUP_GUIDE.md,
        ADR-0002 password-reset-via-auth0).
        """
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 410
        assert "deprecated" in resp.json()["detail"].lower()

    def test_register_duplicate_email(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """Duplicate-email handling moved to Auth0; legacy register returns 410.

        Post-Auth0 the custom register endpoint no longer performs duplicate
        detection — it is deprecated (410 Gone). See api/routers/auth.py:605-621
        and the Auth0 migration (docs/internal/AUTH0_SETUP_GUIDE.md).
        """
        resp1 = client.post("/v1/auth/register", json=test_user_data)
        assert resp1.status_code == 410

        resp2 = client.post("/v1/auth/register", json=test_user_data)
        assert resp2.status_code == 410

    def test_register_short_password(self, client: TestClient) -> None:
        """Password shorter than 8 characters should be rejected."""
        resp = client.post(
            "/v1/auth/register",
            json={
                "email": "short@sigil.dev",
                "password": "short",
                "name": "Short Password",
            },
        )
        assert resp.status_code == 422

    def test_register_missing_email(self, client: TestClient) -> None:
        """Missing email should return 422."""
        resp = client.post(
            "/v1/auth/register",
            json={
                "password": "ValidPassword123",
                "name": "No Email",
            },
        )
        assert resp.status_code == 422

    def test_register_empty_name(self, client: TestClient) -> None:
        """A valid body reaches the deprecated endpoint and returns 410.

        (Bodies failing validation return 422 before the 410 handler — see
        test_register_short_password / test_register_missing_email.) A well-formed
        body passes validation and hits the deprecation. See api/routers/auth.py:605-621
        and the Auth0 migration (docs/internal/AUTH0_SETUP_GUIDE.md).
        """
        resp = client.post(
            "/v1/auth/register",
            json={
                "email": "noname@sigil.dev",
                "password": "ValidPassword123",
            },
        )
        assert resp.status_code == 410
        assert "deprecated" in resp.json()["detail"].lower()


class TestLogin:
    """Tests for POST /v1/auth/login."""

    def test_login_success(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """POST /v1/auth/login is deprecated (410 Gone) post-Auth0 migration.

        Login moved to the Auth0 Universal Login flow; the legacy endpoint now
        returns 410. See api/routers/auth.py:624-640 (login, deprecated=True,
        HTTP_410_GONE) and the Auth0 migration (docs/internal/AUTH0_SETUP_GUIDE.md).
        """
        resp = client.post(
            "/v1/auth/login",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["password"],
            },
        )
        assert resp.status_code == 410
        assert "deprecated" in resp.json()["detail"].lower()

    def test_login_wrong_password(
        self, client: TestClient, test_user_data: dict[str, str]
    ) -> None:
        """Credential checks moved to Auth0; legacy login returns 410.

        Wrong-password handling is now Auth0's responsibility — the legacy
        endpoint is deprecated (410 Gone) regardless of credentials. See
        api/routers/auth.py:624-640 and the Auth0 migration.
        """
        resp = client.post(
            "/v1/auth/login",
            json={
                "email": test_user_data["email"],
                "password": "WrongPassword999",
            },
        )
        assert resp.status_code == 410

    def test_login_nonexistent_user(self, client: TestClient) -> None:
        """Legacy login returns 410 for any input post-Auth0 migration.

        See api/routers/auth.py:624-640 (deprecated=True, HTTP_410_GONE) and the
        Auth0 migration (docs/internal/AUTH0_SETUP_GUIDE.md).
        """
        resp = client.post(
            "/v1/auth/login",
            json={
                "email": "ghost@sigil.dev",
                "password": "DoesNotMatter",
            },
        )
        assert resp.status_code == 410


class TestTokenValidation:
    """Tests for GET /v1/auth/me (token validation)."""

    def test_me_with_valid_token(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        registered_user: dict[str, Any],
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
