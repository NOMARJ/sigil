"""Sigil API — verify_auth0_token /userinfo fallback (F1.5).

When an Auth0 access token does not carry the email claim (the default
behavior unless a Post-Login Action injects a namespaced claim), the API
should fall back to fetching the email + name from the Auth0 /userinfo
endpoint with the access token. This avoids the operator-managed Auth0
Action becoming a hidden dependency that can drift between environments.

Pre-fix: verify_auth0_token returns {"email": "", ...}; the caller
_auto_provision_auth0_user raises 401 "Auth0 token missing email claim".
Post-fix: verify_auth0_token fetches /userinfo and returns the email.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_userinfo_fallback_when_email_claim_missing(monkeypatch):
    """If the JWT payload has no email claim, /userinfo should be queried."""
    from api import config as config_module
    from api.routers import auth as auth_module

    monkeypatch.setattr(config_module.settings, "auth0_domain", "test.auth0.com")
    monkeypatch.setattr(
        config_module.settings, "auth0_audience", "https://api.test.local"
    )

    auth_module._auth0_jwks_cache = {
        "keys": [
            {"kid": "test-kid", "alg": "RS256", "kty": "RSA", "n": "x", "e": "AQAB"}
        ]
    }
    monkeypatch.setattr(auth_module, "_USE_JOSE", True)

    fake_payload = {
        "sub": "auth0|user-without-email-claim",
        "iss": "https://test.auth0.com/",
        "aud": "https://api.test.local",
    }
    fake_jose = MagicMock()
    fake_jose.get_unverified_header.return_value = {"kid": "test-kid"}
    fake_jose.decode.return_value = fake_payload
    monkeypatch.setattr(auth_module, "_jose_jwt", fake_jose)

    userinfo_calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        userinfo_calls.append(request)
        return httpx.Response(
            200,
            json={
                "sub": "auth0|user-without-email-claim",
                "email": "fallback@example.com",
                "name": "Fallback User",
                "email_verified": True,
            },
        )

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(auth_module.httpx, "AsyncClient", factory)

    result = await auth_module.verify_auth0_token("fake-access-token")

    assert result["email"] == "fallback@example.com", (
        f"Expected /userinfo fallback to populate email, got: {result!r}"
    )
    assert result["name"] == "Fallback User"
    assert result["sub"] == "auth0|user-without-email-claim"

    assert len(userinfo_calls) == 1, (
        f"Expected exactly 1 /userinfo call, got: {len(userinfo_calls)}"
    )
    req = userinfo_calls[0]
    assert req.url.path == "/userinfo"
    assert req.url.host == "test.auth0.com"
    assert req.headers.get("authorization") == "Bearer fake-access-token"


@pytest.mark.asyncio
async def test_userinfo_fallback_NOT_called_when_email_claim_present(monkeypatch):
    """If the JWT payload carries the namespaced email claim, /userinfo must NOT be hit."""
    from api import config as config_module
    from api.routers import auth as auth_module

    monkeypatch.setattr(config_module.settings, "auth0_domain", "test.auth0.com")
    monkeypatch.setattr(
        config_module.settings, "auth0_audience", "https://api.test.local"
    )

    auth_module._auth0_jwks_cache = {
        "keys": [
            {"kid": "test-kid", "alg": "RS256", "kty": "RSA", "n": "x", "e": "AQAB"}
        ]
    }
    monkeypatch.setattr(auth_module, "_USE_JOSE", True)

    fake_payload = {
        "sub": "auth0|user-with-email-claim",
        "iss": "https://test.auth0.com/",
        "aud": "https://api.test.local",
        "https://api.sigilsec.ai/email": "claimed@example.com",
        "https://api.sigilsec.ai/name": "Claimed User",
        "https://api.sigilsec.ai/email_verified": True,
    }
    fake_jose = MagicMock()
    fake_jose.get_unverified_header.return_value = {"kid": "test-kid"}
    fake_jose.decode.return_value = fake_payload
    monkeypatch.setattr(auth_module, "_jose_jwt", fake_jose)

    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(
            f"/userinfo must not be called when claims are present; got {request.url}"
        )

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(auth_module.httpx, "AsyncClient", factory)

    result = await auth_module.verify_auth0_token("fake-access-token")

    assert result["email"] == "claimed@example.com"
    assert result["name"] == "Claimed User"
    assert result["sub"] == "auth0|user-with-email-claim"


@pytest.mark.asyncio
async def test_unverified_auth0_email_is_rejected(monkeypatch):
    from api import config as config_module
    from api.routers import auth as auth_module

    monkeypatch.setattr(config_module.settings, "auth0_domain", "test.auth0.com")
    monkeypatch.setattr(
        config_module.settings, "auth0_audience", "https://api.test.local"
    )

    auth_module._auth0_jwks_cache = {
        "keys": [
            {"kid": "test-kid", "alg": "RS256", "kty": "RSA", "n": "x", "e": "AQAB"}
        ]
    }
    monkeypatch.setattr(auth_module, "_USE_JOSE", True)

    fake_payload = {
        "sub": "auth0|unverified-user",
        "iss": "https://test.auth0.com/",
        "aud": "https://api.test.local",
        "email": "victim@example.com",
        "email_verified": False,
    }
    fake_jose = MagicMock()
    fake_jose.get_unverified_header.return_value = {"kid": "test-kid"}
    fake_jose.decode.return_value = fake_payload
    monkeypatch.setattr(auth_module, "_jose_jwt", fake_jose)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "sub": "auth0|unverified-user",
                "email": "victim@example.com",
                "email_verified": False,
            },
        )

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(auth_module.httpx, "AsyncClient", factory)

    with pytest.raises(HTTPException) as exc:
        await auth_module.verify_auth0_token("fake-access-token")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Email must be verified"


@pytest.mark.asyncio
async def test_userinfo_fallback_failure_returns_sanitized_401(monkeypatch):
    from api import config as config_module
    from api.routers import auth as auth_module

    monkeypatch.setattr(config_module.settings, "auth0_domain", "test.auth0.com")
    monkeypatch.setattr(
        config_module.settings, "auth0_audience", "https://api.test.local"
    )

    auth_module._auth0_jwks_cache = {
        "keys": [
            {"kid": "test-kid", "alg": "RS256", "kty": "RSA", "n": "x", "e": "AQAB"}
        ]
    }
    monkeypatch.setattr(auth_module, "_USE_JOSE", True)

    fake_payload = {
        "sub": "auth0|provider-error",
        "iss": "https://test.auth0.com/",
        "aud": "https://api.test.local",
    }
    fake_jose = MagicMock()
    fake_jose.get_unverified_header.return_value = {"kid": "test-kid"}
    fake_jose.decode.return_value = fake_payload
    monkeypatch.setattr(auth_module, "_jose_jwt", fake_jose)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="provider stack trace")

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(auth_module.httpx, "AsyncClient", factory)

    with pytest.raises(HTTPException) as exc:
        await auth_module.verify_auth0_token("fake-access-token")

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid or expired token"
    assert "provider stack trace" not in exc.value.detail


@pytest.mark.asyncio
async def test_auth0_provisioning_rejects_existing_subject_mismatch(monkeypatch):
    from api.routers import auth as auth_module

    mock_db = MagicMock()
    mock_db._table_columns = AsyncMock(
        return_value={"id", "email", "auth0_sub", "password_hash", "role"}
    )
    mock_db.select_one = AsyncMock(
        side_effect=[
            None,
            {
                "id": "victim",
                "email": "victim@example.com",
                "auth0_sub": "auth0|victim",
            },
        ]
    )
    monkeypatch.setattr(auth_module, "db", mock_db)

    with pytest.raises(HTTPException) as exc:
        await auth_module._auto_provision_auth0_user(
            {
                "sub": "auth0|attacker",
                "email": "victim@example.com",
                "email_verified": True,
            }
        )

    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid or expired token"


@pytest.mark.asyncio
async def test_auth0_provisioning_binds_verified_existing_email(monkeypatch):
    from api.routers import auth as auth_module

    existing = {
        "id": "user_1",
        "email": "user@example.com",
        "auth0_sub": None,
        "name": "",
        "role": "member",
    }
    mock_db = MagicMock()
    mock_db._table_columns = AsyncMock(
        return_value={"id", "email", "auth0_sub", "password_hash", "role"}
    )
    mock_db.select_one = AsyncMock(side_effect=[None, existing])
    mock_db.upsert = AsyncMock(return_value={**existing, "auth0_sub": "auth0|user"})
    monkeypatch.setattr(auth_module, "db", mock_db)

    result = await auth_module._auto_provision_auth0_user(
        {
            "sub": "auth0|user",
            "email": "USER@example.com",
            "name": "Verified User",
            "email_verified": True,
        }
    )

    assert result["auth0_sub"] == "auth0|user"
    mock_db.upsert.assert_awaited_once()
