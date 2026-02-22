"""
Sigil API — Test Fixtures

Provides shared fixtures for the test suite including a FastAPI test client
with mocked database/cache backends, authenticated user helpers, and sample
data factories.
"""

from __future__ import annotations

import asyncio
from typing import Any, Iterator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.database import _memory_store, _memory_cache


# ---------------------------------------------------------------------------
# Event loop fixture for async tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """Create a session-scoped event loop for async fixtures."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Reset in-memory stores between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_memory_stores():
    """Clear in-memory fallback stores before each test for isolation."""
    _memory_store.clear()
    _memory_cache.clear()
    yield
    _memory_store.clear()
    _memory_cache.clear()


# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """Create a TestClient for the Sigil API application.

    Uses the in-memory fallback stores (no Supabase/Redis required).
    """
    from api.main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_user_data() -> dict[str, str]:
    """Return standard test user registration data."""
    return {
        "email": f"test-{uuid4().hex[:8]}@sigil.dev",
        "password": "TestPassword123!",
        "name": "Test User",
    }


@pytest.fixture()
def registered_user(
    client: TestClient, test_user_data: dict[str, str]
) -> dict[str, Any]:
    """Register a test user and return the full response dict (includes token)."""
    resp = client.post("/v1/auth/register", json=test_user_data)
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    return resp.json()


@pytest.fixture()
def auth_headers(registered_user: dict[str, Any]) -> dict[str, str]:
    """Return Authorization headers for the registered test user."""
    token = registered_user["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def pro_user(client: TestClient, test_user_data: dict[str, str]) -> dict[str, Any]:
    """Register a test user and upgrade them to PRO plan."""
    import asyncio
    from api.database import db

    # Register user
    resp = client.post("/v1/auth/register", json=test_user_data)
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    user_data = resp.json()

    # Upgrade to PRO plan using database API
    user_id = user_data["user"]["id"]
    asyncio.run(
        db.upsert_subscription(
            user_id=user_id,
            plan="pro",
            status="active",
            stripe_subscription_id="sub_test_pro",
        )
    )

    return user_data


@pytest.fixture()
def pro_auth_headers(pro_user: dict[str, Any]) -> dict[str, str]:
    """Return Authorization headers for a PRO plan user."""
    token = pro_user["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Sample data factories
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_findings() -> list[dict[str, Any]]:
    """Return a list of sample findings for scan tests."""
    return [
        {
            "phase": "install_hooks",
            "rule": "install-npm-postinstall",
            "severity": "CRITICAL",
            "file": "package.json",
            "line": 10,
            "snippet": '"postinstall": "node malicious.js"',
            "weight": 1.0,
        },
        {
            "phase": "code_patterns",
            "rule": "code-eval",
            "severity": "HIGH",
            "file": "index.js",
            "line": 42,
            "snippet": "eval(atob(payload))",
            "weight": 1.0,
        },
        {
            "phase": "obfuscation",
            "rule": "obf-base64-decode",
            "severity": "HIGH",
            "file": "index.js",
            "line": 43,
            "snippet": "atob(payload)",
            "weight": 1.0,
        },
    ]


@pytest.fixture()
def sample_scan_request(sample_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a sample scan submission payload."""
    return {
        "target": "evil-package",
        "target_type": "npm",
        "files_scanned": 15,
        "findings": sample_findings,
        "metadata": {"version": "1.0.0"},
    }


@pytest.fixture()
def clean_scan_request() -> dict[str, Any]:
    """Return a scan request with no findings (should be CLEAN)."""
    return {
        "target": "safe-package",
        "target_type": "pip",
        "files_scanned": 10,
        "findings": [],
        "metadata": {},
    }
