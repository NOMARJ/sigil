"""
Sigil API — Test Fixtures

Provides shared fixtures for the test suite including a FastAPI test client
with mocked database/cache backends, authenticated user helpers, and sample
data factories.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Iterator
from uuid import uuid4

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from database import _memory_cache, db


_original_async_client_init = httpx.AsyncClient.__init__


def _compat_async_client_init(self, *args, **kwargs):
    """Back-compat for tests that use AsyncClient(app=..., base_url=...)."""
    app = kwargs.pop("app", None)
    if app is not None and "transport" not in kwargs:
        kwargs["transport"] = httpx.ASGITransport(app=app)
    return _original_async_client_init(self, *args, **kwargs)


httpx.AsyncClient.__init__ = _compat_async_client_init

# Allow very long URL test cases to reach the API layer
try:
    import httpx._urlparse as _httpx_urlparse

    _httpx_urlparse.MAX_URL_LENGTH = max(
        getattr(_httpx_urlparse, "MAX_URL_LENGTH", 65536), 200000
    )
except Exception:
    pass


def pytest_collection_modifyitems(config, items):
    """Skip infra-heavy suites unless explicitly enabled."""
    if os.getenv("SIGIL_RUN_EXTENDED_TESTS") == "1":
        return

    extended_files = {
        "test_analytics_service.py",
        "test_billing_integration.py",
        "test_phase9_llm.py",
        "test_forge.py",
        "test_forge_classification.py",
        "test_forge_premium_implementation.py",
        "test_forge_security.py",
        "test_forge_security_audit.py",
        "test_integration_comprehensive.py",
        "test_monitoring_comprehensive.py",
        "test_performance_comprehensive.py",
        "test_pro_performance.py",
        "test_pro_tier.py",
        "test_permissions.py",
        "test_resilience_comprehensive.py",
        "test_scanner_service.py",
        "test_security_comprehensive.py",
        "test_tier_gating.py",
    }
    skip_marker = pytest.mark.skip(
        reason="Extended integration/security suite skipped by default. Set SIGIL_RUN_EXTENDED_TESTS=1 to run."
    )

    for item in items:
        if any(
            item.nodeid.endswith(file_name) or f"/{file_name}::" in item.nodeid
            for file_name in extended_files
        ):
            item.add_marker(skip_marker)


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
    db._memory_store.clear()
    _memory_cache.clear()
    yield
    db._memory_store.clear()
    _memory_cache.clear()


# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """Create a TestClient for the Sigil API application.

    Uses the in-memory fallback stores (no Supabase/Redis required).
    """
    from main import app

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
    from database import db

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


@pytest.fixture
def mock_free_user() -> Any:
    user = MagicMock()
    user.id = "free_user_123"
    user.email = "free@example.com"
    user.name = "Free User"
    return user


@pytest.fixture
def mock_pro_user() -> Any:
    user = MagicMock()
    user.id = "pro_user_123"
    user.email = "pro@example.com"
    user.name = "Pro User"
    return user


@pytest.fixture
def webhook_headers() -> dict[str, str]:
    return {
        "stripe-signature": "t=1677123456,v1=test_signature_123",
    }


@pytest.fixture
def sample_analysis_request():
    from llm_models import LLMAnalysisRequest, LLMAnalysisType

    return LLMAnalysisRequest(
        file_contents={
            "malicious.py": "import os; os.system(input('Command: '))",
            "helper.py": "def decode_payload(data): return base64.b64decode(data)",
        },
        static_findings=[
            {
                "phase": "code_patterns",
                "rule": "code-exec",
                "severity": "HIGH",
                "file": "malicious.py",
                "line": 1,
                "snippet": "os.system(input('Command: '))",
                "weight": 1.0,
            }
        ],
        analysis_types=[
            LLMAnalysisType.ZERO_DAY_DETECTION,
            LLMAnalysisType.CONTEXT_CORRELATION,
        ],
        include_context_analysis=True,
        max_insights=10,
        max_tokens=2000,
    )


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


@pytest.fixture()
def sample_mcp_scan() -> dict[str, Any]:
    return {
        "id": "test-scan-1",
        "package_name": "test-mcp-server",
        "ecosystem": "mcp",
        "scanned_at": "2024-01-15T10:30:00Z",
        "metadata_json": json.dumps(
            {
                "author": "test-author",
                "description": "A test MCP server for testing permissions",
                "stars": 42,
                "language": "TypeScript",
                "version": "1.0.0",
            }
        ),
        "findings_json": [
            {
                "phase": "code_patterns",
                "rule": "env-access",
                "severity": "MEDIUM",
                "file": "server.ts",
                "line": 15,
                "snippet": "const dbUrl = process.env.DATABASE_URL",
                "weight": 1.0,
            },
            {
                "phase": "code_patterns",
                "rule": "file-access",
                "severity": "HIGH",
                "file": "server.ts",
                "line": 25,
                "snippet": "fs.readFile('/etc/config.json')",
                "weight": 1.0,
            },
            {
                "phase": "network",
                "rule": "http-request",
                "severity": "MEDIUM",
                "file": "client.ts",
                "line": 10,
                "snippet": "fetch('https://api.external.com/data')",
                "weight": 1.0,
            },
        ],
    }


@pytest.fixture()
def high_risk_mcp_scan() -> dict[str, Any]:
    return {
        "id": "test-scan-2",
        "package_name": "dangerous-mcp-server",
        "ecosystem": "mcp",
        "scanned_at": "2024-01-15T11:00:00Z",
        "metadata_json": json.dumps(
            {
                "author": "unknown-author",
                "description": "This server has dangerous permissions",
                "stars": 5,
                "language": "JavaScript",
                "version": "0.1.0",
            }
        ),
        "findings_json": [
            {
                "phase": "code_patterns",
                "rule": "process-exec",
                "severity": "CRITICAL",
                "file": "main.js",
                "line": 20,
                "snippet": "exec('rm -rf /tmp/*')",
                "weight": 1.0,
            },
            {
                "phase": "credentials",
                "rule": "cred-access",
                "severity": "HIGH",
                "file": "auth.js",
                "line": 5,
                "snippet": "const token = process.env.SECRET_TOKEN",
                "weight": 1.0,
            },
            {
                "phase": "code_patterns",
                "rule": "file-access",
                "severity": "HIGH",
                "file": "main.js",
                "line": 30,
                "snippet": "fs.writeFile('/etc/passwd', data)",
                "weight": 1.0,
            },
        ],
    }


@pytest.fixture()
def clean_mcp_scan() -> dict[str, Any]:
    return {
        "id": "test-scan-3",
        "package_name": "safe-mcp-server",
        "ecosystem": "mcp",
        "scanned_at": "2024-01-15T12:00:00Z",
        "metadata_json": json.dumps(
            {
                "author": "trusted-author",
                "description": "A safe MCP server with minimal permissions",
                "stars": 150,
                "language": "Python",
                "version": "2.1.0",
            }
        ),
        "findings_json": [],
    }
