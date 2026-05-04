"""Sigil API — interactive router registration regression (F1.7).

api/routers/interactive.py defines 33 Pro-gated routes (AI investigation,
chat, attack-chain, compliance-mapping — the headline Pro features). The
router was unmounted from api/main.py because the import chain crashed on a
non-existent `api.exceptions` module that four service files imported from.

Symptoms before fix:
- `from api.routers import interactive` → ModuleNotFoundError: 'api.exceptions'
- POST /v1/interactive/investigate → 404 in production (route never registered)

This test ensures interactive router stays mounted: the canary investigate
route, called without auth, must return 401 (auth required) — never 404
(route not found).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# F1.7 resolved 2026-05-04 by ADR-0003 Branch A (claude_service thin shim).
# These two tests now actively enforce the contract — no @pytest.mark.skip.


def test_interactive_router_is_importable():
    """The router file's import chain must be clean."""
    from api.routers import interactive

    assert interactive.router is not None
    assert interactive.router.prefix == "/v1/interactive"


def test_interactive_router_is_mounted_in_main(client: TestClient) -> None:
    """A Pro-gated interactive route must reach the auth layer (401), not 404."""
    resp = client.post(
        "/v1/interactive/investigate",
        json={
            "scan_id": "00000000-0000-0000-0000-000000000001",
            "finding_id": "00000000-0000-0000-0000-000000000001",
            "depth": "quick",
        },
    )
    assert resp.status_code != 404, (
        f"interactive router not mounted in main.py — got 404 for /v1/interactive/investigate. "
        f"Expected 401 (no auth) or 422 (validation), but anything except 404. Body: {resp.text!r}"
    )
    assert resp.status_code in (401, 422), (
        f"unexpected status {resp.status_code}: {resp.text!r}"
    )
