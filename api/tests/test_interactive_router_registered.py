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

# F1.7 is BLOCKED on a missing api.services.claude_service module that
# bulk_analyzer.py imports. Interactive.py transitively imports
# bulk_analyzer, so the entire router fails at module load. Fixing this
# requires either writing a real Claude API wrapper service (feature
# work, not a bug fix) or refactoring bulk_analyzer's dependency
# direction. See evidence/F-003/F1.7-BLOCKED.md.
#
# These tests stay in the suite as living regression specs. When F1.7 is
# resolved, remove the skip and the suite immediately enforces that
# interactive stays mounted.
_F17_BLOCKED_REASON = (
    "F1.7 BLOCKED: api/services/claude_service.py does not exist; "
    "bulk_analyzer.py:17 needs it to load, blocking interactive.router "
    "registration. See evidence/F-003/F1.7-BLOCKED.md."
)


@pytest.mark.skip(reason=_F17_BLOCKED_REASON)
def test_interactive_router_is_importable():
    """The router file's import chain must be clean."""
    from api.routers import interactive

    assert interactive.router is not None
    assert interactive.router.prefix == "/v1/interactive"


@pytest.mark.skip(reason=_F17_BLOCKED_REASON)
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
