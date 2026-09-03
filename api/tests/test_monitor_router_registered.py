"""Sigil API — change-monitor router registration regression.

``api/routers/monitor.py`` defines the /api/monitor/* surface (watch list, the
rescan queue, forced polls). A router that exists but is never passed to
``app.include_router`` is indistinguishable from a router that does not exist:
every one of its paths 404s in production while its unit tests keep passing
against a bare ``FastAPI()`` instance.

These tests pin the two facts that mounting decides:

1. ``/api/monitor/*`` reaches the auth layer (401) rather than routing (404).
2. The background poller stays OFF unless an environment turns it on. It issues
   outbound HTTP requests to third-party URLs registered through the API, so a
   default of False is the contract, not an accident.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_monitor_router_is_importable():
    """The router file's import chain must be clean and the prefix stable."""
    from api.routers import monitor

    assert monitor.router is not None
    assert monitor.router.prefix == "/api/monitor"


def test_monitor_router_is_mounted_in_main(client: TestClient) -> None:
    """A monitor route must reach the auth layer (401), not 404."""
    resp = client.get("/api/monitor/status")
    assert resp.status_code != 404, (
        "monitor router not mounted in main.py — got 404 for /api/monitor/status. "
        f"Expected 401 (no auth) or 422 (validation). Body: {resp.text!r}"
    )
    assert resp.status_code in (401, 422), (
        f"unexpected status {resp.status_code}: {resp.text!r}"
    )


def test_monitor_source_routes_are_mounted(client: TestClient) -> None:
    """The source-management paths are mounted too, not just /status."""
    resp = client.post(
        "/api/monitor/sources",
        json={"url": "https://example.com/listing", "source_type": "other"},
    )
    assert resp.status_code != 404, (
        "POST /api/monitor/sources is not routed — router prefix or mount is wrong. "
        f"Body: {resp.text!r}"
    )
    assert resp.status_code in (401, 422), (
        f"unexpected status {resp.status_code}: {resp.text!r}"
    )


def test_change_monitor_poller_is_off_by_default() -> None:
    """The outbound poller must not switch itself on in an unconfigured env."""
    from api.config import Settings

    assert Settings().change_monitor_enabled is False
