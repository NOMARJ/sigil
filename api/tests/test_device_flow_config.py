"""Device-flow precondition guard (fix for #124 — opaque 503 on missing client_id)."""

from __future__ import annotations

from api.config import Settings


def _settings(**over) -> Settings:
    base = dict(auth0_domain="auth.sigilsec.ai", auth0_audience="https://api.sigilsec.ai")
    base.update(over)
    return Settings(**base)


def test_device_flow_needs_client_id():
    s = _settings(auth0_client_id=None)
    assert s.auth0_configured is True  # JWT validation still fine
    assert s.auth0_device_flow_configured is False  # but device flow is not


def test_device_flow_configured_when_client_id_present():
    s = _settings(auth0_client_id="abc123")
    assert s.auth0_device_flow_configured is True


def test_device_flow_needs_domain_and_audience():
    assert _settings(auth0_domain=None, auth0_client_id="x").auth0_device_flow_configured is False
    assert _settings(auth0_audience=None, auth0_client_id="x").auth0_device_flow_configured is False
