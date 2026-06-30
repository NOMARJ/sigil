"""
Tests for test-mode Stripe webhook verification (NOM-884 US-003).

Covers:
- Live-mode webhook verification (baseline)
- Test-mode webhook verification
- Dual-secret fallback: live fails → test succeeds
- Dual-secret both fail → 400
- Missing both secrets → 503
- All 6 required event types handled in test mode
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

# Stub native-library dependencies not available in CI/test containers.
for _mod in ("pyodbc", "aiohttp", "aiohttp.client"):
    sys.modules.setdefault(_mod, MagicMock())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402

client = TestClient(app)

WEBHOOK_URL = "/v1/billing/webhook"
SIG_HEADER = "t=1700000000,v1=abc123"
PAYLOAD = b'{"id":"evt_test","type":"checkout.session.completed","data":{"object":{}}}'


def _make_settings(
    live_secret: str | None = None,
    test_secret: str | None = None,
    stripe_configured: bool = False,
    stripe_test_configured: bool = False,
) -> MagicMock:
    s = MagicMock()
    s.stripe_webhook_secret = live_secret
    s.stripe_test_webhook_secret = test_secret
    s.stripe_configured = stripe_configured
    s.stripe_test_configured = stripe_test_configured
    return s


def _mock_stripe(event_type: str = "checkout.session.completed") -> MagicMock:
    stripe = MagicMock()
    stripe.Webhook.construct_event.return_value = {
        "id": "evt_test",
        "type": event_type,
        "data": {"object": {}},
        "livemode": False,
    }
    return stripe


# ---------------------------------------------------------------------------
# 503 — no secrets configured
# ---------------------------------------------------------------------------


def test_webhook_503_when_no_secrets_configured():
    settings = _make_settings()

    with (
        patch("api.routers.billing._get_stripe") as mock_get_stripe,
        patch("api.routers.billing.settings", settings),
    ):
        mock_get_stripe.return_value = None
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 503


def test_webhook_503_when_stripe_module_unavailable_and_no_secrets():
    settings = _make_settings(live_secret=None, test_secret=None)

    with (
        patch("api.routers.billing._get_stripe") as mock_get_stripe,
        patch("api.routers.billing.settings", settings),
    ):
        mock_get_stripe.return_value = _mock_stripe()
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Live-mode verification
# ---------------------------------------------------------------------------


def test_webhook_live_mode_success():
    settings = _make_settings(live_secret="whsec_live_ok", stripe_configured=True)
    stripe = _mock_stripe()

    with (
        patch("api.routers.billing._get_stripe", return_value=stripe),
        patch("api.routers.billing.settings", settings),
        patch("api.routers.billing._handle_checkout_completed"),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 200
    assert resp.json()["received"] is True


def test_webhook_live_mode_bad_signature_returns_400():
    class FakeSigError(Exception):
        pass

    settings = _make_settings(live_secret="whsec_live_ok", test_secret=None)
    mock_stripe = MagicMock()
    mock_stripe.error = MagicMock()
    mock_stripe.error.SignatureVerificationError = FakeSigError
    mock_stripe.Webhook.construct_event.side_effect = FakeSigError("bad sig")

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing.settings", settings),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Test-mode verification
# ---------------------------------------------------------------------------


def test_webhook_test_mode_success_no_live_secret():
    """Only test secret configured — should verify and return 200."""
    settings = _make_settings(
        live_secret=None,
        test_secret="whsec_test_ok",
        stripe_test_configured=True,
    )
    stripe = _mock_stripe()

    with (
        patch("api.routers.billing._get_stripe", return_value=stripe),
        patch("api.routers.billing.settings", settings),
        patch("api.routers.billing._handle_checkout_completed"),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 200
    assert resp.json()["received"] is True


def test_webhook_test_mode_bad_signature_returns_400():
    """Test secret configured but signature wrong — should return 400."""
    import stripe as real_stripe  # noqa: F401 (only needed for exception class)

    settings = _make_settings(live_secret=None, test_secret="whsec_test_ok")
    mock_stripe = MagicMock()
    mock_stripe.error = MagicMock()

    class FakeSigError(Exception):
        pass

    mock_stripe.error.SignatureVerificationError = FakeSigError
    mock_stripe.Webhook.construct_event.side_effect = FakeSigError("bad sig")

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing.settings", settings),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Dual-secret fallback: live fails → test succeeds
# ---------------------------------------------------------------------------


def test_webhook_dual_secret_live_fails_test_succeeds():
    """Live sig check raises SignatureVerificationError; test secret succeeds."""
    settings = _make_settings(
        live_secret="whsec_live_wrong",
        test_secret="whsec_test_ok",
        stripe_configured=True,
        stripe_test_configured=True,
    )

    call_count = 0

    def construct_side_effect(body, sig, secret):
        nonlocal call_count
        call_count += 1
        if secret == "whsec_live_wrong":
            raise FakeSigError("live sig bad")
        return {
            "id": "evt_test",
            "type": "checkout.session.completed",
            "data": {"object": {}},
            "livemode": False,
        }

    class FakeSigError(Exception):
        pass

    mock_stripe = MagicMock()
    mock_stripe.error = MagicMock()
    mock_stripe.error.SignatureVerificationError = FakeSigError
    mock_stripe.Webhook.construct_event.side_effect = construct_side_effect

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing.settings", settings),
        patch("api.routers.billing._handle_checkout_completed"),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 200
    assert call_count == 2  # tried both secrets


def test_webhook_dual_secret_both_fail_returns_400():
    """Both live and test secrets raise SignatureVerificationError → 400."""

    class FakeSigError(Exception):
        pass

    settings = _make_settings(
        live_secret="whsec_live_wrong",
        test_secret="whsec_test_wrong",
        stripe_configured=True,
        stripe_test_configured=True,
    )
    mock_stripe = MagicMock()
    mock_stripe.error = MagicMock()
    mock_stripe.error.SignatureVerificationError = FakeSigError
    mock_stripe.Webhook.construct_event.side_effect = FakeSigError("bad sig")

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing.settings", settings),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=PAYLOAD,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# All 6 required event types in test mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_type,handler_path",
    [
        ("checkout.session.completed", "api.routers.billing._handle_checkout_completed"),
        ("customer.subscription.created", "api.routers.billing._handle_subscription_created"),
        ("customer.subscription.updated", "api.routers.billing._handle_subscription_updated"),
        ("customer.subscription.deleted", "api.routers.billing._handle_subscription_deleted"),
        ("invoice.payment_failed", "api.routers.billing._handle_payment_failed"),
        ("invoice.payment_succeeded", "api.routers.billing._handle_payment_succeeded"),
    ],
)
def test_webhook_test_mode_all_required_events(event_type: str, handler_path: str):
    """Each of the 6 required Stripe events is handled when arriving via test mode."""
    settings = _make_settings(live_secret=None, test_secret="whsec_test_ok")
    payload = (
        f'{{"id":"evt_test","type":"{event_type}","data":{{"object":{{}}}}}}'
    ).encode()
    stripe = _mock_stripe(event_type=event_type)

    with (
        patch("api.routers.billing._get_stripe", return_value=stripe),
        patch("api.routers.billing.settings", settings),
        patch(handler_path) as mock_handler,
    ):
        mock_handler.return_value = None
        resp = client.post(
            WEBHOOK_URL,
            content=payload,
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 200
    mock_handler.assert_called_once()


# ---------------------------------------------------------------------------
# Invalid payload (ValueError path)
# ---------------------------------------------------------------------------


def test_webhook_invalid_payload_format_returns_400():
    """ValueError from construct_event (malformed body) returns 400."""

    class FakeSigError(Exception):
        pass

    settings = _make_settings(live_secret="whsec_live_ok")
    mock_stripe = MagicMock()
    mock_stripe.error = MagicMock()
    mock_stripe.error.SignatureVerificationError = FakeSigError
    mock_stripe.Webhook.construct_event.side_effect = ValueError("bad json")

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing.settings", settings),
    ):
        resp = client.post(
            WEBHOOK_URL,
            content=b"not json",
            headers={"stripe-signature": SIG_HEADER, "content-type": "application/json"},
        )

    assert resp.status_code == 400
