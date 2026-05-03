"""Sigil API — 14-day trial regression (STORY-107 Branch B).

Owner decision 2026-05-04: Pro/Team Stripe Checkout Sessions for first-time
Stripe customers attach `subscription_data={"trial_period_days": 14}`.
Returning customers (existing `stripe_customer_id`) get no trial — preventing
trial recycling via cancel/resubscribe.

Trial is set on the Checkout Session, not the Stripe Price object, so the
length is changeable in code without re-creating Prices.

These tests assert the trial-gate logic in the body of the subscribe
endpoint without spinning up the FastAPI app or hitting MSSQL — the
existing integration suite already covers end-to-end happy paths but is
gated by `SIGIL_RUN_EXTENDED_TESTS=1` and needs MSSQL. These run anywhere.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.models import SubscribeRequest
from api.routers import billing


def test_trial_period_constant_is_14():
    """Source of truth: changing the trial length is a one-line edit."""
    assert billing._TRIAL_PERIOD_DAYS == 14


def _user(uid: str, email: str) -> MagicMock:
    user = MagicMock()
    user.id = uid
    user.email = email
    return user


def _settings_patch():
    return patch.multiple(
        "api.routers.billing.settings",
        stripe_price_pro="price_pro_monthly_test",
        stripe_price_pro_annual="price_pro_annual_test",
        stripe_price_team="price_team_monthly_test",
        stripe_price_team_annual="price_team_annual_test",
        frontend_url="https://app.sigilsec.ai",
    )


@pytest.mark.asyncio
async def test_new_customer_gets_14_day_trial():
    """First-time Stripe customer: subscription_data carries 14-day trial."""
    mock_stripe = MagicMock()
    new_customer = MagicMock()
    new_customer.id = "cus_new_test"
    mock_stripe.Customer.create.return_value = new_customer

    session_mock = MagicMock()
    session_mock.url = "https://checkout.stripe.com/session_trial"
    mock_stripe.checkout.Session.create.return_value = session_mock

    mock_db = MagicMock()
    mock_db.upsert_subscription = AsyncMock(return_value={"plan": "pro"})

    fresh_sub = {
        "plan": "free",
        "status": "active",
        "stripe_customer_id": None,
        "stripe_subscription_id": None,
    }

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing._get_or_create_subscription", AsyncMock(return_value=fresh_sub)),
        patch("api.routers.billing.db", mock_db),
        _settings_patch(),
    ):
        body = SubscribeRequest(plan=billing.PlanTier.PRO, interval="monthly", payment_method_id=None)
        await billing.subscribe(body=body, current_user=_user("user_new_1", "new@example.com"))

    mock_stripe.Customer.create.assert_called_once()
    kwargs = mock_stripe.checkout.Session.create.call_args.kwargs
    assert kwargs.get("subscription_data") == {"trial_period_days": 14}, kwargs


@pytest.mark.asyncio
async def test_existing_customer_no_trial():
    """Returning Stripe customer: no subscription_data → no trial recycle."""
    mock_stripe = MagicMock()
    session_mock = MagicMock()
    session_mock.url = "https://checkout.stripe.com/session_returning"
    mock_stripe.checkout.Session.create.return_value = session_mock

    mock_db = MagicMock()
    mock_db.upsert_subscription = AsyncMock(return_value={"plan": "pro"})

    returning_sub = {
        "plan": "free",
        "status": "active",
        "stripe_customer_id": "cus_returning",
        "stripe_subscription_id": None,
        "billing_interval": "monthly",
    }

    with (
        patch("api.routers.billing._get_stripe", return_value=mock_stripe),
        patch("api.routers.billing._get_or_create_subscription", AsyncMock(return_value=returning_sub)),
        patch("api.routers.billing.db", mock_db),
        _settings_patch(),
    ):
        body = SubscribeRequest(plan=billing.PlanTier.PRO, interval="monthly", payment_method_id=None)
        await billing.subscribe(body=body, current_user=_user("user_returning_1", "back@example.com"))

    mock_stripe.Customer.create.assert_not_called()
    kwargs = mock_stripe.checkout.Session.create.call_args.kwargs
    assert "subscription_data" not in kwargs, (
        f"returning customer must NOT receive a recycled trial; got {kwargs!r}"
    )
