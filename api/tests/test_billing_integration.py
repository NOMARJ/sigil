"""
Billing Integration Tests

Comprehensive tests for Stripe billing integration, subscription lifecycle management,
and payment webhook handling for Pro tier subscriptions.

Test Coverage:
- Stripe Checkout Session creation and handling
- Subscription lifecycle events (create, update, cancel)
- Webhook signature verification and processing
- Payment failure and retry scenarios
- Subscription edge cases and error handling
- Billing analytics and usage tracking
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from api.services.subscription_service import subscription_service
from api.database import db


class TestStripeCheckoutFlow:
    """Test Stripe Checkout Session creation and completion"""

    def test_create_checkout_session_pro_monthly(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test creating Stripe checkout session for Pro monthly plan"""

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock Stripe customer creation
            mock_customer = MagicMock()
            mock_customer.id = "cus_test_123"
            mock_stripe.Customer.create.return_value = mock_customer

            # Mock checkout session creation
            mock_session = MagicMock()
            mock_session.url = "https://checkout.stripe.com/session_123"
            mock_stripe.checkout.Session.create.return_value = mock_session

            # Mock settings for price IDs
            with patch("api.routers.billing.settings") as mock_settings:
                mock_settings.stripe_price_pro = "price_pro_monthly_123"
                mock_settings.frontend_url = "https://app.sigilsec.ai"

                response = client.post(
                    "/v1/billing/subscribe",
                    json={"plan": "pro", "interval": "monthly"},
                    headers=auth_headers,
                )

                assert response.status_code == 200
                data = response.json()
                assert data["checkout_url"] == "https://checkout.stripe.com/session_123"

                # Verify Stripe API calls
                mock_stripe.Customer.create.assert_called_once()
                mock_stripe.checkout.Session.create.assert_called_once()

                # Verify checkout session parameters
                session_args = mock_stripe.checkout.Session.create.call_args[1]
                assert session_args["customer"] == "cus_test_123"
                assert session_args["mode"] == "subscription"
                assert session_args["line_items"][0]["price"] == "price_pro_monthly_123"

    def test_create_checkout_session_existing_customer(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test checkout creation for user with existing Stripe customer"""

        # Setup user with existing subscription record
        import asyncio

        async def setup_existing_customer():
            user_id = "test_user_123"
            await db.upsert_subscription(
                user_id=user_id,
                plan="free",
                status="active",
                stripe_customer_id="cus_existing_123",
                billing_interval="monthly",
            )

        asyncio.run(setup_existing_customer())

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Should not create new customer
            mock_session = MagicMock()
            mock_session.url = "https://checkout.stripe.com/session_456"
            mock_stripe.checkout.Session.create.return_value = mock_session

            response = client.post(
                "/v1/billing/subscribe",
                json={"plan": "pro", "interval": "monthly"},
                headers=auth_headers,
            )

            assert response.status_code == 200
            # Should not have called Customer.create since customer exists
            mock_stripe.Customer.create.assert_not_called()

    def test_checkout_session_creation_failure(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test handling of Stripe checkout session creation failures"""

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock Stripe error
            mock_stripe.checkout.Session.create.side_effect = Exception(
                "Stripe API error"
            )

            response = client.post(
                "/v1/billing/subscribe",
                json={"plan": "pro", "interval": "monthly"},
                headers=auth_headers,
            )

            assert response.status_code == 502  # Bad Gateway
            error_data = response.json()
            assert "Payment provider error" in error_data["detail"]


class TestWebhookProcessing:
    """Test Stripe webhook event processing"""

    @pytest.fixture
    def webhook_headers(self):
        """Stripe webhook signature headers"""
        return {
            "stripe-signature": "t=1677123456,v1=test_signature_123",
            "content-type": "application/json",
        }

    @pytest.mark.asyncio
    async def test_checkout_completed_webhook(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test processing of checkout.session.completed webhook"""

        # Create test user first
        user_resp = client.post(
            "/v1/auth/register",
            json={
                "email": "webhook-user@example.com",
                "password": "Password123!",
                "name": "Webhook User",
            },
        )
        user_data = user_resp.json()
        user_id = user_data["user"]["id"]

        webhook_payload = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": "cus_webhook_test",
                    "subscription": "sub_webhook_test",
                    "metadata": {
                        "sigil_user_id": user_id,
                        "sigil_plan": "pro",
                        "sigil_interval": "monthly",
                    },
                }
            },
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock successful signature verification
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            # Mock subscription retrieval
            mock_subscription = MagicMock()
            mock_subscription.status = "active"
            mock_subscription.current_period_end = int(
                (datetime.utcnow() + timedelta(days=30)).timestamp()
            )
            mock_stripe.Subscription.retrieve.return_value = mock_subscription

            response = client.post(
                "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
            )

            assert response.status_code == 200
            result = response.json()
            assert result["received"] is True
            assert result["event_type"] == "checkout.session.completed"

            # Verify subscription was created
            subscription = await subscription_service.get_user_subscription(user_id)
            assert subscription["plan"] == "pro"
            assert subscription["status"] == "active"
            assert subscription["stripe_customer_id"] == "cus_webhook_test"
            assert subscription["stripe_subscription_id"] == "sub_webhook_test"

    @pytest.mark.asyncio
    async def test_subscription_updated_webhook(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test processing of customer.subscription.updated webhook"""

        # Setup existing subscription
        user_id = "sub_update_user"
        await db.upsert_subscription(
            user_id=user_id,
            plan="pro",
            status="active",
            stripe_customer_id="cus_update_test",
            stripe_subscription_id="sub_update_test",
        )

        webhook_payload = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "customer": "cus_update_test",
                    "status": "past_due",
                    "current_period_end": int(
                        (datetime.utcnow() + timedelta(days=5)).timestamp()
                    ),
                }
            },
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            response = client.post(
                "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
            )

            assert response.status_code == 200

            # Verify subscription status updated
            subscription = await subscription_service.get_user_subscription(user_id)
            assert subscription["status"] == "past_due"

    @pytest.mark.asyncio
    async def test_subscription_deleted_webhook(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test processing of customer.subscription.deleted webhook"""

        # Setup existing Pro subscription
        user_id = "sub_delete_user"
        await db.upsert_subscription(
            user_id=user_id,
            plan="pro",
            status="active",
            stripe_customer_id="cus_delete_test",
            stripe_subscription_id="sub_delete_test",
        )

        webhook_payload = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_delete_test"}},
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            response = client.post(
                "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
            )

            assert response.status_code == 200

            # Verify downgrade to free tier
            subscription = await subscription_service.get_user_subscription(user_id)
            assert subscription["plan"] == "free"
            assert subscription["status"] == "canceled"

    def test_webhook_signature_verification_failure(self, client: TestClient):
        """Test webhook rejection when signature verification fails"""

        webhook_payload = {"type": "checkout.session.completed", "data": {"object": {}}}

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock signature verification failure
            mock_stripe.Webhook.construct_event.side_effect = Exception(
                "Invalid signature"
            )

            # Mock webhook secret configured
            with patch("api.routers.billing.settings") as mock_settings:
                mock_settings.stripe_webhook_secret = "whsec_test_secret"

                response = client.post(
                    "/v1/billing/webhook",
                    json=webhook_payload,
                    headers={"stripe-signature": "invalid_signature"},
                )

                assert response.status_code == 400
                assert "Signature verification failed" in response.json()["detail"]

    def test_webhook_unknown_event_type(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test handling of unknown webhook event types"""

        webhook_payload = {
            "type": "invoice.finalized",  # Event we don't handle
            "data": {"object": {"customer": "cus_test"}},
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            response = client.post(
                "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
            )

            assert response.status_code == 200
            result = response.json()
            assert result["received"] is True
            assert result["event_type"] == "invoice.finalized"


class TestPaymentFailureHandling:
    """Test payment failure scenarios and recovery"""

    def test_payment_failed_webhook_logging(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test logging of payment failures"""

        webhook_payload = {
            "type": "invoice.payment_failed",
            "data": {
                "object": {
                    "customer": "cus_payment_failed",
                    "amount_due": 2900,  # $29.00 in cents
                    "attempt_count": 2,
                }
            },
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            with patch("api.routers.billing.logger") as mock_logger:
                response = client.post(
                    "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
                )

                assert response.status_code == 200

                # Verify payment failure was logged
                mock_logger.warning.assert_called()
                log_call = mock_logger.warning.call_args[0][0]
                assert "Payment failed" in log_call
                assert "cus_payment_failed" in log_call

    def test_payment_succeeded_webhook_logging(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test logging of successful payments"""

        webhook_payload = {
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "customer": "cus_payment_success",
                    "amount_paid": 2900,  # $29.00 in cents
                }
            },
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            with patch("api.routers.billing.logger") as mock_logger:
                response = client.post(
                    "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
                )

                assert response.status_code == 200

                # Verify payment success was logged
                mock_logger.info.assert_called()
                log_call = mock_logger.info.call_args[0][0]
                assert "Payment succeeded" in log_call
                assert "cus_payment_success" in log_call


class TestSubscriptionManagement:
    """Test subscription management operations"""

    def test_get_subscription_sync_from_stripe(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test subscription sync from Stripe when fetching current subscription"""

        # Setup user with Stripe subscription
        import asyncio

        async def setup_user():
            user_id = "stripe_sync_user"
            await db.upsert_subscription(
                user_id=user_id,
                plan="pro",
                status="active",
                stripe_customer_id="cus_sync_test",
                stripe_subscription_id="sub_sync_test",
            )
            return user_id

        asyncio.run(setup_user())

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock Stripe subscription data
            mock_subscription = MagicMock()
            mock_subscription.status = "active"
            mock_subscription.current_period_end = int(
                (datetime.utcnow() + timedelta(days=25)).timestamp()
            )
            mock_subscription.current_period_start = int(
                (datetime.utcnow() - timedelta(days=5)).timestamp()
            )
            mock_subscription.cancel_at_period_end = False
            mock_stripe.Subscription.retrieve.return_value = mock_subscription

            response = client.get("/v1/billing/subscription", headers=auth_headers)

            assert response.status_code == 200
            data = response.json()
            assert data["plan"] == "pro"
            assert data["status"] == "active"
            assert data["cancel_at_period_end"] is False

            # Verify Stripe API was called
            mock_stripe.Subscription.retrieve.assert_called_once_with("sub_sync_test")

    def test_customer_portal_creation(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test Stripe Customer Portal session creation"""

        # Setup user with Stripe customer
        import asyncio

        async def setup_user():
            user_id = "portal_user"
            await db.upsert_subscription(
                user_id=user_id,
                plan="pro",
                status="active",
                stripe_customer_id="cus_portal_test",
            )

        asyncio.run(setup_user())

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock portal session creation
            mock_session = MagicMock()
            mock_session.url = "https://billing.stripe.com/p/session_123"
            mock_stripe.billing_portal.Session.create.return_value = mock_session

            response = client.post("/v1/billing/portal", headers=auth_headers)

            assert response.status_code == 200
            data = response.json()
            assert data["url"] == "https://billing.stripe.com/p/session_123"

            # Verify portal session creation
            mock_stripe.billing_portal.Session.create.assert_called_once()

    def test_customer_portal_no_customer(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test portal creation failure when user has no Stripe customer"""

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            response = client.post("/v1/billing/portal", headers=auth_headers)

            assert response.status_code == 400
            error_data = response.json()
            assert "No billing account found" in error_data["detail"]


class TestBillingEdgeCases:
    """Test edge cases and error scenarios in billing"""

    def test_duplicate_subscription_prevention(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test that users cannot create duplicate active subscriptions"""

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe

            # Mock existing subscription check
            with patch(
                "api.routers.billing._get_or_create_subscription"
            ) as mock_get_sub:
                mock_get_sub.return_value = {
                    "plan": "pro",
                    "status": "active",
                    "stripe_subscription_id": "sub_existing_123",
                    "billing_interval": "monthly",
                }

                response = client.post(
                    "/v1/billing/subscribe",
                    json={"plan": "pro", "interval": "monthly"},
                    headers=pro_auth_headers,
                )

                assert response.status_code == 200
                data = response.json()
                assert data["plan"] == "pro"
                assert data["stripe_subscription_id"] == "sub_existing_123"

                # Should not have created new checkout session
                mock_stripe.checkout.Session.create.assert_not_called()

    def test_enterprise_plan_rejection(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that Enterprise plan subscription is rejected with contact sales message"""

        response = client.post(
            "/v1/billing/subscribe",
            json={"plan": "enterprise", "interval": "monthly"},
            headers=auth_headers,
        )

        assert response.status_code == 400
        error_data = response.json()
        assert "Enterprise plans require a custom contract" in error_data["detail"]
        assert "sales@sigil.dev" in error_data["detail"]

    @pytest.mark.asyncio
    async def test_webhook_orphaned_customer(
        self, client: TestClient, webhook_headers: dict[str, str]
    ):
        """Test webhook handling for unknown/orphaned Stripe customers"""

        webhook_payload = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {"customer": "cus_unknown_customer", "status": "active"}
            },
        }

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_stripe = MagicMock()
            mock_get_stripe.return_value = mock_stripe
            mock_stripe.Webhook.construct_event.return_value = webhook_payload

            with patch("api.routers.billing.logger") as mock_logger:
                response = client.post(
                    "/v1/billing/webhook", json=webhook_payload, headers=webhook_headers
                )

                assert response.status_code == 200

                # Should log warning about unknown customer
                mock_logger.warning.assert_called()
                log_call = mock_logger.warning.call_args[0][0]
                assert "unknown customer" in log_call
                assert "cus_unknown_customer" in log_call

    def test_stripe_not_configured_fallback(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test billing endpoints when Stripe is not configured"""

        with patch("api.routers.billing._get_stripe") as mock_get_stripe:
            mock_get_stripe.return_value = None  # Stripe not configured

            # Subscription should work in stub mode
            response = client.post(
                "/v1/billing/subscribe",
                json={"plan": "pro", "interval": "monthly"},
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["plan"] == "pro"
            assert data["status"] == "active"

            # Portal should return stub URL
            portal_resp = client.post("/v1/billing/portal", headers=auth_headers)
            assert portal_resp.status_code == 200
            portal_data = portal_resp.json()
            assert "stub=true" in portal_data["url"]

    def test_plans_endpoint(self, client: TestClient):
        """Test plans listing endpoint"""

        response = client.get("/v1/billing/plans")
        assert response.status_code == 200

        plans = response.json()
        assert len(plans) == 4  # FREE, PRO, TEAM, ENTERPRISE

        # Verify Pro plan details
        pro_plan = next(plan for plan in plans if plan["tier"] == "pro")
        assert pro_plan["name"] == "Pro"
        assert pro_plan["price_monthly"] == 29.0
        assert "AI-powered threat detection" in pro_plan["features"]

        # Verify Enterprise shows custom pricing
        enterprise_plan = next(plan for plan in plans if plan["tier"] == "enterprise")
        assert enterprise_plan["price_monthly"] == 0.0  # Custom pricing
