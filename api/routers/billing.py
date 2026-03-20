"""
Sigil API — Billing Router (Stripe Integration Stubs)

Provides billing endpoints that integrate with Stripe for subscription
management.  When Stripe is not configured, the endpoints return sensible
stub responses so the rest of the platform works without a payment provider.

Endpoints:
    GET  /v1/billing/plans        — List available plans
    POST /v1/billing/subscribe    — Create a subscription
    GET  /v1/billing/subscription — Get current subscription
    POST /v1/billing/portal       — Create Stripe customer portal session
    POST /v1/billing/webhook      — Stripe webhook handler
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta
from typing import Any
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.config import settings
from api.database import db
from api.rate_limit import RateLimiter
from api.models import (
    ErrorResponse,
    GateError,
    PlanInfo,
    PlanTier,
    PortalResponse,
    SubscribeRequest,
    SubscriptionResponse,
    WebhookResponse,
)
from pydantic import BaseModel, Field
from api.gates import require_plan
from api.routers.auth import get_current_user_unified, UserResponse

sys.modules.setdefault("api.routers.billing", sys.modules[__name__])

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])

AUDIT_TABLE = "audit_log"

# ---------------------------------------------------------------------------
# Credit package models
# ---------------------------------------------------------------------------


class CreditPackage(BaseModel):
    """Credit package information."""

    package_id: int = Field(..., description="Package ID")
    name: str = Field(..., description="Package name")
    credits: int = Field(..., description="Number of credits")
    price_usd: float = Field(..., description="Price in USD")
    bonus_credits: int = Field(default=0, description="Bonus credits")
    stripe_price_id: str | None = Field(default=None, description="Stripe price ID")


class PurchaseCreditsRequest(BaseModel):
    """Request to purchase credits."""

    package_id: int = Field(..., description="Credit package ID to purchase")


class PurchaseCreditsResponse(BaseModel):
    """Response for credit purchase."""

    success: bool = Field(..., description="Whether purchase was successful")
    checkout_url: str | None = Field(default=None, description="Stripe checkout URL")
    credits_purchased: int | None = Field(default=None, description="Credits purchased")
    new_balance: int | None = Field(default=None, description="New credit balance")


# Credit packages available for purchase
CREDIT_PACKAGES: list[CreditPackage] = [
    CreditPackage(
        package_id=1,
        name="Starter Pack",
        credits=1000,
        price_usd=9.99,
        bonus_credits=100,
        stripe_price_id="price_1QQQPzE7LGYj7YY7CrCrCr",  # Would be real Stripe price ID
    ),
    CreditPackage(
        package_id=2,
        name="Power Pack",
        credits=3000,
        price_usd=24.99,
        bonus_credits=500,
        stripe_price_id="price_1QQQQzE7LGYj7YY7DsDsDs",
    ),
    CreditPackage(
        package_id=3,
        name="Pro Pack",
        credits=5000,
        price_usd=39.99,
        bonus_credits=1000,
        stripe_price_id="price_1QQQRzE7LGYj7YY7EtEtEt",
    ),
    CreditPackage(
        package_id=4,
        name="Ultimate Pack",
        credits=10000,
        price_usd=69.99,
        bonus_credits=2500,
        stripe_price_id="price_1QQQSzE7LGYj7YY7FuFuFu",
    ),
]

# ---------------------------------------------------------------------------
# Plan catalogue
# ---------------------------------------------------------------------------

PLANS: list[PlanInfo] = [
    PlanInfo(
        tier=PlanTier.FREE,
        name="Free",
        price_monthly=0.0,
        price_yearly=0.0,
        scans_per_month=50,
        features=[
            "50 scans/month",
            "Community threat intelligence",
            "Basic scan reports",
            "Single user",
        ],
    ),
    PlanInfo(
        tier=PlanTier.PRO,
        name="Pro",
        price_monthly=29.0,
        price_yearly=232.0,  # $232/yr — save $116 (2 months free)
        scans_per_month=500,
        features=[
            "500 scans/month",
            "5,000 monthly AI credits",
            "🔍 AI Finding Investigation",
            "🤖 False Positive Verification",
            "💬 Interactive Security Chat",
            "🎯 Smart Model Routing",
            "📊 Credit Usage Analytics",
            "Full threat intelligence",
            "Advanced scan reports",
            "Priority support",
            "API access",
            "Custom policies",
        ],
    ),
    PlanInfo(
        tier=PlanTier.TEAM,
        name="Team",
        price_monthly=99.0,
        price_yearly=792.0,  # $792/yr — save $396 (2 months free)
        scans_per_month=5000,
        features=[
            "5,000 scans/month",
            "50,000 monthly AI credits",
            "🔍 AI Finding Investigation",
            "🤖 False Positive Verification",
            "💬 Interactive Security Chat",
            "🎯 Smart Model Routing",
            "📊 Credit Usage Analytics",
            "Full threat intelligence",
            "Team dashboard",
            "RBAC & audit log",
            "Slack/webhook alerts",
            "Custom policies",
            "Priority support",
            "SSO (SAML)",
        ],
    ),
    PlanInfo(
        tier=PlanTier.ENTERPRISE,
        name="Enterprise",
        price_monthly=0.0,  # Custom pricing
        price_yearly=0.0,
        scans_per_month=0,  # Unlimited
        features=[
            "Unlimited scans",
            "AI-powered threat detection",
            "🤖 AI-powered threat detection (LLM analysis)",
            "🔍 Zero-day vulnerability detection",
            "🎭 Advanced obfuscation analysis",
            "🔗 Contextual threat correlation",
            "💡 AI-generated remediation suggestions",
            "Full threat intelligence",
            "Dedicated account manager",
            "Custom integrations",
            "SLA guarantee",
            "On-premise deployment option",
            "Advanced audit & compliance",
            "SSO (SAML/OIDC)",
            "Custom contract",
        ],
    ),
]


def _get_price_id(plan: PlanTier, interval: str) -> str | None:
    if plan in (PlanTier.FREE, PlanTier.ENTERPRISE):
        return None
    if plan == PlanTier.PRO:
        return (
            settings.stripe_price_pro
            if interval == "monthly"
            else settings.stripe_price_pro_annual
        )
    if plan == PlanTier.TEAM:
        return (
            settings.stripe_price_team
            if interval == "monthly"
            else settings.stripe_price_team_annual
        )
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_stripe():
    """Import and configure the Stripe module, or return None."""
    if not settings.stripe_configured:
        return None
    try:
        import stripe

        stripe.api_key = settings.stripe_secret_key
        return stripe
    except ImportError:
        logger.warning(
            "stripe package not installed — billing endpoints will use stubs"
        )
        return None


async def _get_or_create_subscription(user_id: str) -> dict[str, Any]:
    """Get the DB subscription for a user, creating a free-plan default if absent."""
    sub_data = await db.get_subscription(user_id)
    if sub_data is None:
        now = datetime.utcnow()
        sub_data = await db.upsert_subscription(
            user_id=user_id,
            plan=PlanTier.FREE.value,
            status="active",
            stripe_customer_id=None,
            stripe_subscription_id=None,
            current_period_end=(now + timedelta(days=30)).isoformat(),
        )
        sub_data.setdefault("current_period_start", now.isoformat())
    return sub_data


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/plans",
    response_model=list[PlanInfo],
    summary="List available plans",
)
async def list_plans() -> list[PlanInfo]:
    """Return the catalogue of available billing plans.

    The Enterprise plan shows $0 because pricing is custom (contact sales).
    """
    return PLANS


@router.post(
    "/subscribe",
    response_model=SubscriptionResponse,
    summary="Create or update a subscription",
    responses={401: {"model": ErrorResponse}},
    dependencies=[Depends(RateLimiter(max_requests=5, window=60))],
)
async def subscribe(
    body: SubscribeRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> SubscriptionResponse:
    """Subscribe to a plan or change the current subscription.

    When Stripe is configured, this creates a Stripe Checkout Session or
    updates the existing subscription.  Without Stripe, a stub subscription
    is recorded in the database.
    """
    stripe = _get_stripe()
    now = datetime.utcnow()

    if body.plan == PlanTier.ENTERPRISE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enterprise plans require a custom contract. Contact sales@sigil.dev.",
        )

    # Fetch (or create) the existing subscription record from DB
    sub_data = await _get_or_create_subscription(current_user.id)

    interval = body.interval  # "monthly" or "annual"
    if stripe is not None:
        # --- Stripe integration path ---
        price_id = _get_price_id(body.plan, interval)

        # Reject if the price ID is missing for paid plans
        if body.plan != PlanTier.FREE and not price_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"The {interval} billing interval is not available for the {body.plan.value} plan. Please contact support.",
            )

        if body.plan == PlanTier.FREE:
            # Downgrade to free — cancel existing Stripe subscription
            stripe_sub_id = sub_data.get("stripe_subscription_id")
            if stripe_sub_id:
                try:
                    stripe.Subscription.modify(
                        stripe_sub_id,
                        cancel_at_period_end=True,
                    )
                except Exception:
                    logger.exception(
                        "Failed to cancel Stripe subscription %s", stripe_sub_id
                    )

            sub_data = await db.upsert_subscription(
                user_id=current_user.id,
                plan=PlanTier.FREE.value,
                status=sub_data.get("status", "active"),
                stripe_customer_id=sub_data.get("stripe_customer_id"),
                stripe_subscription_id=sub_data.get("stripe_subscription_id"),
                current_period_end=sub_data.get("current_period_end"),
                billing_interval="monthly",
            )
            sub_data["cancel_at_period_end"] = True
        else:
            # If the user already has an active subscription for this plan,
            # don't create another checkout session.
            existing_sub_id = sub_data.get("stripe_subscription_id")
            if (
                existing_sub_id
                and sub_data.get("plan") == body.plan.value
                and sub_data.get("status") in ("active", "trialing")
            ):
                return SubscriptionResponse(
                    plan=PlanTier(sub_data["plan"]),
                    status=sub_data.get("status", "active"),
                    billing_interval=sub_data.get("billing_interval", "monthly"),
                    current_period_start=sub_data.get("current_period_start"),
                    current_period_end=sub_data.get("current_period_end"),
                    cancel_at_period_end=sub_data.get("cancel_at_period_end", False),
                    stripe_subscription_id=existing_sub_id,
                )

            # Create a Stripe Checkout Session for paid plans.
            # This redirects the user to Stripe's hosted payment page,
            # which collects payment details and creates the subscription
            # only after successful payment — no more "overdue" invoices.
            try:
                customer_id = sub_data.get("stripe_customer_id")
                if not customer_id:
                    customer = stripe.Customer.create(
                        email=current_user.email,
                        metadata={"sigil_user_id": current_user.id},
                    )
                    customer_id = customer.id

                # Persist the Stripe customer ID right away so portal works
                await db.upsert_subscription(
                    user_id=current_user.id,
                    plan=sub_data.get("plan", PlanTier.FREE.value),
                    status=sub_data.get("status", "active"),
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=sub_data.get("stripe_subscription_id"),
                    current_period_end=sub_data.get("current_period_end"),
                    billing_interval=interval,
                )

                # Build success/cancel URLs for Checkout
                frontend_url = settings.frontend_url.rstrip("/")
                success_url = f"{frontend_url}/settings?checkout=success"
                cancel_url = f"{frontend_url}/settings?checkout=cancel"

                checkout_session = stripe.checkout.Session.create(
                    customer=customer_id,
                    mode="subscription",
                    line_items=[{"price": price_id, "quantity": 1}],
                    success_url=success_url,
                    cancel_url=cancel_url,
                    metadata={
                        "sigil_user_id": current_user.id,
                        "sigil_plan": body.plan.value,
                        "sigil_interval": interval,
                    },
                )

                # Return a response with the checkout URL for the frontend
                # to redirect to. The subscription isn't created yet — Stripe
                # will create it after the user completes payment, and our
                # webhook handler will update the DB.
                return SubscriptionResponse(
                    plan=PlanTier(sub_data.get("plan", PlanTier.FREE.value)),
                    status=sub_data.get("status", "active"),
                    billing_interval=interval,
                    current_period_start=sub_data.get("current_period_start"),
                    current_period_end=sub_data.get("current_period_end"),
                    cancel_at_period_end=False,
                    stripe_subscription_id=sub_data.get("stripe_subscription_id"),
                    checkout_url=checkout_session.url,
                )

            except Exception as exc:
                logger.exception("Stripe Checkout Session creation failed")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Payment provider error: {exc}",
                )
    else:
        # --- Stub path (no Stripe) ---
        days = 365 if interval == "annual" else 30
        period_end = (now + timedelta(days=days)).isoformat()
        sub_data = await db.upsert_subscription(
            user_id=current_user.id,
            plan=body.plan.value,
            status="active",
            stripe_customer_id=sub_data.get("stripe_customer_id"),
            stripe_subscription_id=sub_data.get("stripe_subscription_id"),
            current_period_end=period_end,
            billing_interval=interval,
        )
        sub_data["current_period_start"] = now.isoformat()
        sub_data["cancel_at_period_end"] = False
        logger.info(
            "Stub subscription created for user %s: plan=%s interval=%s (Stripe not configured)",
            current_user.id,
            body.plan.value,
            interval,
        )

    # Audit log
    try:
        from uuid import uuid4

        await db.insert(
            AUDIT_TABLE,
            {
                "id": uuid4().hex[:16],
                "user_id": current_user.id,
                "action": "billing.subscribe",
                "details_json": {"plan": body.plan.value},
                "created_at": now.isoformat(),
            },
        )
    except Exception:
        logger.debug("Failed to write billing audit log")

    return SubscriptionResponse(
        plan=PlanTier(sub_data["plan"]),
        status=sub_data.get("status", "active"),
        billing_interval=sub_data.get("billing_interval", "monthly"),
        current_period_start=sub_data.get("current_period_start"),
        current_period_end=sub_data.get("current_period_end"),
        cancel_at_period_end=sub_data.get("cancel_at_period_end", False),
        stripe_subscription_id=sub_data.get("stripe_subscription_id"),
    )


@router.get(
    "/subscription",
    response_model=SubscriptionResponse,
    summary="Get current subscription",
    responses={401: {"model": ErrorResponse}},
)
async def get_subscription(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> SubscriptionResponse:
    """Return the current subscription details for the authenticated user.

    If the user has no subscription, a Free plan record is created and returned.
    """
    sub_data = await _get_or_create_subscription(current_user.id)

    # If Stripe is configured, try to sync from Stripe
    stripe = _get_stripe()
    stripe_sub_id = sub_data.get("stripe_subscription_id")
    if stripe and stripe_sub_id:
        try:
            subscription = stripe.Subscription.retrieve(stripe_sub_id)
            raw_end = getattr(subscription, "current_period_end", None)
            raw_start = getattr(subscription, "current_period_start", None)
            period_end = (
                datetime.utcfromtimestamp(raw_end).isoformat()
                if raw_end
                else sub_data.get("current_period_end")
            )
            period_start = (
                datetime.utcfromtimestamp(raw_start).isoformat()
                if raw_start
                else sub_data.get("current_period_start")
            )
            sub_data = await db.upsert_subscription(
                user_id=current_user.id,
                plan=sub_data.get("plan", PlanTier.FREE.value),
                status=subscription.status,
                stripe_customer_id=sub_data.get("stripe_customer_id"),
                stripe_subscription_id=stripe_sub_id,
                current_period_end=period_end,
            )
            sub_data["current_period_start"] = period_start
            sub_data["cancel_at_period_end"] = getattr(
                subscription, "cancel_at_period_end", False
            )
        except Exception:
            logger.warning("Failed to sync subscription %s from Stripe", stripe_sub_id)

    return SubscriptionResponse(
        plan=PlanTier(sub_data["plan"]),
        status=sub_data.get("status", "active"),
        billing_interval=sub_data.get("billing_interval", "monthly"),
        current_period_start=sub_data.get("current_period_start"),
        current_period_end=sub_data.get("current_period_end"),
        cancel_at_period_end=sub_data.get("cancel_at_period_end", False),
        stripe_subscription_id=sub_data.get("stripe_subscription_id"),
    )


@router.post(
    "/portal",
    response_model=PortalResponse,
    summary="Create Stripe customer portal session",
    responses={401: {"model": ErrorResponse}},
)
async def create_portal_session(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> PortalResponse:
    """Create a Stripe Customer Portal session for the user to manage their
    subscription, payment methods, and invoices.

    When Stripe is not configured, returns a placeholder URL.
    """
    stripe = _get_stripe()

    if stripe is not None:
        sub_data = await _get_or_create_subscription(current_user.id)
        customer_id = sub_data.get("stripe_customer_id")

        if not customer_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No billing account found. Subscribe to a plan first.",
            )

        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=f"{settings.cors_origins[0]}/settings/billing",
            )
            return PortalResponse(url=session.url)
        except Exception as exc:
            logger.exception("Failed to create Stripe portal session")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Payment provider error: {exc}",
            )

    # Stub response when Stripe is not configured
    logger.info("Stripe not configured — returning stub portal URL")
    return PortalResponse(url=f"{settings.cors_origins[0]}/settings/billing?stub=true")


@router.get(
    "/credit-packages",
    response_model=list[CreditPackage],
    summary="List available credit packages",
)
async def list_credit_packages() -> list[CreditPackage]:
    """Return available credit packages for purchase."""
    return CREDIT_PACKAGES


@router.post(
    "/purchase-credits",
    response_model=PurchaseCreditsResponse,
    summary="Purchase additional credits",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        400: {"model": ErrorResponse},
    },
    dependencies=[Depends(RateLimiter(max_requests=5, window=60))],
)
async def purchase_credits(
    request: PurchaseCreditsRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> PurchaseCreditsResponse:
    """
    Purchase additional credits via Stripe checkout.

    This creates a one-time payment session for credit packages.
    Credits are added after successful payment via webhook.
    """
    stripe = _get_stripe()

    # Find the package
    package = next(
        (p for p in CREDIT_PACKAGES if p.package_id == request.package_id), None
    )
    if not package:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credit package ID",
        )

    if stripe is not None:
        try:
            # Get or create Stripe customer
            sub_data = await _get_or_create_subscription(current_user.id)
            customer_id = sub_data.get("stripe_customer_id")

            if not customer_id:
                customer = stripe.Customer.create(
                    email=current_user.email,
                    metadata={"sigil_user_id": current_user.id},
                )
                customer_id = customer.id

                # Update subscription with customer ID
                await db.upsert_subscription(
                    user_id=current_user.id,
                    plan=sub_data.get("plan", PlanTier.FREE.value),
                    status=sub_data.get("status", "active"),
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=sub_data.get("stripe_subscription_id"),
                    current_period_end=sub_data.get("current_period_end"),
                    billing_interval=sub_data.get("billing_interval", "monthly"),
                )

            # Build success/cancel URLs
            frontend_url = settings.frontend_url.rstrip("/")
            success_url = f"{frontend_url}/settings?credit_purchase=success"
            cancel_url = f"{frontend_url}/settings?credit_purchase=cancel"

            # Create Stripe checkout session for one-time payment
            checkout_session = stripe.checkout.Session.create(
                customer=customer_id,
                mode="payment",  # One-time payment, not subscription
                line_items=[{"price": package.stripe_price_id, "quantity": 1}],
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    "sigil_user_id": current_user.id,
                    "credit_package_id": str(package.package_id),
                    "credits_amount": str(package.credits + package.bonus_credits),
                },
            )

            # Log the purchase attempt
            logger.info(
                f"Created credit purchase checkout for user {current_user.id}: "
                f"package={package.name} credits={package.credits + package.bonus_credits}"
            )

            return PurchaseCreditsResponse(
                success=True,
                checkout_url=checkout_session.url,
                credits_purchased=package.credits + package.bonus_credits,
            )

        except Exception as e:
            logger.exception(f"Failed to create credit purchase checkout: {e}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Payment provider error: {e}",
            )
    else:
        # Stub implementation - directly add credits
        try:
            from api.services.credit_service import credit_service

            total_credits = package.credits + package.bonus_credits
            new_balance = await credit_service.add_credits(
                user_id=current_user.id,
                amount=total_credits,
                transaction_type="purchase",
                metadata={
                    "package_id": package.package_id,
                    "package_name": package.name,
                    "price_usd": package.price_usd,
                    "stub_purchase": True,
                },
            )

            logger.info(
                f"Stub credit purchase for user {current_user.id}: "
                f"added {total_credits} credits"
            )

            return PurchaseCreditsResponse(
                success=True,
                credits_purchased=total_credits,
                new_balance=new_balance,
            )

        except Exception as e:
            logger.exception(f"Failed to process stub credit purchase: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to process credit purchase",
            )


@router.post(
    "/webhook",
    response_model=WebhookResponse,
    summary="Stripe webhook handler",
)
async def stripe_webhook(request: Request) -> WebhookResponse:
    """Handle incoming Stripe webhook events.

    Verifies the webhook signature when ``SIGIL_STRIPE_WEBHOOK_SECRET`` is set,
    then processes relevant events (subscription updates, payment failures, etc.).

    This endpoint does NOT require authentication — it is called by Stripe directly.
    """
    stripe = _get_stripe()
    body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    event: dict[str, Any] | None = None

    if stripe is not None and settings.stripe_webhook_secret:
        # Verify webhook signature for security
        try:
            event = stripe.Webhook.construct_event(
                body, sig_header, settings.stripe_webhook_secret
            )
            logger.info("Webhook signature verified successfully")
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Webhook signature verification failed: {e}")
            raise HTTPException(status_code=400, detail="Invalid webhook signature")
        except ValueError as e:
            logger.error(f"Webhook payload invalid: {e}")
            raise HTTPException(status_code=400, detail="Invalid payload format")
        except Exception as e:
            logger.error(f"Webhook verification error: {e}")
            raise HTTPException(
                status_code=400, detail=f"Webhook verification failed: {e}"
            )
    else:
        # No Stripe or no secret — parse raw JSON (development/testing mode)
        import json

        if not settings.stripe_configured:
            logger.warning(
                "Stripe not configured, processing webhook in development mode"
            )

        try:
            event = json.loads(body)
        except Exception as e:
            logger.error(f"Invalid JSON in webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type", "unknown") if event else "unknown"
    event_id = event.get("id", "unknown") if event else "unknown"

    logger.info(f"Processing Stripe webhook: {event_type} (ID: {event_id})")

    try:
        # --- Handle known event types ---
        if event_type == "checkout.session.completed":
            await _handle_checkout_completed(event)
        elif event_type == "customer.subscription.created":
            await _handle_subscription_created(event)
        elif event_type == "customer.subscription.updated":
            await _handle_subscription_updated(event)
        elif event_type == "customer.subscription.deleted":
            await _handle_subscription_deleted(event)
        elif event_type == "invoice.payment_failed":
            await _handle_payment_failed(event)
        elif event_type == "invoice.payment_succeeded":
            await _handle_payment_succeeded(event)
        elif event_type == "customer.subscription.trial_will_end":
            await _handle_trial_will_end(event)
        else:
            logger.debug(f"Unhandled Stripe event type: {event_type}")

        # Log successful webhook processing
        logger.info(f"Successfully processed webhook {event_type} (ID: {event_id})")

    except Exception as e:
        logger.exception(f"Error processing webhook {event_type} (ID: {event_id}): {e}")
        # Don't raise the exception - Stripe will retry if we return an error
        # Just log it and return success to prevent infinite retries

    return WebhookResponse(received=True, event_type=event_type)


# ---------------------------------------------------------------------------
# Webhook event handlers
# ---------------------------------------------------------------------------


async def _handle_checkout_completed(event: dict[str, Any]) -> None:
    """Process a completed Checkout Session.

    Handles both subscription checkout and credit purchase checkout.
    """
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    subscription_id = data.get("subscription", "")
    metadata = data.get("metadata", {})
    user_id = metadata.get("sigil_user_id", "")

    # Check if this is a credit purchase (no subscription ID)
    if not subscription_id and metadata.get("credit_package_id"):
        await _handle_credit_purchase_completed(data, metadata)
        return

    # Handle subscription checkout
    plan = metadata.get("sigil_plan", PlanTier.FREE.value)
    interval = metadata.get("sigil_interval", "monthly")

    logger.info(
        "Subscription checkout completed: customer=%s subscription=%s user=%s plan=%s",
        customer_id,
        subscription_id,
        user_id,
        plan,
    )

    if not user_id:
        # Try to look up by customer ID
        existing = await db.get_subscription_by_stripe_customer(customer_id)
        if existing:
            user_id = existing["user_id"]

    if not user_id:
        logger.warning(
            "Cannot resolve user for checkout.session.completed: customer=%s",
            customer_id,
        )
        return

    # Fetch the subscription from Stripe to get period dates
    stripe = _get_stripe()
    period_end = None
    sub_status = "active"
    if stripe and subscription_id:
        try:
            sub = stripe.Subscription.retrieve(subscription_id)
            sub_status = sub.status
            period_end = datetime.utcfromtimestamp(sub.current_period_end).isoformat()
        except Exception:
            logger.warning(
                "Failed to retrieve subscription %s from Stripe", subscription_id
            )

    if period_end is None:
        now = datetime.utcnow()
        days = 365 if interval == "annual" else 30
        period_end = (now + timedelta(days=days)).isoformat()

    await db.upsert_subscription(
        user_id=user_id,
        plan=plan,
        status=sub_status,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        current_period_end=period_end,
        billing_interval=interval,
    )

    # Update user subscription tier and refresh credits when subscription is activated
    if sub_status == "active" and plan != PlanTier.FREE.value:
        try:
            from api.services.credit_service import credit_service

            # Update user's subscription tier in users table
            await db.execute(
                "UPDATE users SET subscription_tier = :tier WHERE id = :user_id",
                {"tier": plan, "user_id": user_id},
            )

            # Initialize credits for the new subscription
            await credit_service.initialize_user_credits(user_id)

            logger.info(
                f"Updated user {user_id} to {plan} tier with credits initialized"
            )
        except Exception as e:
            logger.exception(f"Failed to update user tier and credits: {e}")

    # Fire PostHog conversion event for funnel tracking
    from api.services.posthog_service import posthog_service
    posthog_service.capture(
        distinct_id=user_id,
        event="sigil_subscription",
        properties={
            "plan": plan,
            "billing_interval": interval,
            "stripe_customer_id": customer_id,
        },
    )


async def _handle_subscription_updated(event: dict[str, Any]) -> None:
    """Process a subscription update event from Stripe."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    sub_status = data.get("status", "active")

    logger.info(
        "Subscription updated: customer=%s status=%s",
        customer_id,
        sub_status,
    )

    # Find the subscription by Stripe customer ID and update it
    existing = await db.get_subscription_by_stripe_customer(customer_id)
    if existing:
        period_end: str | None = None
        if "current_period_end" in data:
            period_end = datetime.utcfromtimestamp(
                data["current_period_end"]
            ).isoformat()

        user_id = existing["user_id"]
        current_plan = existing.get("plan", PlanTier.FREE.value)

        await db.upsert_subscription(
            user_id=user_id,
            plan=current_plan,
            status=sub_status,
            stripe_customer_id=customer_id,
            stripe_subscription_id=existing.get("stripe_subscription_id"),
            current_period_end=period_end or existing.get("current_period_end"),
            billing_interval=existing.get("billing_interval", "monthly"),
        )

        # Handle subscription status changes
        try:
            if sub_status == "canceled" or sub_status == "past_due":
                # Downgrade to free tier
                await db.execute(
                    "UPDATE users SET subscription_tier = 'free' WHERE id = :user_id",
                    {"user_id": user_id},
                )
                logger.info(
                    f"Downgraded user {user_id} to free tier due to {sub_status}"
                )
            elif sub_status == "active" and current_plan != PlanTier.FREE.value:
                # Ensure user has correct tier and credits
                await db.execute(
                    "UPDATE users SET subscription_tier = :tier WHERE id = :user_id",
                    {"tier": current_plan, "user_id": user_id},
                )

                from api.services.credit_service import credit_service

                await credit_service.initialize_user_credits(user_id)

                logger.info(f"Activated user {user_id} {current_plan} tier")
        except Exception as e:
            logger.exception(f"Failed to update user tier for subscription change: {e}")
    else:
        logger.warning(
            "Received subscription.updated for unknown customer: %s", customer_id
        )


async def _handle_subscription_deleted(event: dict[str, Any]) -> None:
    """Process a subscription cancellation event."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")

    logger.info("Subscription deleted for customer: %s", customer_id)

    existing = await db.get_subscription_by_stripe_customer(customer_id)
    if existing:
        user_id = existing["user_id"]

        await db.upsert_subscription(
            user_id=user_id,
            plan=PlanTier.FREE.value,
            status="canceled",
            stripe_customer_id=customer_id,
            stripe_subscription_id=None,
            current_period_end=existing.get("current_period_end"),
            billing_interval="monthly",
        )

        # Downgrade user to free tier
        try:
            await db.execute(
                "UPDATE users SET subscription_tier = 'free' WHERE id = :user_id",
                {"user_id": user_id},
            )

            # Optionally reset credits to free tier allocation
            from api.services.credit_service import credit_service

            await credit_service.initialize_user_credits(user_id)

            logger.info(
                f"Downgraded user {user_id} to free tier after subscription deletion"
            )
        except Exception as e:
            logger.exception(
                f"Failed to downgrade user after subscription deletion: {e}"
            )
    else:
        logger.warning(
            "Received subscription.deleted for unknown customer: %s", customer_id
        )


async def _handle_subscription_created(event: dict[str, Any]) -> None:
    """Process a new subscription creation event from Stripe."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    subscription_id = data.get("id", "")
    sub_status = data.get("status", "active")

    logger.info(
        f"Subscription created: customer={customer_id} subscription={subscription_id} status={sub_status}"
    )

    # Find the user by Stripe customer ID
    existing = await db.get_subscription_by_stripe_customer(customer_id)
    if existing:
        user_id = existing["user_id"]

        # Determine plan from Stripe subscription items
        items = data.get("items", {}).get("data", [])
        plan = PlanTier.PRO.value  # Default to Pro

        for item in items:
            price_id = item.get("price", {}).get("id", "")
            if (
                price_id == settings.stripe_price_team
                or price_id == settings.stripe_price_team_annual
            ):
                plan = PlanTier.TEAM.value
                break

        period_end = datetime.utcfromtimestamp(data["current_period_end"]).isoformat()
        billing_interval = (
            "annual"
            if data.get("items", {})
            .get("data", [{}])[0]
            .get("price", {})
            .get("recurring", {})
            .get("interval")
            == "year"
            else "monthly"
        )

        # Update subscription with new Stripe subscription ID
        await db.upsert_subscription(
            user_id=user_id,
            plan=plan,
            status=sub_status,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
            current_period_end=period_end,
            billing_interval=billing_interval,
        )

        # Activate user tier and credits
        try:
            await db.execute(
                "UPDATE users SET subscription_tier = :tier WHERE id = :user_id",
                {"tier": plan, "user_id": user_id},
            )

            from api.services.credit_service import credit_service

            await credit_service.initialize_user_credits(user_id)

            logger.info(f"Activated user {user_id} with {plan} subscription")
        except Exception as e:
            logger.exception(f"Failed to activate user tier: {e}")

        # Fire PostHog trial event for funnel tracking
        if sub_status == "trialing":
            from api.services.posthog_service import posthog_service
            posthog_service.capture(
                distinct_id=user_id,
                event="sigil_trial_started",
                properties={
                    "plan": plan,
                    "source": "stripe_subscription",
                },
            )
    else:
        logger.warning(
            f"Received subscription.created for unknown customer: {customer_id}"
        )


async def _handle_payment_failed(event: dict[str, Any]) -> None:
    """Handle payment failure and implement dunning management."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    subscription_id = data.get("subscription", "")
    amount = data.get("amount_due", 0)
    attempt_count = data.get("attempt_count", 1)

    logger.warning(
        f"Payment failed: customer={customer_id} subscription={subscription_id} amount={amount} cents attempt={attempt_count}"
    )

    # Find the user
    existing = await db.get_subscription_by_stripe_customer(customer_id)
    if existing:
        user_id = existing["user_id"]

        # Get user details for notification
        try:
            user_data = await db.fetch_one(
                "SELECT email, first_name, last_name FROM users WHERE id = :user_id",
                {"user_id": user_id},
            )

            user_email = user_data["email"] if user_data else None
            user_name = None
            if user_data and (
                user_data.get("first_name") or user_data.get("last_name")
            ):
                user_name = f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip()

        except Exception as e:
            logger.exception(f"Failed to get user data for notifications: {e}")
            user_email = None
            user_name = None

        # Implement grace period for first few failures
        if attempt_count <= 3:
            logger.info(
                f"Payment failure {attempt_count}/3 for user {user_id}, maintaining access"
            )

            # Send notification about payment failure
            if user_email:
                try:
                    from api.services.notification_service import notification_service

                    await notification_service.send_payment_failure_notification(
                        user_email=user_email,
                        user_name=user_name,
                        attempt_count=attempt_count,
                        amount=amount,
                        next_retry=None,  # Could add retry date logic
                    )
                    logger.info(f"Sent payment failure notification to {user_email}")
                except Exception as e:
                    logger.exception(
                        f"Failed to send payment failure notification: {e}"
                    )

            return

        # After 3 attempts, downgrade to free tier
        try:
            await db.upsert_subscription(
                user_id=user_id,
                plan=PlanTier.FREE.value,
                status="past_due",
                stripe_customer_id=customer_id,
                stripe_subscription_id=subscription_id,
                current_period_end=existing.get("current_period_end"),
                billing_interval=existing.get("billing_interval", "monthly"),
            )

            await db.execute(
                "UPDATE users SET subscription_tier = 'free' WHERE id = :user_id",
                {"user_id": user_id},
            )

            # Send final downgrade notification
            if user_email:
                try:
                    from api.services.notification_service import notification_service

                    await notification_service.send_payment_failure_notification(
                        user_email=user_email,
                        user_name=user_name,
                        attempt_count=attempt_count,
                        amount=amount,
                    )
                    logger.info(f"Sent downgrade notification to {user_email}")
                except Exception as e:
                    logger.exception(f"Failed to send downgrade notification: {e}")

            logger.info(f"Downgraded user {user_id} to free tier after payment failure")

        except Exception as e:
            logger.exception(
                f"Failed to handle payment failure for user {user_id}: {e}"
            )


async def _handle_payment_succeeded(event: dict[str, Any]) -> None:
    """Handle successful payment and restore access if needed."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    subscription_id = data.get("subscription", "")
    amount = data.get("amount_paid", 0)

    logger.info(
        f"Payment succeeded: customer={customer_id} subscription={subscription_id} amount={amount} cents"
    )

    # Find the user and restore access if they were downgraded
    existing = await db.get_subscription_by_stripe_customer(customer_id)
    if existing and existing.get("status") == "past_due":
        user_id = existing["user_id"]
        current_plan = existing.get("plan", PlanTier.PRO.value)

        try:
            # Restore subscription status
            await db.upsert_subscription(
                user_id=user_id,
                plan=current_plan,
                status="active",
                stripe_customer_id=customer_id,
                stripe_subscription_id=subscription_id,
                current_period_end=existing.get("current_period_end"),
                billing_interval=existing.get("billing_interval", "monthly"),
            )

            await db.execute(
                "UPDATE users SET subscription_tier = :tier WHERE id = :user_id",
                {"tier": current_plan, "user_id": user_id},
            )

            from api.services.credit_service import credit_service

            await credit_service.initialize_user_credits(user_id)

            logger.info(
                f"Restored user {user_id} to {current_plan} tier after successful payment"
            )

        except Exception as e:
            logger.exception(f"Failed to restore user access after payment: {e}")


async def _handle_trial_will_end(event: dict[str, Any]) -> None:
    """Handle trial ending notification."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    trial_end = data.get("trial_end", 0)

    logger.info(f"Trial ending for customer {customer_id} at {trial_end}")

    # Could send notification email here
    # For now, just log the event


async def _handle_credit_purchase_completed(
    data: dict[str, Any], metadata: dict[str, Any]
) -> None:
    """Process a completed credit purchase checkout."""
    user_id = metadata.get("sigil_user_id", "")
    package_id = metadata.get("credit_package_id", "")
    credits_amount = int(metadata.get("credits_amount", "0"))
    payment_intent_id = data.get("payment_intent", "")

    logger.info(
        f"Credit purchase completed: user={user_id} package={package_id} credits={credits_amount}"
    )

    if not user_id:
        logger.error("Credit purchase completed but no user ID in metadata")
        return

    try:
        # Find the package details
        package = next(
            (p for p in CREDIT_PACKAGES if p.package_id == int(package_id)), None
        )
        if not package:
            logger.error(f"Unknown credit package ID: {package_id}")
            return

        # Add credits to user's balance
        from api.services.credit_service import credit_service

        new_balance = await credit_service.add_credits(
            user_id=user_id,
            amount=credits_amount,
            transaction_type="purchase",
            metadata={
                "package_id": package_id,
                "package_name": package.name,
                "price_usd": package.price_usd,
                "stripe_payment_intent": payment_intent_id,
                "credits_purchased": package.credits,
                "bonus_credits": package.bonus_credits,
            },
        )

        logger.info(
            f"Added {credits_amount} credits to user {user_id}. New balance: {new_balance}"
        )

        # Send notification email
        try:
            user_data = await db.fetch_one(
                "SELECT email, first_name, last_name FROM users WHERE id = :user_id",
                {"user_id": user_id},
            )

            if user_data and user_data.get("email"):
                user_email = user_data["email"]
                user_name = None
                if user_data.get("first_name") or user_data.get("last_name"):
                    user_name = f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip()

                from api.services.notification_service import notification_service

                # Create custom notification content for credit purchases
                subject = f"Credits Added - {package.name} Purchase Successful"
                amount_dollars = package.price_usd
                name_part = f"Hi {user_name}," if user_name else "Hello,"

                content = f"""
{name_part}

Great news! Your credit purchase has been processed successfully.

Purchase Details:
- Package: {package.name}
- Credits Added: {credits_amount:,} 
- Amount Paid: ${amount_dollars:.2f}
- New Balance: {new_balance:,} credits

Your credits are now available for AI-powered security analysis features.

Start using your credits: https://app.sigilsec.ai/

Best regards,
The Sigil Team
"""

                await notification_service._send_email(user_email, subject, content)
                logger.info(f"Sent credit purchase confirmation to {user_email}")

        except Exception as e:
            logger.exception(f"Failed to send credit purchase notification: {e}")

    except Exception as e:
        logger.exception(f"Failed to process credit purchase for user {user_id}: {e}")
