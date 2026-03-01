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
from datetime import datetime, timedelta
from typing import Any
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.config import settings
from api.database import db
from api.rate_limit import RateLimiter
from api.models import (
    ErrorResponse,
    PlanInfo,
    PlanTier,
    PortalResponse,
    SubscribeRequest,
    SubscriptionResponse,
    WebhookResponse,
)
from api.routers.auth import get_current_user_unified, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])

AUDIT_TABLE = "audit_log"

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

# Stripe price ID mapping — keyed by (tier, interval)
_STRIPE_PRICE_MAP: dict[tuple[PlanTier, str], str | None] = {
    (PlanTier.FREE, "monthly"): None,
    (PlanTier.FREE, "annual"): None,
    (PlanTier.PRO, "monthly"): settings.stripe_price_pro,
    (PlanTier.PRO, "annual"): settings.stripe_price_pro_annual,
    (PlanTier.TEAM, "monthly"): settings.stripe_price_team,
    (PlanTier.TEAM, "annual"): settings.stripe_price_team_annual,
    (PlanTier.ENTERPRISE, "monthly"): None,  # Custom — handled via sales
    (PlanTier.ENTERPRISE, "annual"): None,
}


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
        price_id = _STRIPE_PRICE_MAP.get((body.plan, interval))

        # Reject if the price ID is a placeholder or missing for paid plans
        if (
            body.plan != PlanTier.FREE
            and (not price_id or "placeholder" in price_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"The {interval} billing interval is not yet available for the {body.plan.value} plan. Please select monthly billing.",
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
                if raw_end else sub_data.get("current_period_end")
            )
            period_start = (
                datetime.utcfromtimestamp(raw_start).isoformat()
                if raw_start else sub_data.get("current_period_start")
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
        # Verify webhook signature
        try:
            event = stripe.Webhook.construct_event(
                body, sig_header, settings.stripe_webhook_secret
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid payload")
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Signature verification failed: {exc}"
            )
    else:
        # No Stripe / no secret — parse raw JSON (development mode)
        import json

        try:
            event = json.loads(body)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type", "unknown") if event else "unknown"

    logger.info("Stripe webhook received: %s", event_type)

    # --- Handle known event types ---
    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(event)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(event)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(event)
    elif event_type == "invoice.payment_failed":
        _handle_payment_failed(event)
    elif event_type == "invoice.payment_succeeded":
        _handle_payment_succeeded(event)
    else:
        logger.debug("Unhandled Stripe event type: %s", event_type)

    return WebhookResponse(received=True, event_type=event_type)


# ---------------------------------------------------------------------------
# Webhook event handlers
# ---------------------------------------------------------------------------


async def _handle_checkout_completed(event: dict[str, Any]) -> None:
    """Process a completed Checkout Session.

    When a user finishes Stripe Checkout, this event fires with the new
    subscription ID.  We persist the subscription details to the DB.
    """
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    subscription_id = data.get("subscription", "")
    metadata = data.get("metadata", {})
    user_id = metadata.get("sigil_user_id", "")
    plan = metadata.get("sigil_plan", PlanTier.FREE.value)
    interval = metadata.get("sigil_interval", "monthly")

    logger.info(
        "Checkout completed: customer=%s subscription=%s user=%s plan=%s",
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
            period_end = datetime.utcfromtimestamp(
                sub.current_period_end
            ).isoformat()
        except Exception:
            logger.warning("Failed to retrieve subscription %s from Stripe", subscription_id)

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
        await db.upsert_subscription(
            user_id=existing["user_id"],
            plan=existing.get("plan", PlanTier.FREE.value),
            status=sub_status,
            stripe_customer_id=customer_id,
            stripe_subscription_id=existing.get("stripe_subscription_id"),
            current_period_end=period_end or existing.get("current_period_end"),
            billing_interval=existing.get("billing_interval", "monthly"),
        )
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
        await db.upsert_subscription(
            user_id=existing["user_id"],
            plan=PlanTier.FREE.value,
            status="canceled",
            stripe_customer_id=customer_id,
            stripe_subscription_id=None,
            current_period_end=existing.get("current_period_end"),
            billing_interval="monthly",
        )
    else:
        logger.warning(
            "Received subscription.deleted for unknown customer: %s", customer_id
        )


def _handle_payment_failed(event: dict[str, Any]) -> None:
    """Log a payment failure — in production, trigger a notification."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    amount = data.get("amount_due", 0)

    logger.warning(
        "Payment failed: customer=%s amount=%d cents",
        customer_id,
        amount,
    )


def _handle_payment_succeeded(event: dict[str, Any]) -> None:
    """Log a successful payment."""
    data = event.get("data", {}).get("object", {})
    customer_id = data.get("customer", "")
    amount = data.get("amount_paid", 0)

    logger.info(
        "Payment succeeded: customer=%s amount=%d cents",
        customer_id,
        amount,
    )
