"""
Sigil API — Application Entry Point

FastAPI application with CORS middleware, lifespan management for database
and cache connections, and all versioned routers.

Run with:
    uvicorn api.main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.config import settings
from api.database import cache, db
from api.gates import PlanGateException
from api.models import GateError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sigil.api")


# ---------------------------------------------------------------------------
# Lifespan — connect/disconnect external services
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and shutdown of external connections."""
    logger.info("Starting Sigil API v%s", settings.app_version)

    # Warn loudly if using default JWT secret
    if settings.jwt_secret == "changeme-generate-a-real-secret":
        logger.critical(
            "SECURITY: Using default JWT secret! Set SIGIL_JWT_SECRET "
            "environment variable before deploying to production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # Validate Stripe configuration consistency
    if settings.stripe_configured:
        placeholders = [v for v in [
            settings.stripe_price_pro,
            settings.stripe_price_team,
        ] if "placeholder" in v]
        if placeholders:
            logger.warning(
                "Stripe is configured but price IDs contain placeholders. "
                "Set SIGIL_STRIPE_PRICE_PRO and SIGIL_STRIPE_PRICE_TEAM."
            )

    await db.connect()
    await cache.connect()

    yield

    logger.info("Shutting down Sigil API")
    await cache.disconnect()
    await db.disconnect()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Sigil is an automated security auditing platform for AI agent code. "
        "This API provides scan submission, threat intelligence lookups, "
        "publisher reputation scoring, and marketplace verification."
    ),
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if not settings.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------


@app.exception_handler(PlanGateException)
async def plan_gate_handler(request: Request, exc: PlanGateException) -> JSONResponse:
    """Convert a PlanGateException into a 403 GateError JSON response."""
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content=GateError(
            detail=f"This feature requires the {exc.required_plan.value} plan or higher.",
            required_plan=exc.required_plan.value,
            current_plan=exc.current_plan.value,
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler that prevents unhandled exceptions from leaking
    stack traces to clients in production.
    """
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

from api.routers import (  # noqa: E402
    alerts,
    auth,
    billing,
    policies,
    publisher,
    report,
    scan,
    team,
    threat,
    verify,
)

# --- Original /v1 routes (backward compatibility) --------------------------
app.include_router(scan.router)
app.include_router(threat.router)
app.include_router(publisher.router)
app.include_router(report.router)
app.include_router(verify.router)
app.include_router(auth.router)
app.include_router(policies.router)
app.include_router(alerts.router)
app.include_router(billing.router)

# --- Dashboard-compatible routes (no /v1 prefix) --------------------------
# The dashboard frontend calls paths like /auth/login, /scans, /team,
# /settings/policy, /settings/alerts, etc.  The routers above serve these
# under /v1/*.  To keep backward compatibility AND support the dashboard we
# create lightweight alias routers that delegate to the same handler
# functions but are mounted at the paths the dashboard expects.

from fastapi import APIRouter as _APIRouter  # noqa: E402

# -- Auth aliases: /auth/register, /auth/login, /auth/me, /auth/refresh, /auth/logout
_auth_dashboard = _APIRouter(prefix="/auth", tags=["auth-dashboard"])
_auth_dashboard.add_api_route(
    "/register", auth.register, methods=["POST"], status_code=201
)
_auth_dashboard.add_api_route("/login", auth.login, methods=["POST"])
_auth_dashboard.add_api_route("/me", auth.me, methods=["GET"])
_auth_dashboard.add_api_route("/refresh", auth.refresh_token, methods=["POST"])
_auth_dashboard.add_api_route("/logout", auth.logout, methods=["POST"], status_code=204)
app.include_router(_auth_dashboard)

# -- Scan dashboard routes: /scans, /scans/{id}, /dashboard/stats, etc.
app.include_router(scan.dashboard_router)

# -- Team management: /team, /team/invite, /team/members/{id}, etc.
app.include_router(team.router)

# -- Settings > Policy aliases: /settings/policy -> policies endpoints
_settings_policy = _APIRouter(prefix="/settings/policy", tags=["settings-policy"])
_settings_policy.add_api_route("", policies.list_policies, methods=["GET"])
_settings_policy.add_api_route(
    "", policies.create_policy, methods=["POST"], status_code=201
)
_settings_policy.add_api_route("/{policy_id}", policies.update_policy, methods=["PUT"])
_settings_policy.add_api_route(
    "/{policy_id}", policies.update_policy, methods=["PATCH"]
)
_settings_policy.add_api_route(
    "/{policy_id}", policies.delete_policy, methods=["DELETE"], status_code=204
)
app.include_router(_settings_policy)

# -- Settings > Alerts aliases: /settings/alerts -> alerts endpoints
_settings_alerts = _APIRouter(prefix="/settings/alerts", tags=["settings-alerts"])
_settings_alerts.add_api_route("", alerts.list_alerts, methods=["GET"])
_settings_alerts.add_api_route(
    "", alerts.create_alert, methods=["POST"], status_code=201
)
_settings_alerts.add_api_route("/{alert_id}", alerts.update_alert, methods=["PUT"])
_settings_alerts.add_api_route("/{alert_id}", alerts.update_alert, methods=["PATCH"])
_settings_alerts.add_api_route(
    "/{alert_id}", alerts.delete_alert, methods=["DELETE"], status_code=204
)
_settings_alerts.add_api_route("/test", alerts.test_alert, methods=["POST"])
app.include_router(_settings_alerts)

# -- Unprefixed policy/alert aliases: /policies, /alerts
_policies_dashboard = _APIRouter(prefix="/policies", tags=["policies-dashboard"])
_policies_dashboard.add_api_route("", policies.list_policies, methods=["GET"])
_policies_dashboard.add_api_route(
    "", policies.create_policy, methods=["POST"], status_code=201
)
_policies_dashboard.add_api_route(
    "/evaluate", policies.evaluate_policies, methods=["POST"]
)
_policies_dashboard.add_api_route(
    "/{policy_id}", policies.update_policy, methods=["PUT"]
)
_policies_dashboard.add_api_route(
    "/{policy_id}", policies.update_policy, methods=["PATCH"]
)
_policies_dashboard.add_api_route(
    "/{policy_id}", policies.delete_policy, methods=["DELETE"], status_code=204
)
app.include_router(_policies_dashboard)

_alerts_dashboard = _APIRouter(prefix="/alerts", tags=["alerts-dashboard"])
_alerts_dashboard.add_api_route("", alerts.list_alerts, methods=["GET"])
_alerts_dashboard.add_api_route(
    "", alerts.create_alert, methods=["POST"], status_code=201
)
_alerts_dashboard.add_api_route("/test", alerts.test_alert, methods=["POST"])
_alerts_dashboard.add_api_route("/{alert_id}", alerts.update_alert, methods=["PUT"])
_alerts_dashboard.add_api_route("/{alert_id}", alerts.update_alert, methods=["PATCH"])
_alerts_dashboard.add_api_route(
    "/{alert_id}", alerts.delete_alert, methods=["DELETE"], status_code=204
)
app.include_router(_alerts_dashboard)

# -- Unprefixed threat, publisher, report, verify, billing aliases
_threat_dashboard = _APIRouter(prefix="", tags=["threat-intel-dashboard"])
_threat_dashboard.add_api_route(
    "/threat/{package_hash}", threat.get_threat, methods=["GET"]
)
_threat_dashboard.add_api_route("/threats", threat.get_threats, methods=["GET"])
_threat_dashboard.add_api_route(
    "/signatures", threat.get_all_signatures, methods=["GET"]
)
_threat_dashboard.add_api_route(
    "/signatures", threat.create_or_update_signature, methods=["POST"]
)
_threat_dashboard.add_api_route(
    "/signatures/{sig_id}", threat.remove_signature, methods=["DELETE"]
)
_threat_dashboard.add_api_route(
    "/threat-reports", threat.get_threat_reports, methods=["GET"]
)
_threat_dashboard.add_api_route(
    "/threat-reports/{report_id}", threat.get_single_report, methods=["GET"]
)
_threat_dashboard.add_api_route(
    "/threat-reports/{report_id}", threat.update_report, methods=["PATCH"]
)
_threat_dashboard.add_api_route(
    "/threats/report",
    report.create_report,
    methods=["POST"],
    status_code=201,
)
app.include_router(_threat_dashboard)

_publisher_dashboard = _APIRouter(prefix="", tags=["publisher-dashboard"])
_publisher_dashboard.add_api_route(
    "/publisher/{publisher_id}", publisher.get_publisher, methods=["GET"]
)
app.include_router(_publisher_dashboard)

_report_dashboard = _APIRouter(prefix="", tags=["report-dashboard"])
_report_dashboard.add_api_route(
    "/report", report.create_report, methods=["POST"], status_code=201
)
app.include_router(_report_dashboard)

_verify_dashboard = _APIRouter(prefix="", tags=["verify-dashboard"])
_verify_dashboard.add_api_route("/verify", verify.verify_package, methods=["POST"])
app.include_router(_verify_dashboard)

_billing_dashboard = _APIRouter(prefix="/billing", tags=["billing-dashboard"])
_billing_dashboard.add_api_route("/plans", billing.list_plans, methods=["GET"])
_billing_dashboard.add_api_route("/subscribe", billing.subscribe, methods=["POST"])
_billing_dashboard.add_api_route(
    "/subscription", billing.get_subscription, methods=["GET"]
)
_billing_dashboard.add_api_route(
    "/portal", billing.create_portal_session, methods=["POST"]
)
_billing_dashboard.add_api_route("/webhook", billing.stripe_webhook, methods=["POST"])
app.include_router(_billing_dashboard)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health", tags=["system"], summary="Health check")
async def health() -> JSONResponse:
    """Return service health status including backend connectivity."""
    healthy = db.connected
    return JSONResponse(
        status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "ok" if healthy else "degraded",
            "version": settings.app_version,
            "supabase_connected": db.connected,
            "redis_connected": cache.connected,
        },
    )


@app.get("/", tags=["system"], summary="Root")
async def root() -> dict:
    """Landing endpoint with API metadata."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
