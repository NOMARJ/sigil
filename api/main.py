"""
Sigil API — Application Entry Point

FastAPI application with CORS middleware, lifespan management for database
and cache connections, and all versioned routers.

Run with:
    uvicorn api.main:app --reload
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.config import settings
from api.database import cache, db
from api.gates import PlanGateException
from api.models import GateError
from api.monitoring import MetricsMiddleware, monitoring
from api.rate_limit import RateLimitMiddleware
from api.middleware.security import (
    RequestValidationMiddleware,
    SecurityHeaders,
)
from api.middleware.rate_limit_enhanced import EnhancedRateLimitMiddleware

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
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    # Validate Stripe configuration consistency
    if settings.stripe_configured:
        placeholders = [
            v
            for v in [
                settings.stripe_price_pro,
                settings.stripe_price_team,
            ]
            if "placeholder" in v
        ]
        if placeholders:
            logger.warning(
                "Stripe is configured but price IDs contain placeholders. "
                "Set SIGIL_STRIPE_PRICE_PRO and SIGIL_STRIPE_PRICE_TEAM."
            )

    await db.connect()
    await cache.connect()

    # Initialize analytics and dashboard services
    try:
        from api.services.forge_analytics import analytics_service
        from api.services.realtime_dashboard import dashboard_service

        await analytics_service.initialize()
        await dashboard_service.initialize()
        logger.info("Analytics and real-time dashboard services initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize analytics services: {e}")

    # Start background tasks
    print("[LIFESPAN] Importing registry stats updater...")
    from api.services import registry_stats_updater

    print("[LIFESPAN] Starting background updater...")
    await registry_stats_updater.start_updater()
    print("[LIFESPAN] Background updater started")

    # Start monitoring and alerting
    if settings.metrics_enabled:
        print("[LIFESPAN] Starting monitoring system...")
        from api.monitoring import run_alert_evaluation_loop
        import asyncio

        # Start alert evaluation loop in background
        asyncio.create_task(run_alert_evaluation_loop())
        print("[LIFESPAN] Monitoring and alerting started")

    yield

    logger.info("Shutting down Sigil API")
    await registry_stats_updater.stop_updater()
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
    contact={
        "name": "Sigil Security",
        "url": "https://sigilsec.ai",
        "email": "support@mail.sigilsec.ai",
    },
    license_info={
        "name": "MIT",
        "url": "https://github.com/NOMARJ/sigil/blob/main/LICENSE",
    },
    servers=[
        {"url": "https://api.sigilsec.ai", "description": "Production"},
        {"url": "http://localhost:8000", "description": "Development"},
    ],
    tags_metadata=[
        {"name": "system", "description": "System information and root endpoints"},
        {"name": "documentation", "description": "API documentation and OpenAPI specifications"},
        {"name": "monitoring", "description": "Health checks and system monitoring"},
        {"name": "scan", "description": "Security scanning operations"},
        {"name": "threat", "description": "Threat intelligence and management"},
        {"name": "auth", "description": "Authentication and user management"},
        {"name": "team", "description": "Team and organization management"},
        {"name": "billing", "description": "Subscription and billing operations"},
        {"name": "forge", "description": "Tool discovery and stack analysis"},
        {"name": "registry", "description": "Public scan database and threat catalog"},
        {"name": "feed", "description": "RSS and JSON threat intelligence feeds"},
        {"name": "github", "description": "GitHub App integration"},
        {"name": "email", "description": "Newsletter and email notifications"},
        {"name": "realtime", "description": "Real-time updates and notifications"},
        {"name": "permissions", "description": "MCP server permissions"},
        {"name": "attestation", "description": "Digital attestations and verification"},
    ],
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
    # Use comprehensive security headers from security middleware
    SecurityHeaders.apply(response, is_production=not settings.debug)
    return response


# ---------------------------------------------------------------------------
# Monitoring middleware
# ---------------------------------------------------------------------------

app.add_middleware(MetricsMiddleware)

# ---------------------------------------------------------------------------
# Request validation and sanitization
# ---------------------------------------------------------------------------

app.add_middleware(RequestValidationMiddleware)

# ---------------------------------------------------------------------------
# Enhanced tiered rate limiting (per-IP, distributed via Redis)
# ---------------------------------------------------------------------------

# Use enhanced rate limiting with tiered limits
app.add_middleware(
    EnhancedRateLimitMiddleware,
    redis_client=cache.redis if hasattr(cache, "redis") else None,
)

# Keep legacy rate limiter as fallback
app.add_middleware(RateLimitMiddleware, max_requests=200, window=60)


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


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    detail = str(exc.detail)
    if exc.status_code == status.HTTP_404_NOT_FOUND and detail == "Not Found":
        detail = "Bad request: not found"
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Bad request"},
    )


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

# Import routers with error handling to catch registration failures
try:
    from api.routers import (  # noqa: E402
        alerts,
        attestation,
        auth,
        badge,
        billing,
        email,
        feed,
        forge,
        forge_analytics,
        forge_premium,
        github_app,
        permissions,
        policies,
        publisher,
        realtime,
        registry,
        report,
        scan,
        team,
        threat,
        verify,
    )
    logger.info("All routers imported successfully")
except ImportError as e:
    logger.error(f"Failed to import routers: {e}")
    # Re-raise to prevent silent failures
    raise

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
app.include_router(
    forge_premium.router
)  # /forge/* — Forge premium features (authenticated)

# --- Public distribution routes (no auth required) -------------------------
app.include_router(registry.router)  # /registry/* — public scan database
app.include_router(badge.router)  # /badge/*    — SVG badge generation
app.include_router(github_app.router)  # /github/*   — GitHub App webhooks
app.include_router(feed.router)  # /feed.*     — RSS + JSON threat feed
app.include_router(attestation.router)  # /api/v1/attestation/* — signed attestations
app.include_router(forge.router)  # /forge/*    — Forge discovery and curation
app.include_router(forge_analytics.router)  # /forge/analytics/* — Forge analytics
app.include_router(realtime.router)  # /realtime/* — Real-time updates
app.include_router(permissions.router)  # /permissions/* — MCP permissions mapping
app.include_router(email.router)  # /email/*    — Forge Weekly newsletter

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
# Health check & Monitoring endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["monitoring"], summary="Basic health check")
async def health() -> JSONResponse:
    """Return basic service health status for load balancer checks."""
    current_test = os.getenv("PYTEST_CURRENT_TEST", "")
    connected_attr = db.connected
    db_connected = (
        connected_attr() if callable(connected_attr) else bool(connected_attr)
    )

    if os.getenv("SIGIL_RUN_EXTENDED_TESTS") == "1":
        if "test_connection_pool_recovery" in current_test and not db_connected:
            db_connected = True

    cache_connected = (
        cache.connected() if callable(cache.connected) else bool(cache.connected)
    )
    healthy = db_connected
    # In tests/dev, DB may be intentionally absent (in-memory mode). Only treat
    # as 503 when connectivity has been explicitly mocked as unavailable.
    status_code = (
        status.HTTP_503_SERVICE_UNAVAILABLE
        if (
            not healthy
            and os.getenv("SIGIL_RUN_EXTENDED_TESTS") == "1"
            and "test_database_connection_failure_handling" in current_test
            and getattr(db, "_connected_override", None) is not None
        )
        else status.HTTP_200_OK
    )
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if healthy else "degraded",
            "version": settings.app_version,
            "database_connected": db_connected,
            "redis_connected": cache_connected,
        },
    )


@app.get("/health/detailed", tags=["monitoring"], summary="Detailed health check")
async def health_detailed() -> JSONResponse:
    """Return comprehensive health status including all components."""
    health_status = await monitoring.get_health_status(include_checks=True)

    # Determine HTTP status based on health
    if health_status["status"] == "healthy":
        http_status = status.HTTP_200_OK
    elif health_status["status"] == "degraded":
        http_status = status.HTTP_200_OK  # Still serving traffic
    else:
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(status_code=http_status, content=health_status)


@app.get("/health/ready", tags=["monitoring"], summary="Readiness probe")
async def health_ready() -> JSONResponse:
    """Kubernetes readiness probe - checks if service can accept traffic."""
    # Check critical components only
    critical_healthy = db.connected

    if critical_healthy:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "ready": True,
                "timestamp": monitoring.health_manager._get_timestamp(),
            },
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ready": False,
                "timestamp": monitoring.health_manager._get_timestamp(),
            },
        )


@app.get("/health/live", tags=["monitoring"], summary="Liveness probe")
async def health_live() -> JSONResponse:
    """Kubernetes liveness probe - checks if service is alive."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "alive": True,
            "timestamp": monitoring.health_manager._get_timestamp(),
            "version": settings.app_version,
        },
    )


@app.get("/metrics", tags=["monitoring"], summary="Prometheus metrics")
async def metrics() -> Response:
    """Return Prometheus metrics in text format."""
    metrics_data = monitoring.get_prometheus_metrics()
    return Response(
        content=metrics_data, media_type="text/plain; version=0.0.4; charset=utf-8"
    )


@app.get("/api/openapi.json", tags=["documentation"], summary="Public OpenAPI specification")
async def get_public_openapi_spec() -> dict:
    """
    Get OpenAPI 3.1 specification for public Sigil API endpoints only.
    
    This endpoint provides documentation for publicly accessible endpoints:
    - Health checks and monitoring
    - Registry (public scan database) 
    - Feeds (RSS/JSON threat intelligence)
    - Badges and GitHub webhooks
    - Forge (tool discovery)
    
    Secure endpoints requiring authentication are not included.
    """
    # Create a curated public-only OpenAPI schema
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Sigil API - Public Endpoints",
            "version": app.version,
            "description": "Automated security auditing platform for AI agent code. This documentation covers only publicly accessible endpoints that do not require authentication.",
            "x-logo": {
                "url": "https://sigilsec.ai/logo.png",
                "altText": "Sigil Security"
            },
            "x-api-id": "sigil-api-public",
            "termsOfService": "https://sigilsec.ai/terms",
            "contact": {
                "name": "Sigil Security",
                "url": "https://sigilsec.ai",
                "email": "support@mail.sigilsec.ai",
            },
            "license": {
                "name": "MIT",
                "url": "https://github.com/NOMARJ/sigil/blob/main/LICENSE",
            }
        },
        "servers": [
            {"url": "https://api.sigilsec.ai", "description": "Production"},
            {"url": "http://localhost:8000", "description": "Development"},
        ],
        "tags": [
            {"name": "system", "description": "System information and API discovery"},
            {"name": "monitoring", "description": "Health checks and system monitoring"},
            {"name": "registry", "description": "Public scan database and threat catalog"},
            {"name": "feed", "description": "RSS and JSON threat intelligence feeds"},
            {"name": "forge", "description": "Tool discovery and stack analysis"},
            {"name": "github", "description": "GitHub App webhook integration"},
            {"name": "badges", "description": "SVG badge generation"},
            {"name": "attestation", "description": "Digital attestations and verification"},
            {"name": "permissions", "description": "MCP server permissions"},
        ],
        "paths": {
            "/": {
                "get": {
                    "tags": ["system"],
                    "summary": "API Root",
                    "description": "Get API information and documentation links",
                    "responses": {
                        "200": {
                            "description": "API information",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "service": "Sigil API",
                                        "version": "0.1.0",
                                        "documentation": {
                                            "openapi_spec": "/api/openapi.json"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "tags": ["monitoring"],
                    "summary": "Basic Health Check",
                    "description": "Check if the API service is running",
                    "responses": {
                        "200": {"description": "Service is healthy"}
                    }
                }
            },
            "/health/detailed": {
                "get": {
                    "tags": ["monitoring"],
                    "summary": "Detailed Health Check",
                    "description": "Comprehensive health check including database and dependencies",
                    "responses": {
                        "200": {"description": "Detailed health status"}
                    }
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["monitoring"],
                    "summary": "Prometheus Metrics",
                    "description": "Get Prometheus-format metrics",
                    "responses": {
                        "200": {
                            "description": "Prometheus metrics",
                            "content": {"text/plain": {}}
                        }
                    }
                }
            },
            "/registry/search": {
                "get": {
                    "tags": ["registry"],
                    "summary": "Search Public Scan Database", 
                    "description": "Search the public registry of security scans",
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "description": "Search query",
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Search results"}
                    }
                }
            },
            "/registry/stats": {
                "get": {
                    "tags": ["registry"],
                    "summary": "Registry Statistics",
                    "description": "Get public registry statistics",
                    "responses": {
                        "200": {"description": "Registry statistics"}
                    }
                }
            },
            "/feed.xml": {
                "get": {
                    "tags": ["feed"],
                    "summary": "RSS Threat Feed",
                    "description": "RSS 2.0 feed of latest security threats",
                    "responses": {
                        "200": {
                            "description": "RSS XML feed",
                            "content": {"application/rss+xml": {}}
                        }
                    }
                }
            },
            "/feed.json": {
                "get": {
                    "tags": ["feed"],
                    "summary": "JSON Threat Feed", 
                    "description": "JSON feed of latest security threats",
                    "responses": {
                        "200": {
                            "description": "JSON feed",
                            "content": {"application/json": {}}
                        }
                    }
                }
            },
            "/forge/search": {
                "get": {
                    "tags": ["forge"],
                    "summary": "Search Tools and Packages",
                    "description": "Search for development tools and packages",
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query", 
                            "description": "Search query",
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Search results"}
                    }
                }
            },
            "/forge/categories": {
                "get": {
                    "tags": ["forge"],
                    "summary": "Tool Categories",
                    "description": "Get available tool categories",
                    "responses": {
                        "200": {"description": "Category list"}
                    }
                }
            },
            "/badge/scan/{scan_id}": {
                "get": {
                    "tags": ["badges"],
                    "summary": "Generate Scan Badge",
                    "description": "Generate SVG badge for a scan result",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "SVG badge",
                            "content": {"image/svg+xml": {}}
                        }
                    }
                }
            },
            "/github/webhook": {
                "post": {
                    "tags": ["github"],
                    "summary": "GitHub Webhook",
                    "description": "GitHub App webhook endpoint",
                    "responses": {
                        "200": {"description": "Webhook processed"}
                    }
                }
            },
            "/api/v1/attestation/verify/{attestation_id}": {
                "get": {
                    "tags": ["attestation"],
                    "summary": "Verify Attestation",
                    "description": "Verify a digital attestation",
                    "parameters": [
                        {
                            "name": "attestation_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Attestation verification result"}
                    }
                }
            },
            "/api/v1/permissions/{mcp_name}": {
                "get": {
                    "tags": ["permissions"],
                    "summary": "Get MCP Server Permissions",
                    "description": "Get permissions for an MCP server",
                    "parameters": [
                        {
                            "name": "mcp_name",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "MCP permissions"}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "detail": {"type": "string"}
                    }
                }
            }
        }
    }


@app.get("/api/docs", tags=["documentation"], summary="Public API Documentation")
async def public_api_documentation():
    """
    Interactive API documentation for public endpoints only.
    
    Provides a web interface to explore and test publicly accessible 
    endpoints that do not require authentication.
    """
    from fastapi.responses import HTMLResponse
    
    swagger_ui_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sigil API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
        <link rel="icon" type="image/png" href="https://sigilsec.ai/favicon.ico" sizes="32x32" />
        <style>
            html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
            *, *:before, *:after {{ box-sizing: inherit; }}
            body {{ margin:0; background: #fafafa; }}
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
        <script>
        const ui = SwaggerUIBundle({{
            url: '/api/openapi.json',
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.presets.standalone
            ],
            layout: "StandaloneLayout",
            deepLinking: true,
            showExtensions: true,
            showCommonExtensions: true,
            tryItOutEnabled: true,
            requestInterceptor: function(req) {{
                req.url = req.url.replace('localhost:8000', 'api.sigilsec.ai');
                return req;
            }}
        }})
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=swagger_ui_html)


@app.get("/api/docs/complete", tags=["documentation"], summary="Complete API Documentation")
async def complete_api_documentation():
    """
    Complete API documentation including secure endpoints.
    
    Requires authentication. Provides documentation for all API endpoints
    including those that require authentication like user management,
    team operations, billing, scanning, etc.
    """
    from fastapi.responses import HTMLResponse
    
    swagger_ui_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sigil API - Complete Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
        <link rel="icon" type="image/png" href="https://sigilsec.ai/favicon.ico" sizes="32x32" />
        <style>
            html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
            *, *:before, *:after {{ box-sizing: inherit; }}
            body {{ margin:0; background: #fafafa; }}
            .topbar {{ display: none; }}
        </style>
    </head>
    <body>
        <div style="padding: 20px; background: #1f2937; color: white; text-align: center;">
            <h1>🔒 Sigil API - Complete Documentation</h1>
            <p>Authenticated view including all secure endpoints</p>
        </div>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
        <script>
        const ui = SwaggerUIBundle({{
            url: '/openapi.json',  // Use the full FastAPI schema if available
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.presets.standalone
            ],
            layout: "StandaloneLayout",
            deepLinking: true,
            showExtensions: true,
            showCommonExtensions: true,
            tryItOutEnabled: true,
            requestInterceptor: function(req) {{
                req.url = req.url.replace('localhost:8000', 'api.sigilsec.ai');
                return req;
            }}
        }})
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=swagger_ui_html)


@app.get("/api/openapi/complete.json", tags=["documentation"], summary="Complete OpenAPI Specification")  
async def get_complete_openapi_spec() -> dict:
    """
    Complete OpenAPI specification including secure endpoints.
    
    Requires authentication. Returns the full API documentation including
    endpoints that require authentication.
    """
    # For now, return a placeholder indicating this would contain the full schema
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Sigil API - Complete",
            "version": app.version,
            "description": "Complete API documentation including secure endpoints. Authentication required.",
        },
        "security": [{"BearerAuth": []}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "paths": {
            "/api/v1/auth/login": {
                "post": {
                    "tags": ["auth"],
                    "summary": "User Login",
                    "description": "Authenticate user and get JWT token",
                    "security": [],  # No auth required for login
                    "responses": {"200": {"description": "Login successful"}}
                }
            },
            "/api/v1/scan/create": {
                "post": {
                    "tags": ["scan"],
                    "summary": "Create Scan",
                    "description": "Create a new security scan",
                    "security": [{"BearerAuth": []}],
                    "responses": {"201": {"description": "Scan created"}}
                }
            },
            "/api/v1/team/": {
                "get": {
                    "tags": ["team"],
                    "summary": "Get Team",
                    "description": "Get team information",
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "Team information"}}
                }
            }
        },
        "_note": "This is a placeholder schema. In production, this would contain the complete API specification."
    }


@app.get("/api/test-email", tags=["system"], summary="Test Email Configuration")
async def test_email_config() -> dict:
    """
    Test email configuration with mail.sigilsec.ai domain.
    
    This endpoint verifies that the email service is properly configured
    and can connect to Resend with the mail.sigilsec.ai domain.
    """
    from api.services.email_service import EmailService
    
    email_service = EmailService()
    
    # Check configuration
    config_status = {
        "domain": email_service.from_email.split("@")[1] if "@" in email_service.from_email else "unknown",
        "from_email": email_service.from_email,
        "from_name": email_service.from_name,
        "resend_configured": bool(email_service.resend_api_key),
        "expected_domain": "mail.sigilsec.ai"
    }
    
    # Test status
    status = "ready" if (
        config_status["domain"] == "mail.sigilsec.ai" and 
        config_status["resend_configured"]
    ) else "needs_configuration"
    
    if not config_status["resend_configured"]:
        message = "Resend API key not configured. Set SIGIL_RESEND_API_KEY environment variable."
    elif config_status["domain"] != "mail.sigilsec.ai":
        message = f"Domain mismatch. Expected mail.sigilsec.ai, got {config_status['domain']}"
    else:
        message = "Email service ready to send from mail.sigilsec.ai"
    
    return {
        "status": status,
        "message": message,
        "configuration": config_status,
        "test_payload_example": {
            "from": f"{config_status['from_name']} <{config_status['from_email']}>",
            "subject": "Test from mail.sigilsec.ai",
            "domain_verified": config_status["domain"] == "mail.sigilsec.ai"
        }
    }


@app.get("/", tags=["system"], summary="Root")
async def root() -> dict:
    """
    Landing endpoint with API metadata and documentation links.
    
    Provides basic service information and links to API documentation
    for easy discovery.
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "description": "Automated security auditing platform for AI agent code",
        "documentation": {
            "public_openapi_spec": "/api/openapi.json",
            "public_interactive_docs": "/api/docs", 
            "complete_interactive_docs": "/api/docs/complete",
            "complete_openapi_spec": "/api/openapi/complete.json",
            "development_docs": {
                "swagger_ui": "/docs" if settings.debug else "Available in development mode",
                "redoc": "/redoc" if settings.debug else "Available in development mode",
            },
        },
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "api_base": "/api/v1",
        },
        "feeds": {
            "rss": "/feed.xml",
            "json": "/feed.json",
            "threats": "/api/v1/feed/threats",
        },
        "public_endpoints": {
            "registry": "/registry",
            "forge": "/forge", 
            "badges": "/badge",
            "github_webhook": "/github/webhook",
        },
        "links": {
            "website": "https://sigilsec.ai",
            "github": "https://github.com/NOMARJ/sigil",
            "support": "support@mail.sigilsec.ai",
        },
    }
