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
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

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
    threat,
    verify,
)

app.include_router(scan.router)
app.include_router(threat.router)
app.include_router(publisher.router)
app.include_router(report.router)
app.include_router(verify.router)
app.include_router(auth.router)
app.include_router(policies.router)
app.include_router(alerts.router)
app.include_router(billing.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"], summary="Health check")
async def health() -> dict:
    """Return service health status including backend connectivity."""
    return {
        "status": "ok",
        "version": settings.app_version,
        "supabase_connected": db.connected,
        "redis_connected": cache.connected,
    }


@app.get("/", tags=["system"], summary="Root")
async def root() -> dict:
    """Landing endpoint with API metadata."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
