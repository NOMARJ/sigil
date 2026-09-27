"""
Sigil API — Distributed Rate Limiting

Provides two mechanisms:

1. ``RateLimiter`` — A FastAPI dependency (``Depends()``) for per-endpoint
   rate limits.  Each endpoint can specify its own max requests and window.

2. ``RateLimitMiddleware`` — A Starlette middleware for global per-IP rate
   limiting applied to every request.

Both use Redis via the ``cache`` singleton for distributed counting that
works across multiple API instances.  When Redis is unavailable they fall
back to in-memory counters (via RedisClient internals).
"""

# NOTE: Do NOT add `from __future__ import annotations` to this module.
# RateLimiter is used as a class-instance dependency (`Depends(RateLimiter(...))`).
# FastAPI resolves a callable's annotations via `getattr(call, "__globals__", {})`,
# but an *instance* has no `__globals__`, so a stringised `request: "Request"`
# forward ref would resolve against an empty namespace and stay a ForwardRef.
# FastAPI then fails to recognise the special `Request` param, treats it as a
# required query parameter, and every rate-limited endpoint returns 422.
# Keeping annotations eager makes `request: Request` a real class object.

import logging
import os
import time
from typing import Optional

from fastapi import HTTPException, Request, status
from api.middleware.security import SecurityHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from api.database import cache

logger = logging.getLogger(__name__)


def _should_bypass_during_pytest() -> bool:
    current = os.getenv("PYTEST_CURRENT_TEST", "")
    if not current:
        return False
    return "TestRateLimiting" not in current


def _client_ip(request: Request) -> str:
    """Resolve the real client IP behind Container Apps ingress.

    The ingress proxy connects from loopback, so ``request.client.host`` is
    the same for every caller and all traffic would share one rate-limit
    bucket. The ingress appends the caller's IP to X-Forwarded-For; take the
    last entry (the hop added by the trusted proxy — earlier entries are
    client-supplied and spoofable).
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Per-endpoint rate limiter (FastAPI dependency)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Configurable rate limiter usable as a FastAPI dependency.

    Usage::

        from api.rate_limit import RateLimiter

        @router.get("/expensive", dependencies=[Depends(RateLimiter(max_requests=20, window=60))])
        async def expensive_endpoint(): ...

    Args:
        max_requests: Maximum number of requests allowed within the window.
        window: Time window in seconds.
        key_prefix: Optional prefix for the Redis key (defaults to the route path).
    """

    def __init__(
        self,
        max_requests: int = 60,
        window: int = 60,
        key_prefix: Optional[str] = None,
    ) -> None:
        self.max_requests = max_requests
        self.window = window
        self.key_prefix = key_prefix

    async def __call__(self, request: Request) -> None:
        if _should_bypass_during_pytest():
            return

        client_ip = _client_ip(request)
        prefix = self.key_prefix or request.url.path
        key = f"ratelimit:{prefix}:{client_ip}"

        count = await cache.incr(key, ttl=self.window)
        if count > self.max_requests:
            logger.warning(
                "Rate limit exceeded: %s on %s (%d/%d in %ds)",
                client_ip,
                prefix,
                count,
                self.max_requests,
                self.window,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window}s.",
            )


# ---------------------------------------------------------------------------
# Global rate-limiting middleware
# ---------------------------------------------------------------------------

# Defaults — generous enough for normal usage, tight enough to block abuse
_GLOBAL_MAX_REQUESTS = 200  # per IP
_GLOBAL_WINDOW = 60  # seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global per-IP rate limiter applied to every inbound request.

    Skips health-check endpoints to avoid noise from load balancer probes.
    """

    def __init__(
        self,
        app,
        max_requests: int = _GLOBAL_MAX_REQUESTS,
        window: int = _GLOBAL_WINDOW,
    ) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window

    async def dispatch(self, request: Request, call_next):
        # Disable rate limiting for pytest to avoid cross-test throttling
        if _should_bypass_during_pytest():
            return await call_next(request)

        # Never throttle infra health probes or root: a 429 here fails the
        # container's liveness probe and puts the app in a restart loop.
        if request.url.path == "/" or request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = _client_ip(request)
        key = f"ratelimit:global:{client_ip}"

        count = await cache.incr(key, ttl=self.window)
        if count > self.max_requests:
            logger.warning(
                "Global rate limit exceeded: %s (%d/%d)",
                client_ip,
                count,
                self.max_requests,
            )
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": f"Rate limit exceeded. Max {self.max_requests} requests per {self.window}s."
                },
            )
            SecurityHeaders.apply(response, is_production=not os.getenv("SIGIL_DEBUG"))
            return response

        response = await call_next(request)

        # Add standard rate-limit headers so clients can self-throttle
        remaining = max(0, self.max_requests - count)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.window)

        return response
