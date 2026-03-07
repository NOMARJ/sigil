"""
Sigil API — Enhanced Rate Limiting

Tiered rate limiting with different limits for different operations.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Dict, Optional, Tuple

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from middleware.security import SecurityHeaders

logger = logging.getLogger(__name__)


def _should_bypass_during_pytest() -> bool:
    current = os.getenv("PYTEST_CURRENT_TEST", "")
    if not current:
        return False
    return "TestRateLimiting" not in current


class RateLimitTier:
    """Rate limit configuration for different operation tiers."""

    # Tier configurations: (requests_per_minute, burst_size)
    STRICT = (10, 15)  # Expensive operations (scans, AI analysis)
    MODERATE = (30, 40)  # Standard operations (queries, lookups)
    RELAXED = (60, 80)  # Read-only operations (feeds, badges)
    PUBLIC = (100, 120)  # Public endpoints (RSS, static content)

    # Endpoint to tier mapping
    ENDPOINT_TIERS = {
        # Strict tier - expensive operations
        "/api/v1/scan": STRICT,
        "/api/v1/scan/": STRICT,
        "/forge/": STRICT,
        "/api/v1/threat/": STRICT,
        # Moderate tier - standard operations
        "/api/v1/publisher": MODERATE,
        "/api/v1/registry": MODERATE,
        "/permissions/": MODERATE,
        "/api/v1/permissions/": MODERATE,
        # Relaxed tier - read operations
        "/api/v1/feed": RELAXED,
        "/api/v1/feed/": RELAXED,
        "/v1/scans": RELAXED,
        "/badge/": RELAXED,
        # Public tier - RSS feeds and static content
        "/feed.xml": PUBLIC,
        "/feed/": PUBLIC,
    }

    @classmethod
    def get_tier_for_endpoint(cls, path: str) -> Tuple[int, int]:
        """Get rate limit tier for an endpoint."""
        # Check exact matches first
        for endpoint_prefix, tier in cls.ENDPOINT_TIERS.items():
            if path.startswith(endpoint_prefix):
                return tier

        # Default to moderate tier
        return cls.MODERATE


class TokenBucket:
    """Token bucket algorithm for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket."""
        now = time.time()

        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def time_until_token(self) -> float:
        """Time in seconds until next token is available."""
        if self.tokens >= 1:
            return 0
        return (1 - self.tokens) / self.refill_rate


class EnhancedRateLimitMiddleware(BaseHTTPMiddleware):
    """Enhanced rate limiting with tiered limits and distributed tracking."""

    def __init__(self, app, redis_client=None):
        super().__init__(app)
        self.redis_client = redis_client
        self.local_buckets: Dict[str, TokenBucket] = {}
        self.cleanup_counter = 0

    def get_client_id(self, request: Request) -> str:
        """Get unique client identifier from request."""
        # Try to get real IP from headers (for reverse proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

        # Add user agent to the mix for better fingerprinting
        user_agent = request.headers.get("User-Agent", "")

        # Create a hash of IP + User-Agent for the client ID
        client_string = f"{client_ip}:{user_agent}"
        client_hash = hashlib.md5(client_string.encode()).hexdigest()[:16]

        return f"rl:{client_hash}"

    async def check_rate_limit_redis(
        self, client_id: str, endpoint: str, limit: int, window: int = 60
    ) -> Tuple[bool, Optional[int]]:
        """Check rate limit using Redis (distributed)."""
        if not self.redis_client:
            return True, None

        try:
            key = f"{client_id}:{endpoint}"

            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            now = int(time.time())
            window_start = now - window

            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)

            # Count requests in current window
            pipe.zcard(key)

            # Add current request
            pipe.zadd(key, {str(now): now})

            # Set expiry
            pipe.expire(key, window + 1)

            results = await pipe.execute()
            request_count = results[1]

            if request_count >= limit:
                # Calculate retry-after
                oldest_request = await self.redis_client.zrange(
                    key, 0, 0, withscores=True
                )
                if oldest_request:
                    retry_after = int(window - (now - oldest_request[0][1]))
                    return False, retry_after
                return False, window

            return True, None

        except Exception as e:
            logger.error("Redis rate limit check failed: %s", e)
            # Fall back to allowing the request on Redis failure
            return True, None

    def check_rate_limit_local(
        self, client_id: str, endpoint: str, requests_per_minute: int, burst_size: int
    ) -> Tuple[bool, Optional[float]]:
        """Check rate limit using local token bucket (fallback)."""
        bucket_key = f"{client_id}:{endpoint}"

        # Get or create bucket
        if bucket_key not in self.local_buckets:
            refill_rate = requests_per_minute / 60.0  # tokens per second
            self.local_buckets[bucket_key] = TokenBucket(burst_size, refill_rate)

        bucket = self.local_buckets[bucket_key]

        # Try to consume a token
        if bucket.consume():
            return True, None

        # Calculate retry-after
        retry_after = bucket.time_until_token()
        return False, retry_after

    async def dispatch(self, request: Request, call_next):
        # Disable rate limiting for pytest to avoid cross-test throttling
        if _should_bypass_during_pytest():
            return await call_next(request)

        # Skip rate limiting for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)

        # Skip core health/metrics probes except during explicit rate-limit tests
        if (
            request.url.path
            in {
                "/",
                "/health",
                "/health/detailed",
                "/health/ready",
                "/health/live",
                "/metrics",
            }
            and _should_bypass_during_pytest()
        ):
            return await call_next(request)

        # Get client ID and endpoint
        client_id = self.get_client_id(request)
        endpoint = request.url.path

        # Get tier for this endpoint
        requests_per_minute, burst_size = RateLimitTier.get_tier_for_endpoint(endpoint)

        # Check rate limit (prefer Redis for distributed limiting)
        if self.redis_client:
            allowed, retry_after = await self.check_rate_limit_redis(
                client_id, endpoint, requests_per_minute, 60
            )
        else:
            allowed, retry_after = self.check_rate_limit_local(
                client_id, endpoint, requests_per_minute, burst_size
            )

        if not allowed:
            # Clean up old local buckets periodically
            self.cleanup_counter += 1
            if self.cleanup_counter > 1000:
                self._cleanup_old_buckets()
                self.cleanup_counter = 0

            # Return rate limit error
            headers = {
                "X-RateLimit-Limit": str(requests_per_minute),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + (retry_after or 60)),
            }
            if retry_after:
                headers["Retry-After"] = str(int(retry_after))

            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after,
                },
                headers=headers,
            )
            SecurityHeaders.apply(response, is_production=not os.getenv("SIGIL_DEBUG"))
            return response

        # Add rate limit headers to response
        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(requests_per_minute)
        # Note: Accurate remaining count would require another Redis call
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)

        return response

    def _cleanup_old_buckets(self):
        """Remove old token buckets to prevent memory leak."""
        current_time = time.time()
        cutoff_time = current_time - 300  # Remove buckets unused for 5 minutes

        keys_to_remove = []
        for key, bucket in self.local_buckets.items():
            if bucket.last_refill < cutoff_time:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.local_buckets[key]

        if keys_to_remove:
            logger.debug("Cleaned up %d old rate limit buckets", len(keys_to_remove))
