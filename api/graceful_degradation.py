"""
Sigil API — Graceful Degradation Patterns

Implements graceful degradation for API endpoints to maintain functionality
even when dependent services are unavailable or degraded.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional, TypeVar

from fastapi import Request, status
from fastapi.responses import JSONResponse

from circuit_breakers import circuit_registry

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Degradation Levels and Service States
# ---------------------------------------------------------------------------


class DegradationLevel(str, Enum):
    """Levels of service degradation."""

    FULL = "full"  # Full functionality available
    REDUCED = "reduced"  # Reduced functionality, some features disabled
    MINIMAL = "minimal"  # Minimal functionality, core features only
    UNAVAILABLE = "unavailable"  # Service completely unavailable


class ServiceState(str, Enum):
    """States of dependent services."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"
    UNAVAILABLE = "unavailable"


# ---------------------------------------------------------------------------
# Service Dependency Tracking
# ---------------------------------------------------------------------------


@dataclass
class ServiceDependency:
    """Represents a service dependency and its current state."""

    name: str
    state: ServiceState = ServiceState.HEALTHY
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    failure_count: int = 0
    response_time: float = 0.0
    error_rate: float = 0.0
    is_critical: bool = True  # Whether this service is critical for operation


class DependencyTracker:
    """Tracks the health and state of service dependencies."""

    def __init__(self):
        self.dependencies: Dict[str, ServiceDependency] = {
            "database": ServiceDependency("database", is_critical=True),
            "redis": ServiceDependency("redis", is_critical=False),
            "github_api": ServiceDependency("github_api", is_critical=False),
            "claude_api": ServiceDependency("claude_api", is_critical=False),
            "smtp": ServiceDependency("smtp", is_critical=False),
        }

    def update_service_state(
        self,
        service_name: str,
        state: ServiceState,
        response_time: float = 0.0,
        error_occurred: bool = False,
    ) -> None:
        """Update the state of a service dependency."""
        if service_name not in self.dependencies:
            self.dependencies[service_name] = ServiceDependency(service_name)

        dependency = self.dependencies[service_name]
        dependency.state = state
        dependency.last_check = datetime.now(timezone.utc)
        dependency.response_time = response_time

        if error_occurred:
            dependency.failure_count += 1
        else:
            dependency.failure_count = max(0, dependency.failure_count - 1)

        # Calculate error rate (simplified)
        dependency.error_rate = min(dependency.failure_count / 10.0, 1.0)

    def get_overall_degradation_level(self) -> DegradationLevel:
        """Determine overall system degradation level based on dependencies."""
        critical_services_down = 0
        total_critical_services = 0
        non_critical_services_down = 0
        total_non_critical_services = 0

        for dependency in self.dependencies.values():
            if dependency.is_critical:
                total_critical_services += 1
                if dependency.state in (ServiceState.FAILING, ServiceState.UNAVAILABLE):
                    critical_services_down += 1
            else:
                total_non_critical_services += 1
                if dependency.state in (ServiceState.FAILING, ServiceState.UNAVAILABLE):
                    non_critical_services_down += 1

        # If any critical service is down, we're at least reduced
        if critical_services_down > 0:
            if critical_services_down == total_critical_services:
                return DegradationLevel.UNAVAILABLE
            else:
                return DegradationLevel.MINIMAL

        # If many non-critical services are down, reduce functionality
        if total_non_critical_services > 0:
            non_critical_ratio = (
                non_critical_services_down / total_non_critical_services
            )
            if non_critical_ratio > 0.7:
                return DegradationLevel.REDUCED
            elif non_critical_ratio > 0.3:
                return DegradationLevel.REDUCED

        return DegradationLevel.FULL

    def get_service_state(self, service_name: str) -> ServiceState:
        """Get the current state of a service."""
        return self.dependencies.get(
            service_name, ServiceDependency(service_name)
        ).state

    def get_health_summary(self) -> Dict[str, Any]:
        """Get a summary of all service health states."""
        return {
            "overall_degradation": self.get_overall_degradation_level().value,
            "services": {
                name: {
                    "state": dep.state.value,
                    "is_critical": dep.is_critical,
                    "failure_count": dep.failure_count,
                    "response_time": dep.response_time,
                    "error_rate": dep.error_rate,
                    "last_check": dep.last_check.isoformat(),
                }
                for name, dep in self.dependencies.items()
            },
        }


# ---------------------------------------------------------------------------
# Degraded Response Builders
# ---------------------------------------------------------------------------


class DegradedResponseBuilder:
    """Builds appropriate responses for degraded service states."""

    @staticmethod
    def scan_response_degraded(degradation_level: DegradationLevel) -> Dict[str, Any]:
        """Build a degraded response for scan endpoints."""
        if degradation_level == DegradationLevel.UNAVAILABLE:
            return {
                "error": "Service temporarily unavailable",
                "status": "unavailable",
                "message": "Unable to process scan requests at this time. Please try again later.",
                "degradation_level": degradation_level.value,
            }

        elif degradation_level == DegradationLevel.MINIMAL:
            return {
                "status": "degraded",
                "message": "Running with reduced functionality. Some scan features may be unavailable.",
                "degradation_level": degradation_level.value,
                "available_features": [
                    "basic_pattern_matching",
                    "signature_detection",
                ],
                "unavailable_features": [
                    "llm_classification",
                    "github_integration",
                    "real_time_updates",
                ],
            }

        elif degradation_level == DegradationLevel.REDUCED:
            return {
                "status": "degraded",
                "message": "Some advanced features are temporarily unavailable.",
                "degradation_level": degradation_level.value,
                "available_features": [
                    "basic_pattern_matching",
                    "signature_detection",
                    "basic_classification",
                ],
                "unavailable_features": [
                    "advanced_llm_analysis",
                    "real_time_notifications",
                ],
            }

        # FULL degradation level - no degradation info needed
        return {}

    @staticmethod
    def threat_intel_response_degraded(
        degradation_level: DegradationLevel,
    ) -> Dict[str, Any]:
        """Build a degraded response for threat intelligence endpoints."""
        if degradation_level in (
            DegradationLevel.UNAVAILABLE,
            DegradationLevel.MINIMAL,
        ):
            return {
                "threats": [],
                "status": "degraded",
                "message": "Threat intelligence data temporarily unavailable. Using cached data only.",
                "degradation_level": degradation_level.value,
                "data_staleness": "cached",
            }

        elif degradation_level == DegradationLevel.REDUCED:
            return {
                "status": "degraded",
                "message": "Threat intelligence updates may be delayed.",
                "degradation_level": degradation_level.value,
                "data_staleness": "delayed",
            }

        return {}

    @staticmethod
    def feed_response_degraded(degradation_level: DegradationLevel) -> Dict[str, Any]:
        """Build a degraded response for feed endpoints."""
        if degradation_level == DegradationLevel.UNAVAILABLE:
            return {
                "items": [],
                "status": "unavailable",
                "message": "Feed temporarily unavailable",
                "degradation_level": degradation_level.value,
            }

        # For feeds, we can always serve cached data
        return {
            "status": "degraded"
            if degradation_level != DegradationLevel.FULL
            else "ok",
            "message": "Serving cached feed data"
            if degradation_level != DegradationLevel.FULL
            else None,
            "degradation_level": degradation_level.value,
        }


# ---------------------------------------------------------------------------
# Graceful Degradation Middleware
# ---------------------------------------------------------------------------


class DegradationMiddleware:
    """Middleware to handle graceful degradation across all endpoints."""

    def __init__(self, dependency_tracker: DependencyTracker):
        self.dependency_tracker = dependency_tracker

    async def check_and_apply_degradation(
        self,
        request: Request,
        endpoint_path: str,
    ) -> Optional[JSONResponse]:
        """Check if degradation should be applied and return appropriate response."""
        degradation_level = self.dependency_tracker.get_overall_degradation_level()

        # Add degradation headers to all responses
        headers = {
            "X-Service-Degradation": degradation_level.value,
            "X-Service-Health": "degraded"
            if degradation_level != DegradationLevel.FULL
            else "healthy",
        }

        # Apply endpoint-specific degradation logic
        if degradation_level == DegradationLevel.UNAVAILABLE:
            # Most endpoints should return 503 when completely unavailable
            if not self._is_health_endpoint(endpoint_path):
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "error": "Service temporarily unavailable",
                        "message": "The service is currently experiencing technical difficulties. Please try again later.",
                        "degradation_level": degradation_level.value,
                        "retry_after": 60,
                    },
                    headers=headers,
                )

        # For other degradation levels, let the endpoint handle it
        # but add the headers
        request.state.degradation_level = degradation_level
        request.state.degradation_headers = headers

        return None

    def _is_health_endpoint(self, path: str) -> bool:
        """Check if the endpoint is a health check endpoint."""
        health_paths = ["/health", "/status", "/ping", "/ready"]
        return any(health_path in path for health_path in health_paths)


# ---------------------------------------------------------------------------
# Degradation-Aware Service Calls
# ---------------------------------------------------------------------------


async def call_with_degradation(
    service_name: str,
    operation: Callable[[], T],
    fallback: Optional[Callable[[], T]] = None,
    fallback_value: Optional[T] = None,
    dependency_tracker: Optional[DependencyTracker] = None,
) -> T:
    """
    Call a service operation with graceful degradation.

    Args:
        service_name: Name of the service being called
        operation: Function to call
        fallback: Fallback function if operation fails
        fallback_value: Static fallback value if operation fails
        dependency_tracker: Tracker to update service state

    Returns:
        Result of operation, fallback, or fallback_value
    """
    start_time = time.time()

    try:
        # Try to execute the operation with circuit breaker protection
        result = await circuit_registry.call_with_breaker(service_name, operation)

        # Update service state on success
        response_time = time.time() - start_time
        if dependency_tracker:
            dependency_tracker.update_service_state(
                service_name,
                ServiceState.HEALTHY,
                response_time=response_time,
                error_occurred=False,
            )

        return result

    except Exception as exc:
        response_time = time.time() - start_time

        # Update service state on failure
        if dependency_tracker:
            # Determine service state based on exception
            if "circuit breaker" in str(exc).lower():
                state = ServiceState.FAILING
            elif "timeout" in str(exc).lower():
                state = ServiceState.DEGRADED
            else:
                state = ServiceState.UNAVAILABLE

            dependency_tracker.update_service_state(
                service_name,
                state,
                response_time=response_time,
                error_occurred=True,
            )

        logger.warning(
            "Service %s failed (%.2fs): %s - using fallback",
            service_name,
            response_time,
            exc,
        )

        # Try fallback function
        if fallback:
            try:
                return await fallback()
            except Exception as fallback_exc:
                logger.error(
                    "Fallback for %s also failed: %s", service_name, fallback_exc
                )

        # Return fallback value if available
        if fallback_value is not None:
            return fallback_value

        # No fallback available, re-raise the original exception
        raise


# ---------------------------------------------------------------------------
# Degradation Decorators
# ---------------------------------------------------------------------------


def with_degradation(
    service_name: str,
    fallback_value: Any = None,
    fallback_response_builder: Optional[Callable] = None,
):
    """
    Decorator to add graceful degradation to endpoint functions.

    Usage:
        @with_degradation("github_api", fallback_value={"repos": []})
        async def list_repos():
            # This endpoint will gracefully degrade if GitHub API is unavailable
            pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as exc:
                # Check if this is a degradable error
                if _is_degradable_error(exc):
                    logger.warning(
                        "Endpoint %s degrading due to %s failure: %s",
                        func.__name__,
                        service_name,
                        exc,
                    )

                    # Build degraded response
                    if fallback_response_builder:
                        degradation_level = (
                            dependency_tracker.get_overall_degradation_level()
                        )
                        return fallback_response_builder(degradation_level)
                    elif fallback_value is not None:
                        return fallback_value
                    else:
                        # Return a generic degraded response
                        return {
                            "status": "degraded",
                            "message": f"Service temporarily degraded due to {service_name} unavailability",
                            "data": None,
                        }
                else:
                    # Not a degradable error, re-raise
                    raise

        return wrapper

    return decorator


def _is_degradable_error(exc: Exception) -> bool:
    """Check if an error should trigger degradation rather than failure."""
    degradable_indicators = [
        "circuit breaker",
        "timeout",
        "connection",
        "unavailable",
        "rate limit",
    ]

    error_message = str(exc).lower()
    return any(indicator in error_message for indicator in degradable_indicators)


# ---------------------------------------------------------------------------
# Cache-Based Fallbacks
# ---------------------------------------------------------------------------


class CachedFallbackManager:
    """Manages cached fallback data for degraded services."""

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
        self._cache_ttl = 3600  # 1 hour default TTL

    async def store_fallback_data(
        self,
        key: str,
        data: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """Store data that can be used as fallback during degradation."""
        self._cache[key] = data
        self._cache_timestamps[key] = datetime.now(timezone.utc)

        # Optional: Store in Redis if available
        try:
            from database import cache

            if cache.connected:
                import json

                await cache.set(
                    f"fallback:{key}",
                    json.dumps(data, default=str),
                    ttl=ttl or self._cache_ttl,
                )
        except Exception as exc:
            logger.debug("Failed to store fallback data in Redis: %s", exc)

    async def get_fallback_data(
        self,
        key: str,
        max_age: Optional[int] = None,
    ) -> Optional[Any]:
        """Retrieve cached fallback data."""
        # Check memory cache first
        if key in self._cache:
            timestamp = self._cache_timestamps.get(key)
            if timestamp and max_age:
                age = (datetime.now(timezone.utc) - timestamp).total_seconds()
                if age > max_age:
                    # Data too old, remove it
                    del self._cache[key]
                    del self._cache_timestamps[key]
                else:
                    return self._cache[key]
            elif not max_age:
                return self._cache[key]

        # Try Redis cache
        try:
            from database import cache

            if cache.connected:
                import json

                cached_data = await cache.get(f"fallback:{key}")
                if cached_data:
                    return json.loads(cached_data)
        except Exception as exc:
            logger.debug("Failed to retrieve fallback data from Redis: %s", exc)

        return None


# ---------------------------------------------------------------------------
# Global Instances
# ---------------------------------------------------------------------------

dependency_tracker = DependencyTracker()
degradation_middleware = DegradationMiddleware(dependency_tracker)
cached_fallback_manager = CachedFallbackManager()


# ---------------------------------------------------------------------------
# Health Check Integration
# ---------------------------------------------------------------------------


async def update_service_health_from_circuit_breakers():
    """Update dependency tracker based on circuit breaker states."""
    breaker_statuses = circuit_registry.get_all_status()

    for service_name, breaker_status in breaker_statuses.items():
        state = breaker_status["state"]

        if state == "closed":
            service_state = ServiceState.HEALTHY
        elif state == "half_open":
            service_state = ServiceState.DEGRADED
        else:  # open
            service_state = ServiceState.FAILING

        dependency_tracker.update_service_state(
            service_name,
            service_state,
            response_time=0.0,  # Circuit breaker doesn't track this
            error_occurred=(state == "open"),
        )


def get_degradation_health_status() -> Dict[str, Any]:
    """Get health status for degradation monitoring."""
    return {
        "degradation": dependency_tracker.get_health_summary(),
        "circuit_breakers": circuit_registry.get_all_status(),
    }
