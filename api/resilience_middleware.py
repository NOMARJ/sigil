"""
Sigil API — Resilience Middleware

Integrates all resilience patterns (error handling, circuit breakers, retry,
graceful degradation, monitoring) into FastAPI middleware for comprehensive
error handling across the entire application.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from circuit_breakers import CircuitBreakerOpenError
from errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DatabaseError,
    ErrorResponse,
    NotFoundError,
    RateLimitError,
    SigilError,
    TimeoutError,
    ValidationError,
    error_tracker,
)
from graceful_degradation import (
    DegradationLevel,
    dependency_tracker,
    degradation_middleware,
    update_service_health_from_circuit_breakers,
)
from monitoring import (
    AlertLevel,
    alert_manager,
    metrics_collector,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enhanced Error Handling Middleware
# ---------------------------------------------------------------------------


class ResilienceMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive resilience middleware that handles:
    - Error tracking and correlation
    - Graceful degradation
    - Circuit breaker integration
    - Monitoring and alerting
    - Standardized error responses
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process requests with full resilience patterns."""
        # Generate unique request ID for correlation
        request_id = str(uuid.uuid4())
        correlation_id = request.headers.get("X-Correlation-ID") or request_id

        # Add to request state
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        request.state.start_time = time.time()

        # Extract user ID if available
        user_id = getattr(request.state, "user_id", None)

        try:
            # Update service health from circuit breakers
            await update_service_health_from_circuit_breakers()

            # Check for degradation and apply if needed
            degradation_response = (
                await degradation_middleware.check_and_apply_degradation(
                    request, str(request.url.path)
                )
            )
            if degradation_response:
                return degradation_response

            # Process the request
            response = await call_next(request)

            # Record successful request metrics
            duration = time.time() - request.state.start_time
            self._record_request_metrics(request, response, duration, success=True)

            # Add resilience headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Correlation-ID"] = correlation_id

            # Add degradation headers if available
            degradation_headers = getattr(request.state, "degradation_headers", {})
            for key, value in degradation_headers.items():
                response.headers[key] = value

            return response

        except Exception as exc:
            # Handle the error with full resilience patterns
            return await self._handle_error(
                request, exc, request_id, correlation_id, user_id
            )

    async def _handle_error(
        self,
        request: Request,
        exc: Exception,
        request_id: str,
        correlation_id: str,
        user_id: str = None,
    ) -> JSONResponse:
        """Handle errors with comprehensive error management."""
        duration = time.time() - getattr(request.state, "start_time", time.time())
        endpoint = str(request.url.path)

        # Convert exception to standardized error
        if isinstance(exc, SigilError):
            error = exc
        else:
            error = self._convert_exception_to_sigil_error(exc)

        # Track the error
        error_tracker.track_error(
            error,
            request_id=request_id,
            user_id=user_id,
            endpoint=endpoint,
        )

        # Record error metrics
        self._record_request_metrics(
            request, None, duration, success=False, error=error
        )

        # Check if we should trigger alerts
        await self._check_error_alerts(error, endpoint)

        # Build error response
        error_response = self._build_error_response(
            error,
            request_id,
            correlation_id,
            endpoint,
        )

        # Determine HTTP status code
        status_code = self._get_http_status_code(error)

        # Log the error
        log_level = (
            logging.ERROR
            if error.severity.value in ("high", "critical")
            else logging.WARNING
        )
        logger.log(
            log_level,
            "Request error: %s %s -> %d %s (duration=%.2fs, correlation_id=%s)",
            request.method,
            endpoint,
            status_code,
            error.code.value,
            duration,
            correlation_id,
            exc_info=exc if log_level == logging.ERROR else None,
        )

        return JSONResponse(
            status_code=status_code,
            content=error_response.model_dump(),
            headers={
                "X-Request-ID": request_id,
                "X-Correlation-ID": correlation_id,
                "X-Error-Code": error.code.value,
                "X-Error-Category": error.category.value,
                "X-Error-Severity": error.severity.value,
            },
        )

    def _convert_exception_to_sigil_error(self, exc: Exception) -> SigilError:
        """Convert various exception types to standardized SigilError."""

        # FastAPI/Pydantic validation errors
        if hasattr(exc, "detail") and isinstance(exc.detail, list):
            return ValidationError(
                message="Validation failed", context={"validation_errors": exc.detail}
            )

        # HTTP exceptions
        if hasattr(exc, "status_code"):
            status_code = exc.status_code
            if status_code == 401:
                return AuthenticationError()
            elif status_code == 403:
                return AuthorizationError()
            elif status_code == 404:
                return NotFoundError("Resource", "")
            elif status_code == 409:
                return ConflictError(str(exc))
            elif status_code == 429:
                return RateLimitError()

        # Timeout errors
        if isinstance(exc, asyncio.TimeoutError) or "timeout" in str(exc).lower():
            return TimeoutError(
                operation="request_processing",
                timeout_seconds=30,  # Default timeout
                context={"original_exception": str(exc)},
            )

        # Circuit breaker errors
        if isinstance(exc, CircuitBreakerOpenError):
            return exc

        # Database errors
        if any(
            keyword in str(exc).lower() for keyword in ["database", "connection", "sql"]
        ):
            return DatabaseError(
                message=f"Database operation failed: {exc}",
                context={"original_exception": str(exc)},
                is_transient=True,
            )

        # Generic error fallback
        from errors import ErrorCode, ErrorCategory, ErrorSeverity

        return SigilError(
            message=f"Internal server error: {exc}",
            code=ErrorCode.INTERNAL_ERROR,
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.HIGH,
            context={
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
            },
        )

    def _build_error_response(
        self,
        error: SigilError,
        request_id: str,
        correlation_id: str,
        endpoint: str,
    ) -> ErrorResponse:
        """Build standardized error response."""
        error_detail = error.to_error_detail()

        # Add context
        if error_detail.context is None:
            error_detail.context = {}

        error_detail.context.update(
            {
                "endpoint": endpoint,
                "request_id": request_id,
            }
        )

        return ErrorResponse(
            error=error_detail,
            request_id=request_id,
            documentation_url="https://docs.sigilsec.ai/errors",  # Optional docs URL
        )

    def _get_http_status_code(self, error: SigilError) -> int:
        """Map error codes to HTTP status codes."""
        status_map = {
            "validation_error": status.HTTP_400_BAD_REQUEST,
            "authentication_error": status.HTTP_401_UNAUTHORIZED,
            "authorization_error": status.HTTP_403_FORBIDDEN,
            "not_found": status.HTTP_404_NOT_FOUND,
            "conflict": status.HTTP_409_CONFLICT,
            "rate_limited": status.HTTP_429_TOO_MANY_REQUESTS,
            "plan_gate": status.HTTP_403_FORBIDDEN,
            "timeout_error": status.HTTP_408_REQUEST_TIMEOUT,
            "circuit_breaker_open": status.HTTP_503_SERVICE_UNAVAILABLE,
            "service_unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
            "database_error": status.HTTP_503_SERVICE_UNAVAILABLE,
            "external_service_error": status.HTTP_502_BAD_GATEWAY,
        }

        return status_map.get(error.code.value, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _record_request_metrics(
        self,
        request: Request,
        response: Response = None,
        duration: float = 0.0,
        success: bool = True,
        error: SigilError = None,
    ):
        """Record request metrics for monitoring."""
        endpoint = str(request.url.path)
        method = request.method

        # Record response time
        labels = {
            "method": method,
            "endpoint": endpoint,
            "status": "success" if success else "error",
        }

        if response:
            labels["status_code"] = str(response.status_code)
        elif error:
            labels["error_code"] = error.code.value
            labels["error_category"] = error.category.value

        metrics_collector.record_histogram("request_duration", duration, labels)
        metrics_collector.record_counter("requests_total", labels)

        if not success and error:
            metrics_collector.record_counter(
                "errors_total",
                {
                    "error_code": error.code.value,
                    "error_category": error.category.value,
                    "error_severity": error.severity.value,
                },
            )

    async def _check_error_alerts(self, error: SigilError, endpoint: str):
        """Check if error should trigger alerts."""
        # High severity errors always trigger alerts
        if error.severity.value == "high":
            await alert_manager.raise_alert(
                title=f"High Severity Error: {error.code.value}",
                message=f"Error on {endpoint}: {error.message}",
                level=AlertLevel.WARNING,
                source="error_handler",
                labels={
                    "error_code": error.code.value,
                    "endpoint": endpoint,
                    "category": error.category.value,
                },
            )
        elif error.severity.value == "critical":
            await alert_manager.raise_alert(
                title=f"Critical Error: {error.code.value}",
                message=f"Critical error on {endpoint}: {error.message}",
                level=AlertLevel.CRITICAL,
                source="error_handler",
                labels={
                    "error_code": error.code.value,
                    "endpoint": endpoint,
                    "category": error.category.value,
                },
            )


# ---------------------------------------------------------------------------
# Health Check Enhancement
# ---------------------------------------------------------------------------


async def enhanced_health_check() -> dict:
    """Enhanced health check that includes all resilience components."""
    from background_job_resilience import job_queue
    from circuit_breakers import circuit_registry
    from database_resilience import get_database_health
    from graceful_degradation import get_degradation_health_status
    from monitoring import get_monitoring_status

    health_data = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",  # Should come from config
        "components": {},
        "resilience": {},
    }

    overall_healthy = True

    # Database health
    try:
        db_health = get_database_health()
        health_data["components"]["database"] = db_health["database"]
        health_data["components"]["cache"] = db_health["cache"]

        if (
            not db_health["database"].get("available")
            or db_health["database"].get("health_status") == "unavailable"
        ):
            overall_healthy = False
    except Exception as exc:
        health_data["components"]["database"] = {"error": str(exc)}
        overall_healthy = False

    # Circuit breakers
    try:
        breaker_status = circuit_registry.get_all_status()
        health_data["resilience"]["circuit_breakers"] = breaker_status

        open_breakers = sum(
            1 for status in breaker_status.values() if status["state"] == "open"
        )
        if open_breakers > 0:
            overall_healthy = False
    except Exception as exc:
        health_data["resilience"]["circuit_breakers"] = {"error": str(exc)}

    # Job queue health
    try:
        queue_stats = job_queue.get_queue_stats()
        health_data["components"]["job_queue"] = queue_stats

        if queue_stats.get("dead_letter_jobs", 0) > 20:  # Too many failed jobs
            overall_healthy = False
    except Exception as exc:
        health_data["components"]["job_queue"] = {"error": str(exc)}

    # Degradation status
    try:
        degradation_status = get_degradation_health_status()
        health_data["resilience"]["degradation"] = degradation_status

        overall_degradation = dependency_tracker.get_overall_degradation_level()
        if overall_degradation == DegradationLevel.UNAVAILABLE:
            overall_healthy = False
    except Exception as exc:
        health_data["resilience"]["degradation"] = {"error": str(exc)}

    # Monitoring status
    try:
        monitoring_status = get_monitoring_status()
        health_data["resilience"]["monitoring"] = monitoring_status
    except Exception as exc:
        health_data["resilience"]["monitoring"] = {"error": str(exc)}

    # Error tracking summary
    try:
        error_summary = {
            "total_tracked_errors": len(error_tracker._errors),
            "error_categories": {},
        }

        for errors in error_tracker._errors.values():
            for error in errors:
                category = error.category.value
                error_summary["error_categories"][category] = (
                    error_summary["error_categories"].get(category, 0) + 1
                )

        health_data["resilience"]["errors"] = error_summary
    except Exception as exc:
        health_data["resilience"]["errors"] = {"error": str(exc)}

    # Set overall status
    if not overall_healthy:
        health_data["status"] = "degraded"

    # Check if we're completely unavailable
    critical_components_down = 0
    if not health_data["components"].get("database", {}).get("available"):
        critical_components_down += 1

    if critical_components_down > 0:
        health_data["status"] = "unhealthy"

    return health_data


# ---------------------------------------------------------------------------
# Startup Integration
# ---------------------------------------------------------------------------


async def initialize_resilience_systems():
    """Initialize all resilience systems during application startup."""
    logger.info("Initializing resilience systems...")

    # Initialize database resilience
    from database_resilience import (
        initialize_database_resilience,
        start_database_monitoring,
    )

    initialize_database_resilience()
    await start_database_monitoring()

    # Start background job system
    from background_job_resilience import start_background_jobs

    await start_background_jobs()

    # Start monitoring
    from monitoring import start_monitoring

    await start_monitoring()

    logger.info("Resilience systems initialized successfully")


async def shutdown_resilience_systems():
    """Shutdown all resilience systems during application shutdown."""
    logger.info("Shutting down resilience systems...")

    # Stop monitoring
    from monitoring import stop_monitoring

    await stop_monitoring()

    # Stop background jobs
    from background_job_resilience import stop_background_jobs

    await stop_background_jobs()

    # Stop database monitoring
    from database_resilience import stop_database_monitoring

    await stop_database_monitoring()

    logger.info("Resilience systems shutdown complete")


# ---------------------------------------------------------------------------
# Recovery Endpoint
# ---------------------------------------------------------------------------


async def trigger_system_recovery():
    """Manually trigger system recovery procedures."""
    logger.info("Triggering system recovery...")

    recovery_results = {}

    # Reset circuit breakers
    try:
        from circuit_breakers import circuit_registry

        breaker_statuses = circuit_registry.get_all_status()
        reset_count = 0

        for service_name, status in breaker_statuses.items():
            if status["state"] == "open":
                if await circuit_registry.reset_breaker(service_name):
                    reset_count += 1

        recovery_results["circuit_breakers"] = {
            "reset_count": reset_count,
            "status": "success",
        }
    except Exception as exc:
        recovery_results["circuit_breakers"] = {
            "status": "error",
            "error": str(exc),
        }

    # Trigger database recovery
    try:
        from database_resilience import get_database_health
        from database import db

        if hasattr(db, "_resilient_manager"):
            await db._resilient_manager._attempt_recovery()

        recovery_results["database"] = {
            "status": "attempted",
            "health": get_database_health(),
        }
    except Exception as exc:
        recovery_results["database"] = {
            "status": "error",
            "error": str(exc),
        }

    # Clean up error tracking
    try:
        error_tracker.cleanup_old_errors(
            max_age_hours=1
        )  # Clean errors older than 1 hour
        recovery_results["error_tracking"] = {
            "status": "cleaned",
            "remaining_errors": len(error_tracker._errors),
        }
    except Exception as exc:
        recovery_results["error_tracking"] = {
            "status": "error",
            "error": str(exc),
        }

    logger.info("System recovery completed: %s", recovery_results)
    return recovery_results
