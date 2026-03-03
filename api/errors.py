"""
Sigil API — Error Handling Framework

Comprehensive error handling with standardized error types, responses, 
correlation IDs, and error categorization for reliable API operations.
"""

from __future__ import annotations

import logging
import traceback
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Error Categories and Types
# ---------------------------------------------------------------------------


class ErrorCategory(str, Enum):
    """High-level categorization of errors for monitoring and alerting."""
    
    TRANSIENT = "transient"  # Temporary failures that may resolve
    PERMANENT = "permanent"  # Persistent failures requiring intervention
    USER_ERROR = "user_error"  # Client-side issues (bad input, auth)
    SYSTEM = "system"  # Infrastructure or service failures
    EXTERNAL = "external"  # Third-party service failures


class ErrorSeverity(str, Enum):
    """Error severity levels for monitoring and alerting."""
    
    LOW = "low"  # Minor issues, no user impact
    MEDIUM = "medium"  # Partial degradation
    HIGH = "high"  # Significant impact
    CRITICAL = "critical"  # Service unavailable


class ErrorCode(str, Enum):
    """Standardized error codes for programmatic handling."""
    
    # Client errors (4xx)
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    PLAN_GATE = "plan_gate"
    
    # Server errors (5xx)
    INTERNAL_ERROR = "internal_error"
    DATABASE_ERROR = "database_error"
    EXTERNAL_SERVICE_ERROR = "external_service_error"
    TIMEOUT_ERROR = "timeout_error"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    SERVICE_UNAVAILABLE = "service_unavailable"
    
    # Specific service errors
    GITHUB_API_ERROR = "github_api_error"
    CLAUDE_API_ERROR = "claude_api_error"
    REDIS_ERROR = "redis_error"
    SMTP_ERROR = "smtp_error"
    STRIPE_ERROR = "stripe_error"


# ---------------------------------------------------------------------------
# Error Response Models
# ---------------------------------------------------------------------------


class ErrorDetail(BaseModel):
    """Structured error detail for API responses."""
    
    code: ErrorCode
    message: str
    category: ErrorCategory
    severity: ErrorSeverity
    correlation_id: str
    timestamp: datetime
    retry_after: Optional[int] = None  # Seconds to wait before retry
    context: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standardized API error response format."""
    
    error: ErrorDetail
    errors: Optional[List[ErrorDetail]] = None  # For multiple errors
    request_id: Optional[str] = None
    documentation_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Error Exception Classes
# ---------------------------------------------------------------------------


class SigilError(Exception):
    """Base exception class for all Sigil errors."""
    
    def __init__(
        self,
        message: str,
        code: ErrorCode,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.category = category
        self.severity = severity
        self.context = context or {}
        self.retry_after = retry_after
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
    
    def to_error_detail(self) -> ErrorDetail:
        """Convert exception to structured error detail."""
        return ErrorDetail(
            code=self.code,
            message=self.message,
            category=self.category,
            severity=self.severity,
            correlation_id=self.correlation_id,
            timestamp=self.timestamp,
            retry_after=self.retry_after,
            context=self.context,
        )


class ValidationError(SigilError):
    """Client validation errors (400)."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code=ErrorCode.VALIDATION_ERROR,
            category=ErrorCategory.USER_ERROR,
            severity=ErrorSeverity.LOW,
            context=context,
        )


class AuthenticationError(SigilError):
    """Authentication failures (401)."""
    
    def __init__(self, message: str = "Authentication required"):
        super().__init__(
            message=message,
            code=ErrorCode.AUTHENTICATION_ERROR,
            category=ErrorCategory.USER_ERROR,
            severity=ErrorSeverity.LOW,
        )


class AuthorizationError(SigilError):
    """Authorization failures (403)."""
    
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            code=ErrorCode.AUTHORIZATION_ERROR,
            category=ErrorCategory.USER_ERROR,
            severity=ErrorSeverity.LOW,
        )


class NotFoundError(SigilError):
    """Resource not found (404)."""
    
    def __init__(self, resource: str, identifier: str = ""):
        message = f"{resource} not found"
        if identifier:
            message += f": {identifier}"
        super().__init__(
            message=message,
            code=ErrorCode.NOT_FOUND,
            category=ErrorCategory.USER_ERROR,
            severity=ErrorSeverity.LOW,
            context={"resource": resource, "identifier": identifier},
        )


class ConflictError(SigilError):
    """Resource conflict (409)."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code=ErrorCode.CONFLICT,
            category=ErrorCategory.USER_ERROR,
            severity=ErrorSeverity.LOW,
            context=context,
        )


class RateLimitError(SigilError):
    """Rate limiting (429)."""
    
    def __init__(self, retry_after: int = 60):
        super().__init__(
            message="Rate limit exceeded",
            code=ErrorCode.RATE_LIMITED,
            category=ErrorCategory.TRANSIENT,
            severity=ErrorSeverity.MEDIUM,
            retry_after=retry_after,
        )


class DatabaseError(SigilError):
    """Database operation failures."""
    
    def __init__(
        self,
        message: str = "Database operation failed",
        context: Optional[Dict[str, Any]] = None,
        is_transient: bool = True,
    ):
        category = ErrorCategory.TRANSIENT if is_transient else ErrorCategory.SYSTEM
        super().__init__(
            message=message,
            code=ErrorCode.DATABASE_ERROR,
            category=category,
            severity=ErrorSeverity.HIGH,
            context=context,
        )


class ExternalServiceError(SigilError):
    """External service failures (GitHub, Claude, etc.)."""
    
    def __init__(
        self,
        service: str,
        message: str = "External service error",
        context: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
    ):
        super().__init__(
            message=f"{service}: {message}",
            code=ErrorCode.EXTERNAL_SERVICE_ERROR,
            category=ErrorCategory.EXTERNAL,
            severity=ErrorSeverity.MEDIUM,
            context={"service": service, **(context or {})},
            retry_after=retry_after,
        )


class TimeoutError(SigilError):
    """Operation timeout failures."""
    
    def __init__(
        self,
        operation: str,
        timeout_seconds: int,
        context: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=f"Operation '{operation}' timed out after {timeout_seconds}s",
            code=ErrorCode.TIMEOUT_ERROR,
            category=ErrorCategory.TRANSIENT,
            severity=ErrorSeverity.MEDIUM,
            context={"operation": operation, "timeout": timeout_seconds, **(context or {})},
            retry_after=min(timeout_seconds * 2, 300),  # Exponential backoff, max 5 min
        )


class CircuitBreakerOpenError(SigilError):
    """Circuit breaker is open, preventing requests."""
    
    def __init__(
        self,
        service: str,
        retry_after: int = 60,
        context: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=f"Service '{service}' is temporarily unavailable (circuit breaker open)",
            code=ErrorCode.CIRCUIT_BREAKER_OPEN,
            category=ErrorCategory.TRANSIENT,
            severity=ErrorSeverity.HIGH,
            context={"service": service, **(context or {})},
            retry_after=retry_after,
        )


class ServiceUnavailableError(SigilError):
    """Service temporarily unavailable."""
    
    def __init__(
        self,
        service: str = "API",
        retry_after: int = 60,
        context: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=f"Service '{service}' is temporarily unavailable",
            code=ErrorCode.SERVICE_UNAVAILABLE,
            category=ErrorCategory.TRANSIENT,
            severity=ErrorSeverity.HIGH,
            context={"service": service, **(context or {})},
            retry_after=retry_after,
        )


# ---------------------------------------------------------------------------
# Error Tracking and Correlation
# ---------------------------------------------------------------------------


class ErrorTracker:
    """Track and correlate errors for monitoring and debugging."""
    
    def __init__(self):
        self._errors: Dict[str, List[ErrorDetail]] = {}
    
    def track_error(
        self,
        error: SigilError,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None,
    ) -> None:
        """Track an error occurrence with correlation data."""
        error_detail = error.to_error_detail()
        
        # Add correlation context
        if error_detail.context is None:
            error_detail.context = {}
        
        if request_id:
            error_detail.context["request_id"] = request_id
        if user_id:
            error_detail.context["user_id"] = user_id
        if endpoint:
            error_detail.context["endpoint"] = endpoint
        
        # Log error for monitoring
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
        }.get(error.severity, logging.ERROR)
        
        logger.log(
            log_level,
            "Error tracked: %s [%s] %s (correlation_id: %s)",
            error.code.value,
            error.category.value,
            error.message,
            error.correlation_id,
            extra={
                "error_code": error.code.value,
                "error_category": error.category.value,
                "error_severity": error.severity.value,
                "correlation_id": error.correlation_id,
                "context": error_detail.context,
            }
        )
        
        # Store for correlation analysis
        correlation_key = error.correlation_id
        if correlation_key not in self._errors:
            self._errors[correlation_key] = []
        self._errors[correlation_key].append(error_detail)
    
    def get_error_chain(self, correlation_id: str) -> List[ErrorDetail]:
        """Get all errors related to a correlation ID."""
        return self._errors.get(correlation_id, [])
    
    def cleanup_old_errors(self, max_age_hours: int = 24) -> None:
        """Clean up old error records to prevent memory leaks."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        to_remove = []
        
        for correlation_id, errors in self._errors.items():
            # Keep only recent errors
            recent_errors = [e for e in errors if e.timestamp > cutoff]
            if recent_errors:
                self._errors[correlation_id] = recent_errors
            else:
                to_remove.append(correlation_id)
        
        for correlation_id in to_remove:
            del self._errors[correlation_id]


# ---------------------------------------------------------------------------
# Error Utilities
# ---------------------------------------------------------------------------


def extract_error_context(exc: Exception) -> Dict[str, Any]:
    """Extract contextual information from an exception."""
    context = {
        "exception_type": type(exc).__name__,
        "exception_message": str(exc),
    }
    
    # Add traceback in debug mode
    import os
    if os.getenv("SIGIL_DEBUG", "").lower() in ("true", "1", "yes"):
        context["traceback"] = traceback.format_exc()
    
    # Extract specific context for known exception types
    if hasattr(exc, "__dict__"):
        for key, value in exc.__dict__.items():
            if key.startswith("_"):
                continue
            try:
                # Only add serializable values
                if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    context[f"exc_{key}"] = value
            except Exception:
                continue
    
    return context


def wrap_external_error(
    exc: Exception,
    service: str,
    operation: str = "",
    context: Optional[Dict[str, Any]] = None,
) -> SigilError:
    """Wrap external service exceptions into standardized Sigil errors."""
    error_context = extract_error_context(exc)
    if context:
        error_context.update(context)
    if operation:
        error_context["operation"] = operation
    
    message = f"{operation} failed" if operation else "Operation failed"
    if str(exc):
        message += f": {exc}"
    
    # Determine if error is likely transient
    is_transient = any(
        keyword in str(exc).lower()
        for keyword in ["timeout", "connection", "network", "temporary", "rate limit"]
    )
    
    if is_transient:
        return ExternalServiceError(
            service=service,
            message=message,
            context=error_context,
            retry_after=60,  # Default retry after 60 seconds
        )
    else:
        return ExternalServiceError(
            service=service,
            message=message,
            context=error_context,
        )


# ---------------------------------------------------------------------------
# Global Error Tracker Instance
# ---------------------------------------------------------------------------

error_tracker = ErrorTracker()