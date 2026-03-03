"""
Sigil API — Retry Mechanisms

Implements retry patterns with exponential backoff, jitter, and intelligent
retry logic for handling transient failures in external service calls.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional, Set, Type, TypeVar, Union

from api.errors import (
    ErrorCategory,
    ExternalServiceError,
    SigilError,
    TimeoutError,
    error_tracker,
    wrap_external_error,
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ---------------------------------------------------------------------------
# Retry Configuration
# ---------------------------------------------------------------------------


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    
    # Basic retry settings
    max_attempts: int = 3
    base_delay: float = 1.0  # Initial delay in seconds
    max_delay: float = 60.0  # Maximum delay between retries
    exponential_base: float = 2.0  # Multiplier for exponential backoff
    
    # Jitter settings
    jitter: bool = True  # Add random jitter to prevent thundering herd
    jitter_ratio: float = 0.1  # Jitter as ratio of delay (0.1 = ±10%)
    
    # Timeout settings
    total_timeout: Optional[float] = None  # Total time limit for all attempts
    per_attempt_timeout: Optional[float] = None  # Timeout per individual attempt
    
    # Retry condition settings
    retryable_exceptions: Set[Type[Exception]] = field(default_factory=lambda: {
        # Network and connection errors
        ConnectionError,
        ConnectionResetError,
        ConnectionRefusedError,
        ConnectionAbortedError,
        TimeoutError,
        asyncio.TimeoutError,
        OSError,  # Includes network-related OS errors
        
        # HTTP client errors that are retryable
        # Note: Specific HTTP client libraries may have their own exception types
    })
    
    # HTTP status codes that should be retried
    retryable_status_codes: Set[int] = field(default_factory=lambda: {
        408,  # Request Timeout
        429,  # Too Many Requests (rate limit)
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
        520,  # Unknown Error (Cloudflare)
        521,  # Web Server Is Down (Cloudflare)
        522,  # Connection Timed Out (Cloudflare)
        523,  # Origin Is Unreachable (Cloudflare)
        524,  # A Timeout Occurred (Cloudflare)
    })
    
    # Keywords in error messages that indicate retryable errors
    retryable_keywords: Set[str] = field(default_factory=lambda: {
        "timeout", "connection", "network", "temporary", "rate limit",
        "throttled", "unavailable", "overloaded", "busy", "retry",
    })
    
    # Service identification
    service_name: str = "unknown"
    operation_name: str = "operation"


# ---------------------------------------------------------------------------
# Retry State Tracking
# ---------------------------------------------------------------------------


@dataclass
class RetryState:
    """Track state during retry attempts."""
    
    attempt: int = 0
    total_elapsed: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_exception: Optional[Exception] = None
    delays: List[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Retry Decision Logic
# ---------------------------------------------------------------------------


class RetryDecision:
    """Determine if an exception should be retried."""
    
    @staticmethod
    def should_retry(
        exc: Exception,
        config: RetryConfig,
        state: RetryState,
    ) -> tuple[bool, Optional[str]]:
        """
        Determine if an exception should be retried.
        
        Returns:
            Tuple of (should_retry, reason)
        """
        # Check attempt limit
        if state.attempt >= config.max_attempts:
            return False, f"Maximum attempts ({config.max_attempts}) exceeded"
        
        # Check total timeout
        if config.total_timeout and state.total_elapsed >= config.total_timeout:
            return False, f"Total timeout ({config.total_timeout}s) exceeded"
        
        # Check exception type
        if type(exc) in config.retryable_exceptions:
            return True, f"Retryable exception type: {type(exc).__name__}"
        
        # Check for wrapped Sigil errors
        if isinstance(exc, SigilError):
            if exc.category == ErrorCategory.TRANSIENT:
                return True, f"Transient Sigil error: {exc.code.value}"
            else:
                return False, f"Non-transient Sigil error: {exc.code.value}"
        
        # Check HTTP status codes (if the exception has a status code)
        status_code = getattr(exc, 'status_code', None) or getattr(exc, 'status', None)
        if status_code in config.retryable_status_codes:
            return True, f"Retryable HTTP status code: {status_code}"
        
        # Check error message for retryable keywords
        error_message = str(exc).lower()
        for keyword in config.retryable_keywords:
            if keyword in error_message:
                return True, f"Retryable keyword '{keyword}' found in error message"
        
        # Check base exception types that might be wrapped
        for exc_type in config.retryable_exceptions:
            if isinstance(exc, exc_type):
                return True, f"Instance of retryable exception: {exc_type.__name__}"
        
        # Default: don't retry
        return False, f"Non-retryable exception: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# Retry Delay Calculation
# ---------------------------------------------------------------------------


class DelayCalculator:
    """Calculate retry delays with various strategies."""
    
    @staticmethod
    def exponential_backoff(
        attempt: int,
        base_delay: float,
        exponential_base: float,
        max_delay: float,
    ) -> float:
        """Calculate delay using exponential backoff."""
        delay = base_delay * (exponential_base ** attempt)
        return min(delay, max_delay)
    
    @staticmethod
    def add_jitter(delay: float, jitter_ratio: float) -> float:
        """Add random jitter to a delay."""
        if jitter_ratio <= 0:
            return delay
        
        jitter_amount = delay * jitter_ratio
        jitter = random.uniform(-jitter_amount, jitter_amount)
        return max(0.1, delay + jitter)  # Minimum 0.1s delay
    
    @staticmethod
    def calculate_delay(config: RetryConfig, state: RetryState) -> float:
        """Calculate the next retry delay."""
        base_delay = DelayCalculator.exponential_backoff(
            attempt=state.attempt,
            base_delay=config.base_delay,
            exponential_base=config.exponential_base,
            max_delay=config.max_delay,
        )
        
        if config.jitter:
            base_delay = DelayCalculator.add_jitter(base_delay, config.jitter_ratio)
        
        return base_delay


# ---------------------------------------------------------------------------
# Retry Decorator
# ---------------------------------------------------------------------------


async def retry_with_backoff(
    func: Callable[..., Awaitable[T]],
    config: RetryConfig,
    *args: Any,
    **kwargs: Any,
) -> T:
    """
    Execute a function with retry logic and exponential backoff.
    
    Args:
        func: Async function to execute
        config: Retry configuration
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func
        
    Returns:
        Result of successful function execution
        
    Raises:
        Last exception if all retries are exhausted
    """
    state = RetryState()
    
    while True:
        state.attempt += 1
        attempt_start = time.time()
        
        try:
            # Apply per-attempt timeout if configured
            if config.per_attempt_timeout:
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=config.per_attempt_timeout,
                )
            else:
                result = await func(*args, **kwargs)
            
            # Success - log if there were previous failures
            if state.attempt > 1:
                logger.info(
                    "Retry successful for %s.%s after %d attempts (total_elapsed=%.2fs)",
                    config.service_name,
                    config.operation_name,
                    state.attempt,
                    state.total_elapsed,
                )
            
            return result
            
        except Exception as exc:
            attempt_duration = time.time() - attempt_start
            state.total_elapsed = time.time() - state.start_time
            state.last_exception = exc
            
            # Decide if we should retry
            should_retry, reason = RetryDecision.should_retry(exc, config, state)
            
            if not should_retry:
                logger.error(
                    "Retry exhausted for %s.%s: %s (attempts=%d, total_elapsed=%.2fs)",
                    config.service_name,
                    config.operation_name,
                    reason,
                    state.attempt,
                    state.total_elapsed,
                )
                
                # Track the final failure
                if isinstance(exc, SigilError):
                    error_tracker.track_error(exc)
                else:
                    wrapped_error = wrap_external_error(
                        exc,
                        service=config.service_name,
                        operation=config.operation_name,
                        context={
                            "retry_attempts": state.attempt,
                            "total_elapsed": state.total_elapsed,
                            "retry_delays": state.delays,
                        },
                    )
                    error_tracker.track_error(wrapped_error)
                
                raise exc
            
            # Calculate delay for next attempt
            delay = DelayCalculator.calculate_delay(config, state)
            state.delays.append(delay)
            
            # Check if delay would exceed total timeout
            if config.total_timeout:
                time_after_delay = state.total_elapsed + delay
                if time_after_delay > config.total_timeout:
                    remaining_time = config.total_timeout - state.total_elapsed
                    logger.error(
                        "Retry timeout for %s.%s: delay %.2fs would exceed timeout (remaining=%.2fs)",
                        config.service_name,
                        config.operation_name,
                        delay,
                        remaining_time,
                    )
                    raise exc
            
            # Log retry attempt
            logger.warning(
                "Retrying %s.%s in %.2fs: %s (attempt=%d/%d, reason=%s)",
                config.service_name,
                config.operation_name,
                delay,
                str(exc)[:100],  # Truncate long error messages
                state.attempt,
                config.max_attempts,
                reason,
            )
            
            # Wait before retry
            await asyncio.sleep(delay)


def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    jitter_ratio: float = 0.1,
    total_timeout: Optional[float] = None,
    per_attempt_timeout: Optional[float] = None,
    service_name: str = "unknown",
    operation_name: str = "operation",
    retryable_exceptions: Optional[Set[Type[Exception]]] = None,
    retryable_status_codes: Optional[Set[int]] = None,
    retryable_keywords: Optional[Set[str]] = None,
):
    """
    Decorator to add retry logic to async functions.
    
    Usage:
        @retry(max_attempts=3, service_name="github_api")
        async def fetch_repo_info(repo_url: str):
            # This function will be retried on transient failures
            pass
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            config = RetryConfig(
                max_attempts=max_attempts,
                base_delay=base_delay,
                max_delay=max_delay,
                exponential_base=exponential_base,
                jitter=jitter,
                jitter_ratio=jitter_ratio,
                total_timeout=total_timeout,
                per_attempt_timeout=per_attempt_timeout,
                service_name=service_name,
                operation_name=operation_name or func.__name__,
            )
            
            if retryable_exceptions:
                config.retryable_exceptions = retryable_exceptions
            if retryable_status_codes:
                config.retryable_status_codes = retryable_status_codes
            if retryable_keywords:
                config.retryable_keywords = retryable_keywords
            
            return await retry_with_backoff(func, config, *args, **kwargs)
        
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Predefined Retry Configurations
# ---------------------------------------------------------------------------


# GitHub API retry configuration
GITHUB_RETRY_CONFIG = RetryConfig(
    max_attempts=5,
    base_delay=2.0,
    max_delay=300.0,  # 5 minutes max
    exponential_base=2.0,
    jitter=True,
    jitter_ratio=0.2,
    total_timeout=600.0,  # 10 minutes total
    per_attempt_timeout=30.0,
    service_name="github_api",
    retryable_status_codes={403, 408, 429, 502, 503, 504},  # Include 403 for rate limits
)

# Claude API retry configuration
CLAUDE_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=60.0,
    exponential_base=2.0,
    jitter=True,
    jitter_ratio=0.1,
    total_timeout=300.0,  # 5 minutes total
    per_attempt_timeout=120.0,  # 2 minutes per attempt
    service_name="claude_api",
    retryable_status_codes={429, 502, 503, 504},
)

# Database retry configuration
DATABASE_RETRY_CONFIG = RetryConfig(
    max_attempts=5,
    base_delay=0.5,
    max_delay=10.0,  # Quick recovery for database
    exponential_base=2.0,
    jitter=True,
    jitter_ratio=0.1,
    total_timeout=30.0,  # 30 seconds total
    per_attempt_timeout=10.0,
    service_name="database",
    retryable_keywords={"connection", "timeout", "deadlock", "lock", "temporary"},
)

# Redis retry configuration
REDIS_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=0.1,
    max_delay=2.0,  # Very quick for cache
    exponential_base=2.0,
    jitter=False,  # No jitter for cache - we want fast recovery
    total_timeout=10.0,  # 10 seconds total
    per_attempt_timeout=2.0,
    service_name="redis",
)

# SMTP retry configuration
SMTP_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=5.0,
    max_delay=120.0,  # 2 minutes max
    exponential_base=2.0,
    jitter=True,
    jitter_ratio=0.2,
    total_timeout=300.0,  # 5 minutes total
    per_attempt_timeout=30.0,
    service_name="smtp",
    retryable_keywords={"temporary", "throttled", "rate limit", "busy", "unavailable"},
)

# HTTP client retry configuration (general purpose)
HTTP_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True,
    jitter_ratio=0.1,
    total_timeout=120.0,  # 2 minutes total
    per_attempt_timeout=30.0,
    service_name="http_client",
)


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------


async def retry_github_api(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Convenience function for retrying GitHub API calls."""
    return await retry_with_backoff(func, GITHUB_RETRY_CONFIG, *args, **kwargs)


async def retry_claude_api(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Convenience function for retrying Claude API calls."""
    return await retry_with_backoff(func, CLAUDE_RETRY_CONFIG, *args, **kwargs)


async def retry_database(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Convenience function for retrying database operations."""
    return await retry_with_backoff(func, DATABASE_RETRY_CONFIG, *args, **kwargs)


async def retry_redis(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Convenience function for retrying Redis operations."""
    return await retry_with_backoff(func, REDIS_RETRY_CONFIG, *args, **kwargs)


async def retry_smtp(func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
    """Convenience function for retrying SMTP operations."""
    return await retry_with_backoff(func, SMTP_RETRY_CONFIG, *args, **kwargs)


# ---------------------------------------------------------------------------
# Combined Circuit Breaker + Retry Pattern
# ---------------------------------------------------------------------------


async def call_with_circuit_breaker_and_retry(
    service_name: str,
    func: Callable[..., Awaitable[T]],
    retry_config: Optional[RetryConfig] = None,
    *args: Any,
    **kwargs: Any,
) -> T:
    """
    Call a function with both circuit breaker protection and retry logic.
    
    This provides the best of both patterns:
    - Circuit breaker prevents cascading failures
    - Retry handles transient issues within the circuit breaker
    """
    from api.circuit_breakers import circuit_registry
    
    if retry_config is None:
        # Use default retry config based on service name
        retry_configs = {
            "github_api": GITHUB_RETRY_CONFIG,
            "claude_api": CLAUDE_RETRY_CONFIG,
            "database": DATABASE_RETRY_CONFIG,
            "redis": REDIS_RETRY_CONFIG,
            "smtp": SMTP_RETRY_CONFIG,
        }
        retry_config = retry_configs.get(service_name, HTTP_RETRY_CONFIG)
        retry_config.service_name = service_name
    
    async def retry_wrapper():
        return await retry_with_backoff(func, retry_config, *args, **kwargs)
    
    return await circuit_registry.call_with_breaker(service_name, retry_wrapper)


# ---------------------------------------------------------------------------
# Decorator for Combined Protection
# ---------------------------------------------------------------------------


def protected(
    service_name: str,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
):
    """
    Decorator that combines circuit breaker and retry protection.
    
    Usage:
        @protected("github_api", max_attempts=5)
        async def fetch_repo():
            # This function is protected by both circuit breaker and retry
            pass
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            retry_config = RetryConfig(
                max_attempts=max_attempts,
                base_delay=base_delay,
                max_delay=max_delay,
                service_name=service_name,
                operation_name=func.__name__,
            )
            return await call_with_circuit_breaker_and_retry(
                service_name, func, retry_config, *args, **kwargs
            )
        return wrapper
    return decorator