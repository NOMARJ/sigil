"""
Sigil API — Circuit Breaker Patterns

Implements circuit breaker patterns for external service calls to prevent
cascading failures and provide automatic recovery mechanisms.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar

from api.errors import CircuitBreakerOpenError, error_tracker

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Circuit Breaker States
# ---------------------------------------------------------------------------


class CircuitState(str, Enum):
    """Circuit breaker states following the classic pattern."""

    CLOSED = "closed"  # Normal operation, requests allowed
    OPEN = "open"  # Failing fast, requests blocked
    HALF_OPEN = "half_open"  # Testing if service has recovered


# ---------------------------------------------------------------------------
# Circuit Breaker Configuration
# ---------------------------------------------------------------------------


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker instance."""

    # Failure thresholds
    failure_threshold: int = 5  # Number of failures to trigger open
    success_threshold: int = 2  # Number of successes to close from half-open

    # Time windows
    timeout_duration: float = 60.0  # Seconds to wait in open state
    call_timeout: float = 30.0  # Timeout for individual calls

    # Monitoring window
    monitoring_window: float = 300.0  # 5 minutes sliding window
    min_calls_in_window: int = 3  # Minimum calls before considering failure rate

    # Recovery settings
    recovery_timeout: float = 10.0  # Timeout for recovery attempts in half-open
    exponential_backoff: bool = True  # Use exponential backoff for retry delay
    max_retry_delay: float = 300.0  # Maximum retry delay (5 minutes)

    # Service identification
    service_name: str = "unknown"


@dataclass
class CircuitBreakerStats:
    """Statistics and state tracking for a circuit breaker."""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    last_state_change: float = field(default_factory=time.time)

    # Call tracking for monitoring window
    call_history: list[tuple[float, bool]] = field(
        default_factory=list
    )  # (timestamp, success)

    # Exponential backoff state
    consecutive_failures: int = 0
    next_retry_time: float = 0.0


# ---------------------------------------------------------------------------
# Circuit Breaker Implementation
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """
    Circuit breaker implementation for protecting against cascading failures.

    Follows the classic circuit breaker pattern:
    - CLOSED: Normal operation, all requests pass through
    - OPEN: Failing fast, requests are blocked
    - HALF_OPEN: Limited testing to see if service has recovered
    """

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()

        logger.info(
            "Circuit breaker initialized for service '%s' with failure_threshold=%d",
            config.service_name,
            config.failure_threshold,
        )

    async def call(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Execute a function with circuit breaker protection.

        Args:
            func: Async function to call
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func

        Returns:
            Result of func execution

        Raises:
            CircuitBreakerOpenError: When circuit is open
            TimeoutError: When call exceeds timeout
            Any exception raised by func
        """
        async with self._lock:
            await self._update_state()

            if self.stats.state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(
                    service=self.config.service_name,
                    retry_after=int(self._get_retry_delay()),
                    context={
                        "failure_count": self.stats.failure_count,
                        "last_failure": self.stats.last_failure_time,
                        "next_retry": self.stats.next_retry_time,
                    },
                )

        # Execute the protected call
        start_time = time.time()
        try:
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.config.call_timeout,
            )

            # Record successful call
            await self._record_success(start_time)
            return result

        except asyncio.TimeoutError as exc:
            await self._record_failure(start_time, exc)
            raise TimeoutError(
                operation=f"{self.config.service_name}.{func.__name__}",
                timeout_seconds=int(self.config.call_timeout),
                context={"args_count": len(args), "kwargs_count": len(kwargs)},
            )

        except Exception as exc:
            await self._record_failure(start_time, exc)
            raise

    async def _update_state(self) -> None:
        """Update circuit breaker state based on current conditions."""
        now = time.time()
        current_state = self.stats.state

        if current_state == CircuitState.CLOSED:
            # Check if we should open due to too many failures
            failure_rate = self._calculate_failure_rate()
            if self.stats.failure_count >= self.config.failure_threshold or (
                failure_rate > 0.5 and self._has_sufficient_calls()
            ):
                await self._transition_to_open()

        elif current_state == CircuitState.OPEN:
            # Check if we should try half-open
            if self._should_attempt_reset(now):
                await self._transition_to_half_open()

        elif current_state == CircuitState.HALF_OPEN:
            # Check if we should close or reopen
            if self.stats.success_count >= self.config.success_threshold:
                await self._transition_to_closed()
            elif self.stats.failure_count > 0:
                await self._transition_to_open()

    async def _record_success(self, start_time: float) -> None:
        """Record a successful call."""
        now = time.time()
        duration = now - start_time

        async with self._lock:
            self.stats.success_count += 1
            self.stats.last_success_time = now
            self.stats.call_history.append((now, True))
            self.stats.consecutive_failures = 0

            # Clean old call history
            self._clean_call_history(now)

            logger.debug(
                "Circuit breaker success for %s (duration=%.2fs, success_count=%d)",
                self.config.service_name,
                duration,
                self.stats.success_count,
            )

    async def _record_failure(self, start_time: float, exc: Exception) -> None:
        """Record a failed call."""
        now = time.time()
        duration = now - start_time

        async with self._lock:
            self.stats.failure_count += 1
            self.stats.last_failure_time = now
            self.stats.call_history.append((now, False))
            self.stats.consecutive_failures += 1

            # Update exponential backoff
            if self.config.exponential_backoff:
                delay = min(
                    2**self.stats.consecutive_failures,
                    self.config.max_retry_delay,
                )
                self.stats.next_retry_time = now + delay

            # Clean old call history
            self._clean_call_history(now)

            logger.warning(
                "Circuit breaker failure for %s (duration=%.2fs, failure_count=%d, exc=%s)",
                self.config.service_name,
                duration,
                self.stats.failure_count,
                type(exc).__name__,
            )

    async def _transition_to_open(self) -> None:
        """Transition circuit breaker to OPEN state."""
        if self.stats.state != CircuitState.OPEN:
            old_state = self.stats.state
            self.stats.state = CircuitState.OPEN
            self.stats.last_state_change = time.time()

            logger.error(
                "Circuit breaker OPENED for %s (failures=%d, %s -> %s)",
                self.config.service_name,
                self.stats.failure_count,
                old_state.value,
                CircuitState.OPEN.value,
            )

            # Track this as a critical error
            error_tracker.track_error(
                CircuitBreakerOpenError(
                    service=self.config.service_name,
                    context={
                        "previous_state": old_state.value,
                        "failure_count": self.stats.failure_count,
                        "failure_rate": self._calculate_failure_rate(),
                    },
                )
            )

    async def _transition_to_half_open(self) -> None:
        """Transition circuit breaker to HALF_OPEN state."""
        old_state = self.stats.state
        self.stats.state = CircuitState.HALF_OPEN
        self.stats.last_state_change = time.time()
        self.stats.success_count = 0
        self.stats.failure_count = 0

        logger.info(
            "Circuit breaker HALF_OPEN for %s (%s -> %s)",
            self.config.service_name,
            old_state.value,
            CircuitState.HALF_OPEN.value,
        )

    async def _transition_to_closed(self) -> None:
        """Transition circuit breaker to CLOSED state."""
        old_state = self.stats.state
        self.stats.state = CircuitState.CLOSED
        self.stats.last_state_change = time.time()
        self.stats.failure_count = 0
        self.stats.success_count = 0
        self.stats.consecutive_failures = 0

        logger.info(
            "Circuit breaker CLOSED for %s (%s -> %s)",
            self.config.service_name,
            old_state.value,
            CircuitState.CLOSED.value,
        )

    def _should_attempt_reset(self, now: float) -> bool:
        """Check if circuit should attempt to reset from OPEN to HALF_OPEN."""
        if self.config.exponential_backoff:
            return now >= self.stats.next_retry_time
        else:
            return now - self.stats.last_state_change >= self.config.timeout_duration

    def _calculate_failure_rate(self) -> float:
        """Calculate failure rate within the monitoring window."""
        now = time.time()
        window_start = now - self.config.monitoring_window

        recent_calls = [
            success
            for timestamp, success in self.stats.call_history
            if timestamp >= window_start
        ]

        if len(recent_calls) < self.config.min_calls_in_window:
            return 0.0

        failures = sum(1 for success in recent_calls if not success)
        return failures / len(recent_calls)

    def _has_sufficient_calls(self) -> bool:
        """Check if we have sufficient calls to make failure rate decisions."""
        now = time.time()
        window_start = now - self.config.monitoring_window

        recent_calls = [
            timestamp
            for timestamp, _ in self.stats.call_history
            if timestamp >= window_start
        ]

        return len(recent_calls) >= self.config.min_calls_in_window

    def _get_retry_delay(self) -> float:
        """Get the delay before next retry attempt."""
        now = time.time()
        if self.config.exponential_backoff:
            return max(0, self.stats.next_retry_time - now)
        else:
            return max(
                0, self.config.timeout_duration - (now - self.stats.last_state_change)
            )

    def _clean_call_history(self, now: float) -> None:
        """Remove old calls from history to prevent memory growth."""
        cutoff = now - self.config.monitoring_window * 2  # Keep 2x window for safety
        self.stats.call_history = [
            (timestamp, success)
            for timestamp, success in self.stats.call_history
            if timestamp >= cutoff
        ]

    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status for monitoring."""
        now = time.time()
        return {
            "service_name": self.config.service_name,
            "state": self.stats.state.value,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "failure_rate": self._calculate_failure_rate(),
            "last_failure": self.stats.last_failure_time,
            "last_success": self.stats.last_success_time,
            "time_in_current_state": now - self.stats.last_state_change,
            "next_retry_in": self._get_retry_delay(),
            "call_history_size": len(self.stats.call_history),
        }


# ---------------------------------------------------------------------------
# Circuit Breaker Registry
# ---------------------------------------------------------------------------


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()

    async def get_breaker(
        self,
        service_name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        """Get or create a circuit breaker for a service."""
        async with self._lock:
            if service_name not in self._breakers:
                if config is None:
                    config = CircuitBreakerConfig(service_name=service_name)
                self._breakers[service_name] = CircuitBreaker(config)

            return self._breakers[service_name]

    async def call_with_breaker(
        self,
        service_name: str,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs: Any,
    ) -> T:
        """Convenience method to call a function with circuit breaker protection."""
        breaker = await self.get_breaker(service_name, config)
        return await breaker.call(func, *args, **kwargs)

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {name: breaker.get_status() for name, breaker in self._breakers.items()}

    async def reset_breaker(self, service_name: str) -> bool:
        """Manually reset a circuit breaker to CLOSED state."""
        async with self._lock:
            if service_name in self._breakers:
                breaker = self._breakers[service_name]
                async with breaker._lock:
                    await breaker._transition_to_closed()
                logger.info("Manually reset circuit breaker for %s", service_name)
                return True
            return False


# ---------------------------------------------------------------------------
# Predefined Circuit Breaker Configurations
# ---------------------------------------------------------------------------


# GitHub API circuit breaker - more tolerant due to rate limiting
GITHUB_CONFIG = CircuitBreakerConfig(
    service_name="github_api",
    failure_threshold=10,  # Higher threshold for rate-limited API
    success_threshold=3,
    timeout_duration=300.0,  # 5 minute timeout
    call_timeout=30.0,
    monitoring_window=600.0,  # 10 minute window
    min_calls_in_window=5,
    exponential_backoff=True,
    max_retry_delay=600.0,  # 10 minute max delay
)

# Claude API circuit breaker - standard settings
CLAUDE_CONFIG = CircuitBreakerConfig(
    service_name="claude_api",
    failure_threshold=5,
    success_threshold=2,
    timeout_duration=120.0,  # 2 minute timeout
    call_timeout=60.0,  # Longer timeout for LLM calls
    monitoring_window=300.0,
    min_calls_in_window=3,
    exponential_backoff=True,
    max_retry_delay=300.0,
)

# Database circuit breaker - fast recovery for transient issues
DATABASE_CONFIG = CircuitBreakerConfig(
    service_name="database",
    failure_threshold=3,  # Lower threshold for critical service
    success_threshold=2,
    timeout_duration=30.0,  # Quick recovery attempts
    call_timeout=10.0,  # Database should be fast
    monitoring_window=120.0,  # 2 minute window
    min_calls_in_window=2,
    exponential_backoff=False,  # Fixed retry for infrastructure
    max_retry_delay=60.0,
)

# Redis circuit breaker - very tolerant (cache failures are acceptable)
REDIS_CONFIG = CircuitBreakerConfig(
    service_name="redis",
    failure_threshold=20,  # Very high threshold - cache failures OK
    success_threshold=1,
    timeout_duration=60.0,
    call_timeout=5.0,  # Cache should be very fast
    monitoring_window=300.0,
    min_calls_in_window=10,
    exponential_backoff=False,
    max_retry_delay=60.0,
)

# SMTP circuit breaker - standard settings for notifications
SMTP_CONFIG = CircuitBreakerConfig(
    service_name="smtp",
    failure_threshold=5,
    success_threshold=2,
    timeout_duration=300.0,  # 5 minute timeout for email delays
    call_timeout=30.0,
    monitoring_window=600.0,
    min_calls_in_window=3,
    exponential_backoff=True,
    max_retry_delay=1800.0,  # 30 minute max delay
)


# ---------------------------------------------------------------------------
# Global Registry Instance
# ---------------------------------------------------------------------------

circuit_registry = CircuitBreakerRegistry()


# ---------------------------------------------------------------------------
# Decorator for Easy Circuit Breaker Usage
# ---------------------------------------------------------------------------


def circuit_protected(
    service_name: str,
    config: Optional[CircuitBreakerConfig] = None,
):
    """
    Decorator to automatically protect a function with a circuit breaker.

    Usage:
        @circuit_protected("my_service")
        async def my_function():
            # This function is now protected by a circuit breaker
            pass
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            return await circuit_registry.call_with_breaker(
                service_name, func, *args, config=config, **kwargs
            )

        return wrapper

    return decorator
