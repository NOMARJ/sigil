"""
Sigil API — Database Resilience and Recovery

Enhanced database connection management with resilience patterns, connection
pooling recovery, health monitoring, and graceful degradation.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncContextManager, Callable, Dict, Optional, TypeVar

from circuit_breakers import CircuitBreaker, CircuitBreakerConfig
from config import settings
from database import cache, db
from errors import (
    DatabaseError,
    ErrorSeverity,
    SigilError,
    error_tracker,
)
from retry import DATABASE_RETRY_CONFIG, retry_with_backoff

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Database Health and State
# ---------------------------------------------------------------------------


class DatabaseHealth(str, Enum):
    """Database connection health states."""

    HEALTHY = "healthy"  # All connections working normally
    DEGRADED = "degraded"  # Some issues but functional
    UNHEALTHY = "unhealthy"  # Significant issues
    UNAVAILABLE = "unavailable"  # Complete failure


@dataclass
class DatabaseMetrics:
    """Database connection and performance metrics."""

    # Connection metrics
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0

    # Performance metrics
    avg_query_time: float = 0.0
    total_queries: int = 0
    failed_queries: int = 0

    # Health metrics
    health_status: DatabaseHealth = DatabaseHealth.HEALTHY
    last_successful_query: Optional[datetime] = None
    last_connection_attempt: Optional[datetime] = None
    uptime_percentage: float = 100.0

    # Recovery metrics
    recovery_attempts: int = 0
    last_recovery_attempt: Optional[datetime] = None
    time_since_last_failure: Optional[float] = None


# ---------------------------------------------------------------------------
# Enhanced Database Connection Manager
# ---------------------------------------------------------------------------


class ResilientDatabaseManager:
    """Enhanced database manager with resilience patterns."""

    def __init__(self, original_client):
        self.original_client = original_client
        self.metrics = DatabaseMetrics()
        self.circuit_breaker: Optional[CircuitBreaker] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._recovery_lock = asyncio.Lock()
        self._last_health_check = 0.0
        self._connection_failures = 0
        self._max_consecutive_failures = 5

        # Setup circuit breaker for database
        self._setup_circuit_breaker()

    def _setup_circuit_breaker(self):
        """Setup circuit breaker with database-specific configuration."""
        config = CircuitBreakerConfig(
            service_name="database",
            failure_threshold=3,
            success_threshold=2,
            timeout_duration=30.0,
            call_timeout=10.0,
            monitoring_window=120.0,
            min_calls_in_window=2,
            exponential_backoff=False,
        )
        self.circuit_breaker = CircuitBreaker(config)

    async def start_health_monitoring(self):
        """Start background health monitoring."""
        if not self._health_check_task:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            logger.info("Database health monitoring started")

    async def stop_health_monitoring(self):
        """Stop background health monitoring."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
            logger.info("Database health monitoring stopped")

    async def _health_check_loop(self):
        """Background loop for database health checks."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Health check loop error: %s", exc)

    async def _perform_health_check(self):
        """Perform a database health check."""
        start_time = time.time()

        try:
            # Simple health check query
            if self.original_client._pool:
                async with self.original_client._pool.acquire() as conn:
                    cursor = await conn.cursor()
                    await cursor.execute("SELECT 1")
                    await cursor.fetchone()

                # Update metrics on success
                self.metrics.last_successful_query = datetime.now(timezone.utc)
                self._connection_failures = 0

                # Determine health status
                query_time = time.time() - start_time
                if query_time < 1.0:
                    self.metrics.health_status = DatabaseHealth.HEALTHY
                elif query_time < 5.0:
                    self.metrics.health_status = DatabaseHealth.DEGRADED
                else:
                    self.metrics.health_status = DatabaseHealth.UNHEALTHY

            else:
                # No pool available - degraded or unavailable
                if settings.database_configured:
                    self.metrics.health_status = DatabaseHealth.UNAVAILABLE
                else:
                    self.metrics.health_status = (
                        DatabaseHealth.DEGRADED
                    )  # Using memory store

        except Exception as exc:
            self._connection_failures += 1
            self.metrics.health_status = DatabaseHealth.UNHEALTHY

            logger.warning(
                "Database health check failed (%d consecutive failures): %s",
                self._connection_failures,
                exc,
            )

            # Trigger recovery if we have too many failures
            if self._connection_failures >= self._max_consecutive_failures:
                await self._attempt_recovery()

    async def _attempt_recovery(self):
        """Attempt to recover database connections."""
        async with self._recovery_lock:
            logger.warning("Attempting database connection recovery")
            self.metrics.recovery_attempts += 1
            self.metrics.last_recovery_attempt = datetime.now(timezone.utc)

            try:
                # Disconnect and reconnect
                await self.original_client.disconnect()
                await asyncio.sleep(2)  # Brief pause
                await self.original_client.connect()

                # Test the connection
                if self.original_client._pool:
                    async with self.original_client._pool.acquire() as conn:
                        cursor = await conn.cursor()
                        await cursor.execute("SELECT 1")
                        await cursor.fetchone()

                    logger.info("Database connection recovery successful")
                    self._connection_failures = 0
                    self.metrics.health_status = DatabaseHealth.HEALTHY
                else:
                    logger.warning("Database recovery failed - no pool available")
                    self.metrics.health_status = DatabaseHealth.UNAVAILABLE

            except Exception as exc:
                logger.error("Database recovery failed: %s", exc)
                self.metrics.health_status = DatabaseHealth.UNAVAILABLE

                # Track recovery failure
                error_tracker.track_error(
                    DatabaseError(
                        message=f"Database recovery failed: {exc}",
                        context={
                            "recovery_attempts": self.metrics.recovery_attempts,
                            "consecutive_failures": self._connection_failures,
                        },
                        is_transient=True,
                    )
                )

    @asynccontextmanager
    async def get_connection(self) -> AsyncContextManager[Any]:
        """Get a database connection with resilience patterns."""
        if not self.original_client._pool:
            # No pool available - check if we should attempt recovery
            if (
                settings.database_configured
                and self.metrics.health_status == DatabaseHealth.UNAVAILABLE
            ):
                await self._attempt_recovery()

            # If still no pool, this will use memory fallback in the original client
            yield None
            return

        connection = None
        start_time = time.time()

        try:
            # Use circuit breaker protection
            async def acquire_connection():
                return await self.original_client._pool.acquire()

            connection = await self.circuit_breaker.call(acquire_connection)
            self.metrics.active_connections += 1

            yield connection

            # Record successful operation
            duration = time.time() - start_time
            self._update_metrics(duration, success=True)

        except Exception as exc:
            duration = time.time() - start_time
            self._update_metrics(duration, success=False)

            # Log and track the error
            logger.error(
                "Database connection error (duration=%.2fs): %s", duration, exc
            )
            error_tracker.track_error(
                DatabaseError(
                    message=f"Database connection failed: {exc}",
                    context={
                        "duration": duration,
                        "active_connections": self.metrics.active_connections,
                        "health_status": self.metrics.health_status.value,
                    },
                    is_transient=True,
                )
            )
            raise

        finally:
            if connection:
                try:
                    connection.release()
                    self.metrics.active_connections = max(
                        0, self.metrics.active_connections - 1
                    )
                except Exception as exc:
                    logger.warning("Error releasing connection: %s", exc)

    def _update_metrics(self, duration: float, success: bool = True):
        """Update database metrics."""
        self.metrics.total_queries += 1

        if success:
            # Update average query time
            if self.metrics.total_queries == 1:
                self.metrics.avg_query_time = duration
            else:
                # Rolling average
                self.metrics.avg_query_time = (
                    self.metrics.avg_query_time * (self.metrics.total_queries - 1)
                    + duration
                ) / self.metrics.total_queries
            self.metrics.last_successful_query = datetime.now(timezone.utc)
        else:
            self.metrics.failed_queries += 1

    async def execute_with_resilience(
        self,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute a database operation with full resilience patterns."""

        async def database_operation():
            async with self.get_connection() as conn:
                if conn is None:
                    # Fallback to original client's memory store behavior
                    return await func(*args, **kwargs)
                else:
                    # Use the connection for the operation
                    return await func(conn, *args, **kwargs)

        # Apply retry logic
        return await retry_with_backoff(
            database_operation,
            DATABASE_RETRY_CONFIG,
        )

    def get_health_status(self) -> Dict[str, Any]:
        """Get current database health status."""
        now = datetime.now(timezone.utc)

        # Calculate uptime percentage
        if self.metrics.last_successful_query:
            time_since_success = (
                now - self.metrics.last_successful_query
            ).total_seconds()
            self.metrics.time_since_last_failure = time_since_success

        return {
            "health_status": self.metrics.health_status.value,
            "connected": self.original_client.connected,
            "pool_available": self.original_client._pool is not None,
            "active_connections": self.metrics.active_connections,
            "total_queries": self.metrics.total_queries,
            "failed_queries": self.metrics.failed_queries,
            "success_rate": (
                (self.metrics.total_queries - self.metrics.failed_queries)
                / self.metrics.total_queries
                * 100
                if self.metrics.total_queries > 0
                else 100.0
            ),
            "avg_query_time": self.metrics.avg_query_time,
            "last_successful_query": (
                self.metrics.last_successful_query.isoformat()
                if self.metrics.last_successful_query
                else None
            ),
            "recovery_attempts": self.metrics.recovery_attempts,
            "consecutive_failures": self._connection_failures,
            "time_since_last_failure": self.metrics.time_since_last_failure,
        }


# ---------------------------------------------------------------------------
# Enhanced Redis Client with Resilience
# ---------------------------------------------------------------------------


class ResilientRedisManager:
    """Enhanced Redis manager with resilience patterns."""

    def __init__(self, original_client):
        self.original_client = original_client
        self.metrics = DatabaseMetrics()  # Reuse metrics structure
        self.circuit_breaker: Optional[CircuitBreaker] = None
        self._recovery_lock = asyncio.Lock()
        self._connection_failures = 0
        self._max_consecutive_failures = 10  # More tolerant for cache

        # Setup circuit breaker for Redis
        self._setup_circuit_breaker()

    def _setup_circuit_breaker(self):
        """Setup circuit breaker with Redis-specific configuration."""
        config = CircuitBreakerConfig(
            service_name="redis",
            failure_threshold=10,  # Very high threshold - cache failures are OK
            success_threshold=1,
            timeout_duration=60.0,
            call_timeout=5.0,
            monitoring_window=300.0,
            min_calls_in_window=5,
            exponential_backoff=False,
        )
        self.circuit_breaker = CircuitBreaker(config)

    async def execute_with_resilience(
        self,
        func: Callable[..., Any],
        *args: Any,
        fallback_value: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Execute a Redis operation with resilience and fallback."""

        async def redis_operation():
            return await func(*args, **kwargs)

        try:
            return await self.circuit_breaker.call(redis_operation)
        except Exception as exc:
            logger.warning("Redis operation failed, using fallback: %s", exc)
            self._connection_failures += 1

            # Track error but don't let it propagate for cache operations
            error_tracker.track_error(
                SigilError(
                    message=f"Redis operation failed: {exc}",
                    code="redis_error",
                    category="transient",
                    severity=ErrorSeverity.LOW,  # Cache failures are low severity
                    context={
                        "operation": func.__name__,
                        "consecutive_failures": self._connection_failures,
                        "fallback_used": True,
                    },
                )
            )

            # Attempt recovery if too many failures
            if self._connection_failures >= self._max_consecutive_failures:
                asyncio.create_task(self._attempt_recovery())

            return fallback_value

    async def _attempt_recovery(self):
        """Attempt to recover Redis connections."""
        async with self._recovery_lock:
            logger.info("Attempting Redis connection recovery")
            self.metrics.recovery_attempts += 1

            try:
                await self.original_client.disconnect()
                await asyncio.sleep(1)
                await self.original_client.connect()

                # Test the connection
                if self.original_client.connected:
                    logger.info("Redis connection recovery successful")
                    self._connection_failures = 0

            except Exception as exc:
                logger.error("Redis recovery failed: %s", exc)

    def get_health_status(self) -> Dict[str, Any]:
        """Get current Redis health status."""
        return {
            "connected": self.original_client.connected,
            "consecutive_failures": self._connection_failures,
            "recovery_attempts": self.metrics.recovery_attempts,
            "health_status": (
                "healthy"
                if self._connection_failures < 5
                else "degraded"
                if self._connection_failures < 15
                else "unhealthy"
            ),
        }


# ---------------------------------------------------------------------------
# Database Operation Decorators
# ---------------------------------------------------------------------------


def with_database_resilience(fallback_result: Any = None):
    """Decorator to add database resilience to operations."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                # Get the resilient manager from the database client
                if hasattr(db, "_resilient_manager"):
                    return await db._resilient_manager.execute_with_resilience(
                        func, *args, **kwargs
                    )
                else:
                    return await func(*args, **kwargs)
            except Exception as exc:
                logger.error("Database operation failed: %s", exc)
                if fallback_result is not None:
                    logger.info("Using fallback result for database operation")
                    return fallback_result
                raise

        return wrapper

    return decorator


def with_redis_resilience(fallback_result: Any = None):
    """Decorator to add Redis resilience to cache operations."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                if hasattr(cache, "_resilient_manager"):
                    return await cache._resilient_manager.execute_with_resilience(
                        func, *args, fallback_value=fallback_result, **kwargs
                    )
                else:
                    return await func(*args, **kwargs)
            except Exception:
                # For cache operations, always fallback gracefully
                return fallback_result

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Initialize Enhanced Managers
# ---------------------------------------------------------------------------


def initialize_database_resilience():
    """Initialize database resilience patterns."""
    from database import db, cache

    # Add resilient managers to existing clients
    if not hasattr(db, "_resilient_manager"):
        db._resilient_manager = ResilientDatabaseManager(db)

    if not hasattr(cache, "_resilient_manager"):
        cache._resilient_manager = ResilientRedisManager(cache)

    logger.info("Database resilience patterns initialized")


async def start_database_monitoring():
    """Start database health monitoring."""
    from database import db

    if hasattr(db, "_resilient_manager"):
        await db._resilient_manager.start_health_monitoring()


async def stop_database_monitoring():
    """Stop database health monitoring."""
    from database import db

    if hasattr(db, "_resilient_manager"):
        await db._resilient_manager.stop_health_monitoring()


def get_database_health():
    """Get overall database health status."""
    from database import db, cache

    health_status = {
        "database": {
            "available": False,
            "health": "unknown",
        },
        "cache": {
            "available": False,
            "health": "unknown",
        },
    }

    if hasattr(db, "_resilient_manager"):
        health_status["database"] = {
            "available": True,
            **db._resilient_manager.get_health_status(),
        }

    if hasattr(cache, "_resilient_manager"):
        health_status["cache"] = {
            "available": True,
            **cache._resilient_manager.get_health_status(),
        }

    return health_status
