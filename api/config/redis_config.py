"""
Redis Configuration for Trending Tools

Configuration for Redis connection pooling and caching settings
specifically for trending tools functionality.
"""

import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RedisConfig:
    """Redis configuration settings."""

    # Connection settings
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    database: int = 0

    # Connection pool settings
    max_connections: int = 20
    min_connections: int = 5
    connection_timeout: int = 10  # seconds
    socket_keepalive: bool = True

    # Cache settings for trending
    trending_ttl: int = 3600  # 1 hour
    trending_prefix: str = "forge:trending"

    # Retry settings
    retry_on_timeout: bool = True
    max_retries: int = 3
    retry_delay: float = 0.1  # seconds

    # Monitoring
    enable_metrics: bool = True
    log_slow_queries: bool = True
    slow_query_threshold: float = 0.1  # 100ms

    @classmethod
    def from_environment(cls) -> "RedisConfig":
        """Create Redis config from environment variables."""
        import os

        return cls(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=os.getenv("REDIS_PASSWORD"),
            database=int(os.getenv("REDIS_DB", "0")),
            max_connections=int(os.getenv("REDIS_MAX_CONNECTIONS", "20")),
            min_connections=int(os.getenv("REDIS_MIN_CONNECTIONS", "5")),
            connection_timeout=int(os.getenv("REDIS_CONNECTION_TIMEOUT", "10")),
            trending_ttl=int(os.getenv("TRENDING_CACHE_TTL", "3600")),
            trending_prefix=os.getenv("TRENDING_CACHE_PREFIX", "forge:trending"),
        )

    def get_redis_url(self) -> str:
        """Get Redis URL for connection."""
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.database}"
        else:
            return f"redis://{self.host}:{self.port}/{self.database}"

    def get_connection_kwargs(self) -> dict:
        """Get connection keyword arguments for redis client."""
        kwargs = {
            "host": self.host,
            "port": self.port,
            "db": self.database,
            "socket_connect_timeout": self.connection_timeout,
            "socket_keepalive": self.socket_keepalive,
            "decode_responses": True,
            "max_connections": self.max_connections,
            "retry_on_timeout": self.retry_on_timeout,
        }

        if self.password:
            kwargs["password"] = self.password

        return kwargs


class RedisConnectionManager:
    """Manages Redis connection pool for trending functionality."""

    def __init__(self, config: RedisConfig):
        self.config = config
        self.client = None
        self._pool = None
        self.logger = logging.getLogger(__name__)

    async def initialize(self) -> bool:
        """Initialize Redis connection pool."""
        try:
            import redis.asyncio as aioredis

            # Create connection pool
            self._pool = aioredis.ConnectionPool.from_url(
                self.config.get_redis_url(),
                max_connections=self.config.max_connections,
                retry_on_timeout=self.config.retry_on_timeout,
                socket_connect_timeout=self.config.connection_timeout,
                socket_keepalive=self.config.socket_keepalive,
                decode_responses=True,
            )

            # Create client
            self.client = aioredis.Redis(connection_pool=self._pool)

            # Test connection
            await self.client.ping()

            self.logger.info(
                f"Redis connection pool initialized: "
                f"{self.config.host}:{self.config.port} "
                f"(max_connections={self.config.max_connections})"
            )

            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Redis connection pool: {e}")
            return False

    async def close(self) -> None:
        """Close Redis connection pool."""
        try:
            if self.client:
                await self.client.close()
            if self._pool:
                await self._pool.disconnect()

            self.logger.info("Redis connection pool closed")

        except Exception as e:
            self.logger.warning(f"Error closing Redis connection pool: {e}")

    async def health_check(self) -> dict:
        """Perform Redis health check."""
        try:
            if not self.client:
                return {
                    "status": "disconnected",
                    "error": "No Redis client initialized",
                }

            # Test basic operations
            import time

            start_time = time.time()

            await self.client.ping()
            ping_time = (time.time() - start_time) * 1000  # Convert to ms

            # Get connection pool info
            pool_info = {
                "available_connections": self._pool.available_connections
                if self._pool
                else 0,
                "created_connections": self._pool.created_connections
                if self._pool
                else 0,
                "max_connections": self.config.max_connections,
            }

            # Get Redis server info
            info = await self.client.info("server")

            status = "healthy"
            if ping_time > self.config.slow_query_threshold * 1000:  # Convert to ms
                status = "slow"

            return {
                "status": status,
                "ping_time_ms": round(ping_time, 2),
                "pool_info": pool_info,
                "redis_version": info.get("redis_version", "unknown"),
                "uptime_seconds": info.get("uptime_in_seconds", 0),
                "config": {
                    "host": self.config.host,
                    "port": self.config.port,
                    "database": self.config.database,
                    "trending_ttl": self.config.trending_ttl,
                },
            }

        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "ping_time_ms": None}

    async def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        try:
            if not self.client:
                return {"error": "No Redis client available"}

            # Get memory usage
            memory_info = await self.client.info("memory")

            # Count trending cache keys
            trending_keys = await self.client.keys(f"{self.config.trending_prefix}:*")

            # Get key TTL info for trending keys (sample)
            ttl_info = []
            for key in trending_keys[:10]:  # Sample first 10 keys
                ttl = await self.client.ttl(key)
                ttl_info.append({"key": key, "ttl": ttl})

            return {
                "memory_used_mb": round(
                    memory_info.get("used_memory", 0) / 1024 / 1024, 2
                ),
                "memory_peak_mb": round(
                    memory_info.get("used_memory_peak", 0) / 1024 / 1024, 2
                ),
                "trending_keys_count": len(trending_keys),
                "sample_ttls": ttl_info,
                "total_keys": await self.client.dbsize(),
            }

        except Exception as e:
            return {"error": str(e)}


# Global instances (initialized in application startup)
redis_config = RedisConfig.from_environment()
redis_manager = RedisConnectionManager(redis_config)
