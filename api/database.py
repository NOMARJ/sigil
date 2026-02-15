"""
Sigil API — Database & Cache Connections

Provides async-friendly wrappers around Supabase and Redis.  Both are
optional — the service degrades gracefully when they are not configured,
falling back to in-memory stores so development/testing can proceed without
external infrastructure.
"""

from __future__ import annotations

import logging
from typing import Any

from api.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory fallback stores (used when external backends are unavailable)
# ---------------------------------------------------------------------------
_memory_store: dict[str, dict[str, Any]] = {}
_memory_cache: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Supabase wrapper
# ---------------------------------------------------------------------------

class SupabaseClient:
    """Thin wrapper around the Supabase Python client.

    Falls back to a simple in-memory dict when Supabase is not configured so
    that endpoint logic never needs to branch on availability.
    """

    def __init__(self) -> None:
        self._client: Any | None = None
        self._connected = False

    async def connect(self) -> None:
        """Initialise the Supabase connection (if configured)."""
        if not settings.supabase_configured:
            logger.warning(
                "Supabase not configured — using in-memory store. "
                "Set SIGIL_SUPABASE_URL and SIGIL_SUPABASE_KEY to enable."
            )
            return

        try:
            from supabase import create_client

            self._client = create_client(settings.supabase_url, settings.supabase_key)
            self._connected = True
            logger.info("Supabase client connected.")
        except Exception:
            logger.exception("Failed to connect to Supabase — falling back to in-memory store.")
            self._client = None
            self._connected = False

    async def disconnect(self) -> None:
        """Clean up the Supabase connection."""
        self._client = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    # -- CRUD helpers -------------------------------------------------------

    async def insert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        """Insert a row into *table*.  Returns the row dict."""
        if self._connected and self._client is not None:
            try:
                result = self._client.table(table).insert(data).execute()
                if result.data:
                    return result.data[0]
            except Exception:
                logger.exception("Supabase insert failed for table '%s'", table)

        # Fallback: in-memory
        _memory_store.setdefault(table, {})[data.get("id", str(len(_memory_store.get(table, {}))))] = data
        return data

    async def select(
        self,
        table: str,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Select rows from *table* with optional equality filters."""
        if self._connected and self._client is not None:
            try:
                query = self._client.table(table).select("*")
                for col, val in (filters or {}).items():
                    query = query.eq(col, val)
                result = query.limit(limit).execute()
                return result.data or []
            except Exception:
                logger.exception("Supabase select failed for table '%s'", table)

        # Fallback: in-memory
        rows = list(_memory_store.get(table, {}).values())
        if filters:
            rows = [
                r for r in rows
                if all(r.get(k) == v for k, v in filters.items())
            ]
        return rows[:limit]

    async def select_one(self, table: str, filters: dict[str, Any]) -> dict[str, Any] | None:
        """Return the first matching row or ``None``."""
        rows = await self.select(table, filters, limit=1)
        return rows[0] if rows else None

    async def upsert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        """Insert or update a row (keyed on ``id``)."""
        if self._connected and self._client is not None:
            try:
                result = self._client.table(table).upsert(data).execute()
                if result.data:
                    return result.data[0]
            except Exception:
                logger.exception("Supabase upsert failed for table '%s'", table)

        row_id = data.get("id", str(len(_memory_store.get(table, {}))))
        _memory_store.setdefault(table, {})[row_id] = data
        return data


# ---------------------------------------------------------------------------
# Redis wrapper
# ---------------------------------------------------------------------------

class RedisClient:
    """Async Redis wrapper with in-memory cache fallback."""

    def __init__(self) -> None:
        self._client: Any | None = None
        self._connected = False

    async def connect(self) -> None:
        """Open a Redis connection pool (if configured)."""
        if not settings.redis_configured:
            logger.warning(
                "Redis not configured — using in-memory cache. "
                "Set SIGIL_REDIS_URL to enable."
            )
            return

        try:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
            await self._client.ping()
            self._connected = True
            logger.info("Redis connected at %s", settings.redis_url)
        except Exception:
            logger.exception("Failed to connect to Redis — falling back to in-memory cache.")
            self._client = None
            self._connected = False

    async def disconnect(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self._client = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    async def get(self, key: str) -> str | None:
        """Get a cached value by key."""
        if self._connected and self._client is not None:
            try:
                return await self._client.get(key)
            except Exception:
                logger.exception("Redis GET failed for key '%s'", key)
        return _memory_cache.get(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        """Set a cached value with optional TTL (seconds)."""
        if self._connected and self._client is not None:
            try:
                await self._client.set(key, value, ex=ttl)
                return
            except Exception:
                logger.exception("Redis SET failed for key '%s'", key)
        _memory_cache[key] = value

    async def delete(self, key: str) -> None:
        """Delete a cached key."""
        if self._connected and self._client is not None:
            try:
                await self._client.delete(key)
                return
            except Exception:
                logger.exception("Redis DELETE failed for key '%s'", key)
        _memory_cache.pop(key, None)


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

db = SupabaseClient()
cache = RedisClient()
