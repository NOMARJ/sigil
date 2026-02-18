"""
Sigil API — Database & Cache Connections

Provides async-friendly wrappers around Supabase and Redis.  Both are
optional — the service degrades gracefully when they are not configured,
falling back to in-memory stores so development/testing can proceed without
external infrastructure.
"""

from __future__ import annotations

import logging
from datetime import datetime
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
        self._subscriptions: dict[str, dict[str, Any]] = {}

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
            logger.exception(
                "Failed to connect to Supabase — falling back to in-memory store."
            )
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
        _memory_store.setdefault(table, {})[
            data.get("id", str(len(_memory_store.get(table, {}))))
        ] = data
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
            rows = [r for r in rows if all(r.get(k) == v for k, v in filters.items())]
        return rows[:limit]

    async def select_one(
        self, table: str, filters: dict[str, Any]
    ) -> dict[str, Any] | None:
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

    async def delete(self, table: str, filters: dict[str, Any]) -> None:
        """Delete rows from *table* matching the given equality filters."""
        if self._connected and self._client is not None:
            try:
                query = self._client.table(table).delete()
                for col, val in filters.items():
                    query = query.eq(col, val)
                query.execute()
                return
            except Exception:
                logger.exception("Supabase delete failed for table '%s'", table)

        # Fallback: in-memory
        rows = _memory_store.get(table, {})
        to_delete = [
            k for k, v in rows.items()
            if all(v.get(col) == val for col, val in filters.items())
        ]
        for k in to_delete:
            rows.pop(k, None)

    async def update(self, table: str, filters: dict[str, Any], data: dict[str, Any]) -> None:
        """Update rows in *table* matching the given equality filters."""
        if self._connected and self._client is not None:
            try:
                query = self._client.table(table).update(data)
                for col, val in filters.items():
                    query = query.eq(col, val)
                query.execute()
                return
            except Exception:
                logger.exception("Supabase update failed for table '%s'", table)

        # Fallback: in-memory
        rows = _memory_store.get(table, {})
        for row in rows.values():
            if all(row.get(col) == val for col, val in filters.items()):
                row.update(data)

    # -- Password reset helpers -----------------------------------------------

    async def create_password_reset_token(
        self, user_id: str, token_hash: str, expires_at: datetime
    ) -> dict[str, Any]:
        """Insert a password reset token, replacing any existing token for this user."""
        # Delete any existing tokens for this user first
        await self.delete("password_reset_tokens", {"user_id": user_id})

        row: dict[str, Any] = {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.utcnow().isoformat(),
        }

        if self._connected and self._client is not None:
            try:
                result = self._client.table("password_reset_tokens").insert(row).execute()
                if result.data:
                    return result.data[0]
            except Exception:
                logger.exception("Supabase insert failed for password_reset_tokens")

        # Fallback: in-memory (keyed by token_hash for easy lookup)
        _memory_store.setdefault("password_reset_tokens", {})[token_hash] = row
        return row

    async def get_password_reset_token(self, token_hash: str) -> dict[str, Any] | None:
        """Find a password reset token by hash.  Returns None if not found or expired."""
        if self._connected and self._client is not None:
            try:
                result = (
                    self._client.table("password_reset_tokens")
                    .select("*")
                    .eq("token_hash", token_hash)
                    .limit(1)
                    .execute()
                )
                rows = result.data or []
                if not rows:
                    return None
                row = rows[0]
                # Check expiry inline so callers can rely on non-expired results
                expires_at_raw = row.get("expires_at")
                if expires_at_raw:
                    try:
                        from datetime import timezone
                        expires_dt = datetime.fromisoformat(
                            str(expires_at_raw).replace("Z", "+00:00")
                        )
                        # Normalise to offset-aware UTC for comparison
                        now_utc = datetime.now(tz=timezone.utc)
                        if expires_dt.tzinfo is None:
                            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                        if now_utc > expires_dt:
                            return None
                    except (ValueError, TypeError):
                        pass
                return row
            except Exception:
                logger.exception("Supabase select failed for password_reset_tokens")

        # Fallback: in-memory
        row = _memory_store.get("password_reset_tokens", {}).get(token_hash)
        if row is None:
            return None
        expires_at_raw = row.get("expires_at")
        if expires_at_raw:
            try:
                expires_dt = datetime.fromisoformat(str(expires_at_raw))
                if datetime.utcnow() > expires_dt:
                    return None
            except (ValueError, TypeError):
                pass
        return row

    async def delete_password_reset_token(self, token_hash: str) -> None:
        """Delete a password reset token after use."""
        await self.delete("password_reset_tokens", {"token_hash": token_hash})

    async def update_user_password(self, user_id: str, password_hash: str) -> None:
        """Update the password_hash column for the given user."""
        await self.update("users", {"id": user_id}, {"password_hash": password_hash})

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Find a user by email address.  Returns None if not found."""
        return await self.select_one("users", {"email": email})

    # -- Subscription helpers -----------------------------------------------

    async def get_subscription(self, user_id: str) -> dict[str, Any] | None:
        """Get subscription for a user.  Returns None if not found."""
        if self._connected and self._client is not None:
            try:
                result = (
                    self._client.table("subscriptions")
                    .select("*")
                    .eq("user_id", user_id)
                    .limit(1)
                    .execute()
                )
                rows = result.data or []
                return rows[0] if rows else None
            except Exception:
                logger.exception(
                    "Supabase select failed for subscriptions (user_id=%s)", user_id
                )

        # Fallback: in-memory store keyed by user_id
        return self._subscriptions.get(user_id)

    async def upsert_subscription(
        self,
        user_id: str,
        plan: str,
        status: str,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        current_period_end: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a subscription record."""
        now = datetime.utcnow().isoformat()
        data: dict[str, Any] = {
            "user_id": user_id,
            "plan": plan,
            "status": status,
            "stripe_customer_id": stripe_customer_id,
            "stripe_subscription_id": stripe_subscription_id,
            "current_period_end": current_period_end,
            "updated_at": now,
        }

        if self._connected and self._client is not None:
            try:
                result = (
                    self._client.table("subscriptions")
                    .upsert(data, on_conflict="user_id")
                    .execute()
                )
                if result.data:
                    return result.data[0]
            except Exception:
                logger.exception(
                    "Supabase upsert failed for subscriptions (user_id=%s)", user_id
                )

        # Fallback: merge into in-memory store keyed by user_id
        existing = self._subscriptions.get(user_id, {})
        existing.update(data)
        self._subscriptions[user_id] = existing
        return existing

    async def get_subscription_by_stripe_customer(
        self, stripe_customer_id: str
    ) -> dict[str, Any] | None:
        """Find a subscription by Stripe customer ID."""
        if self._connected and self._client is not None:
            try:
                result = (
                    self._client.table("subscriptions")
                    .select("*")
                    .eq("stripe_customer_id", stripe_customer_id)
                    .limit(1)
                    .execute()
                )
                rows = result.data or []
                return rows[0] if rows else None
            except Exception:
                logger.exception(
                    "Supabase select failed for subscriptions "
                    "(stripe_customer_id=%s)",
                    stripe_customer_id,
                )

        # Fallback: linear scan of in-memory store
        for sub in self._subscriptions.values():
            if sub.get("stripe_customer_id") == stripe_customer_id:
                return sub
        return None


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
            logger.exception(
                "Failed to connect to Redis — falling back to in-memory cache."
            )
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
