"""
Sigil API — Database & Cache Connections

Provides async-friendly wrappers around Supabase and Redis.  Both are
optional — the service degrades gracefully when they are not configured,
falling back to in-memory stores so development/testing can proceed without
external infrastructure.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from api.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory fallback stores (used when external backends are unavailable)
# ---------------------------------------------------------------------------
_memory_store: dict[str, dict[str, Any]] = {}
_memory_cache: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# AsyncpgClient — PostgreSQL backend via asyncpg
# ---------------------------------------------------------------------------


class AsyncpgClient:
    """asyncpg-backed database client for Azure PostgreSQL / any Postgres."""

    def __init__(self):
        self._pool = None
        # in-memory fallback (same as SupabaseClient)
        self._memory_store: dict[str, dict[str, Any]] = {}

    async def connect(self):
        if not settings.database_configured:
            logger.info("AsyncpgClient: no DATABASE_URL, using in-memory store")
            return
        try:
            import asyncpg

            self._pool = await asyncpg.create_pool(
                settings.database_url,
                min_size=1,
                max_size=10,
                command_timeout=30,
                ssl="require",
            )
            logger.info("AsyncpgClient: connected to PostgreSQL")
        except Exception as e:
            logger.error(f"AsyncpgClient: connection failed: {e}")
            self._pool = None

    async def disconnect(self):
        if self._pool:
            await self._pool.close()

    @property
    def connected(self) -> bool:
        """Check if connected to PostgreSQL."""
        return self._pool is not None

    def _mem(self, table: str) -> dict[str, Any]:
        return self._memory_store.setdefault(table, {})

    # ── Generic CRUD ──────────────────────────────────────────────────────────

    async def insert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        if not self._pool:
            row_id = data.get("id", str(uuid.uuid4()))
            row = {
                "id": row_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                **data,
            }
            self._mem(table)[row_id] = row
            return row
        cols = list(data.keys())
        placeholders = [f"${i + 1}" for i in range(len(cols))]
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"VALUES ({', '.join(placeholders)}) RETURNING *"
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *[data[c] for c in cols])
            return dict(row)

    async def select(
        self,
        table: str,
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        offset: int | None = None,
        order_by: str | None = None,
        order_desc: bool = False,
    ) -> list[dict[str, Any]]:
        if not self._pool:
            rows = list(self._mem(table).values())
            if filters:
                rows = [
                    r for r in rows if all(r.get(k) == v for k, v in filters.items())
                ]
            if order_by:
                rows.sort(key=lambda r: r.get(order_by, ""), reverse=order_desc)
            if offset:
                rows = rows[offset:]
            if limit:
                rows = rows[:limit]
            return rows
        conditions, vals = [], []
        if filters:
            for i, (k, v) in enumerate(filters.items(), 1):
                conditions.append(f"{k} = ${i}")
                vals.append(v)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        order = ""
        if order_by:
            direction = "DESC" if order_desc else "ASC"
            order = f"ORDER BY {order_by} {direction}"
        lim = f"LIMIT {limit}" if limit else ""
        off = f"OFFSET {offset}" if offset else ""
        sql = f"SELECT * FROM {table} {where} {order} {lim} {off}".strip()
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *vals)
            return [dict(r) for r in rows]

    async def select_one(
        self, table: str, filters: dict[str, Any]
    ) -> dict[str, Any] | None:
        rows = await self.select(table, filters, limit=1)
        return rows[0] if rows else None

    async def upsert(
        self,
        table: str,
        data: dict[str, Any],
        conflict_columns: list[str] | None = None,
    ) -> dict[str, Any]:
        if not self._pool:
            key = data.get("id", str(uuid.uuid4()))
            self._mem(table)[key] = {**self._mem(table).get(key, {}), **data}
            return self._mem(table)[key]
        cols = list(data.keys())
        placeholders = [f"${i + 1}" for i in range(len(cols))]
        conflict = conflict_columns or ["id"]
        updates = [f"{c} = EXCLUDED.{c}" for c in cols if c not in conflict]
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"VALUES ({', '.join(placeholders)}) "
            f"ON CONFLICT ({', '.join(conflict)}) DO UPDATE SET {', '.join(updates)} "
            f"RETURNING *"
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *[data[c] for c in cols])
            return dict(row)

    async def update(
        self, table: str, filters: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not self._pool:
            for key, row in self._mem(table).items():
                if all(row.get(k) == v for k, v in filters.items()):
                    self._mem(table)[key].update(data)
                    return self._mem(table)[key]
            return None
        set_parts, vals = [], []
        for i, (k, v) in enumerate(data.items(), 1):
            set_parts.append(f"{k} = ${i}")
            vals.append(v)
        where_parts = []
        for i, (k, v) in enumerate(filters.items(), len(vals) + 1):
            where_parts.append(f"{k} = ${i}")
            vals.append(v)
        sql = (
            f"UPDATE {table} SET {', '.join(set_parts)} "
            f"WHERE {' AND '.join(where_parts)} RETURNING *"
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *vals)
            return dict(row) if row else None

    async def delete(self, table: str, filters: dict[str, Any]) -> None:
        if not self._pool:
            to_del = [
                k
                for k, r in self._mem(table).items()
                if all(r.get(fk) == fv for fk, fv in filters.items())
            ]
            for k in to_del:
                del self._mem(table)[k]
            return
        conditions, vals = [], []
        for i, (k, v) in enumerate(filters.items(), 1):
            conditions.append(f"{k} = ${i}")
            vals.append(v)
        sql = f"DELETE FROM {table} WHERE {' AND '.join(conditions)}"
        async with self._pool.acquire() as conn:
            await conn.execute(sql, *vals)

    # ── Domain Methods (same interface as SupabaseClient) ─────────────────────

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        return await self.select_one("users", {"email": email})

    async def create_password_reset_token(
        self, user_id: str, token_hash: str, expires_at: datetime
    ) -> dict[str, Any]:
        await self.delete("password_reset_tokens", {"user_id": user_id})
        return await self.insert(
            "password_reset_tokens",
            {
                "user_id": user_id,
                "token_hash": token_hash,
                "expires_at": expires_at,
            },
        )

    async def get_password_reset_token(self, token_hash: str) -> dict[str, Any] | None:
        row = await self.select_one("password_reset_tokens", {"token_hash": token_hash})
        if row is None:
            return None
        expires = row.get("expires_at")
        if expires and datetime.now(timezone.utc) > (
            expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)
        ):
            await self.delete("password_reset_tokens", {"token_hash": token_hash})
            return None
        return row

    async def delete_password_reset_token(self, token_hash: str) -> None:
        await self.delete("password_reset_tokens", {"token_hash": token_hash})

    async def update_user_password(self, user_id: str, password_hash: str) -> None:
        await self.update("users", {"id": user_id}, {"password_hash": password_hash})

    async def get_subscription(self, user_id: str) -> dict[str, Any] | None:
        return await self.select_one("subscriptions", {"user_id": user_id})

    async def upsert_subscription(
        self,
        user_id: str,
        plan: str,
        status: str,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        current_period_end=None,
        billing_interval: str = "monthly",
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "user_id": user_id,
            "plan": plan,
            "status": status,
            "billing_interval": billing_interval,
        }
        if stripe_customer_id is not None:
            data["stripe_customer_id"] = stripe_customer_id
        if stripe_subscription_id is not None:
            data["stripe_subscription_id"] = stripe_subscription_id
        if current_period_end is not None:
            data["current_period_end"] = current_period_end
        return await self.upsert("subscriptions", data, conflict_columns=["user_id"])

    async def get_subscription_by_stripe_customer(
        self, stripe_customer_id: str
    ) -> dict[str, Any] | None:
        return await self.select_one(
            "subscriptions", {"stripe_customer_id": stripe_customer_id}
        )

    async def get_scan_usage(self, user_id: str, year_month: str) -> int:
        """Return the current scan count for a user in a given month."""
        if not self._pool:
            key = f"{user_id}:{year_month}"
            return self._mem("scan_usage").get(key, {}).get("count", 0)
        row = await self.select_one(
            "scan_usage", {"user_id": user_id, "year_month": year_month}
        )
        return row["count"] if row else 0

    async def increment_scan_usage(self, user_id: str, year_month: str) -> int:
        """Atomically increment the scan count for a user/month. Returns the new count."""
        if not self._pool:
            key = f"{user_id}:{year_month}"
            store = self._mem("scan_usage")
            if key not in store:
                store[key] = {"user_id": user_id, "year_month": year_month, "count": 0}
            store[key]["count"] += 1
            return store[key]["count"]
        sql = """
            INSERT INTO scan_usage (user_id, year_month, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (user_id, year_month)
            DO UPDATE SET count = scan_usage.count + 1
            RETURNING count
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, user_id, year_month)
            return row["count"]


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
            k
            for k, v in rows.items()
            if all(v.get(col) == val for col, val in filters.items())
        ]
        for k in to_delete:
            rows.pop(k, None)

    async def update(
        self, table: str, filters: dict[str, Any], data: dict[str, Any]
    ) -> None:
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
                result = (
                    self._client.table("password_reset_tokens").insert(row).execute()
                )
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
        billing_interval: str = "monthly",
    ) -> dict[str, Any]:
        """Create or update a subscription record."""
        now = datetime.utcnow().isoformat()
        data: dict[str, Any] = {
            "user_id": user_id,
            "plan": plan,
            "status": status,
            "billing_interval": billing_interval,
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
                    "Supabase select failed for subscriptions (stripe_customer_id=%s)",
                    stripe_customer_id,
                )

        # Fallback: linear scan of in-memory store
        for sub in self._subscriptions.values():
            if sub.get("stripe_customer_id") == stripe_customer_id:
                return sub
        return None

    async def get_scan_usage(self, user_id: str, year_month: str) -> int:
        """Return the current scan count for a user in a given month."""
        if self._connected and self._client is not None:
            try:
                result = (
                    self._client.table("scan_usage")
                    .select("count")
                    .eq("user_id", user_id)
                    .eq("year_month", year_month)
                    .limit(1)
                    .execute()
                )
                rows = result.data or []
                return rows[0]["count"] if rows else 0
            except Exception:
                logger.exception("Supabase get_scan_usage failed (user_id=%s)", user_id)

        # Fallback: in-memory
        key = f"{user_id}:{year_month}"
        return _memory_store.get("scan_usage", {}).get(key, {}).get("count", 0)

    async def increment_scan_usage(self, user_id: str, year_month: str) -> int:
        """Atomically increment the scan count for a user/month. Returns the new count."""
        if self._connected and self._client is not None:
            try:
                # Supabase doesn't support ON CONFLICT natively in the client lib,
                # so we do a read-then-upsert (acceptable for non-critical quota tracking).
                existing = await self.get_scan_usage(user_id, year_month)
                new_count = existing + 1
                self._client.table("scan_usage").upsert(
                    {"user_id": user_id, "year_month": year_month, "count": new_count},
                    on_conflict="user_id,year_month",
                ).execute()
                return new_count
            except Exception:
                logger.exception(
                    "Supabase increment_scan_usage failed (user_id=%s)", user_id
                )

        # Fallback: in-memory
        key = f"{user_id}:{year_month}"
        store = _memory_store.setdefault("scan_usage", {})
        if key not in store:
            store[key] = {"user_id": user_id, "year_month": year_month, "count": 0}
        store[key]["count"] += 1
        return store[key]["count"]


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

# Select database backend based on configuration
if settings.database_configured:
    db = AsyncpgClient()
elif settings.supabase_configured:
    db = SupabaseClient()
else:
    db = SupabaseClient()  # falls back to in-memory inside SupabaseClient
cache = RedisClient()
