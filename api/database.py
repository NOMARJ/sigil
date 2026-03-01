"""
Sigil API — Database & Cache Connections

Provides async-friendly wrappers around Azure SQL Database and Redis. Both are
optional — the service degrades gracefully when they are not configured,
falling back to in-memory stores so development/testing can proceed without
external infrastructure.
"""

from __future__ import annotations

import json
import logging
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from api.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory fallback stores (used when external backends are unavailable)
# ---------------------------------------------------------------------------
_memory_cache: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# MssqlClient — Azure SQL Database backend via aioodbc
# ---------------------------------------------------------------------------


class MssqlClient:
    """aioodbc-backed database client for Azure SQL Database."""

    def __init__(self):
        self._pool = None
        # in-memory fallback for local development
        self._memory_store: dict[str, dict[str, Any]] = {}

    @staticmethod
    async def _configure_connection(raw_conn):
        """Configure pyodbc connection with type converters.

        Register an output converter for DATETIMEOFFSET (ODBC type -155)
        which pyodbc does not handle natively.  The raw_conn argument is
        the underlying pyodbc.Connection object.
        """

        def handle_datetimeoffset(dto_value):
            tup = struct.unpack("<6hI2h", dto_value)
            return datetime(
                tup[0],
                tup[1],
                tup[2],
                tup[3],
                tup[4],
                tup[5],
                tup[6] // 1000,
                timezone(timedelta(hours=tup[7], minutes=tup[8])),
            )

        raw_conn.add_output_converter(-155, handle_datetimeoffset)

    async def connect(self):
        if not settings.database_configured:
            logger.info("MssqlClient: no DATABASE_URL, using in-memory store")
            return
        try:
            import aioodbc

            self._pool = await aioodbc.create_pool(
                dsn=settings.database_url,
                minsize=1,
                maxsize=10,
                after_created=self._configure_connection,
            )
            logger.info("MssqlClient: connected to Azure SQL Database")
        except Exception as e:
            logger.error(f"MssqlClient: connection failed: {e}")
            self._pool = None

    async def disconnect(self):
        if self._pool:
            try:
                self._pool.close()
                await self._pool.wait_closed()
            except AttributeError:
                pass

    @property
    def connected(self) -> bool:
        """Check if connected to Azure SQL Database."""
        return self._pool is not None

    def _mem(self, table: str) -> dict[str, Any]:
        return self._memory_store.setdefault(table, {})

    @staticmethod
    def _row_to_dict(cursor, row):
        """Convert aioodbc row tuple to dict using cursor description."""
        if row is None:
            return None
        if cursor.description is None:
            return None
        return dict(zip([col[0] for col in cursor.description], row))

    @staticmethod
    def _serialize_value(v):
        """Serialize dict/list values to JSON strings for NVARCHAR(MAX) columns."""
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return v

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
        placeholders = ", ".join(["?"] * len(cols))
        values = [self._serialize_value(data[c]) for c in cols]
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"OUTPUT INSERTED.* VALUES ({placeholders})"
        )
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(values))
            row = await cursor.fetchone()
            result = self._row_to_dict(cursor, row)
            await conn.commit()
            return result

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
            for k, v in filters.items():
                conditions.append(f"{k} = ?")
                vals.append(self._serialize_value(v))
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        order = ""
        if order_by:
            direction = "DESC" if order_desc else "ASC"
            order = f"ORDER BY {order_by} {direction}"

        # T-SQL requires ORDER BY for OFFSET/FETCH
        if limit or offset:
            if not order_by:
                order = "ORDER BY (SELECT NULL)"
            off = f"OFFSET {offset or 0} ROWS"
            fetch = f"FETCH NEXT {limit} ROWS ONLY" if limit else ""
            sql = f"SELECT * FROM {table} {where} {order} {off} {fetch}".strip()
        else:
            sql = f"SELECT * FROM {table} {where} {order}".strip()

        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(vals))
            rows = await cursor.fetchall()
            return [self._row_to_dict(cursor, r) for r in rows]

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
        values = [self._serialize_value(data[c]) for c in cols]
        conflict = conflict_columns or ["id"]

        # Build T-SQL MERGE statement
        merge_conditions = " AND ".join([f"target.{c} = source.{c}" for c in conflict])
        update_cols = [c for c in cols if c not in conflict]
        insert_cols = ", ".join(cols)
        source_cols = ", ".join([f"source.{c}" for c in cols])
        source_select = ", ".join([f"? AS {c}" for c in cols])

        matched_clause = ""
        if update_cols:
            set_clauses = ", ".join([f"target.{c} = source.{c}" for c in update_cols])
            matched_clause = f"WHEN MATCHED THEN UPDATE SET {set_clauses}"

        sql = f"""
MERGE {table} AS target
USING (SELECT {source_select}) AS source ({", ".join(cols)})
ON ({merge_conditions})
{matched_clause}
WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({source_cols})
OUTPUT INSERTED.*;
"""
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(values))
            row = await cursor.fetchone()
            result = self._row_to_dict(cursor, row)
            await conn.commit()
            return result

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
        for k, v in data.items():
            set_parts.append(f"{k} = ?")
            vals.append(self._serialize_value(v))
        where_parts = []
        for k, v in filters.items():
            where_parts.append(f"{k} = ?")
            vals.append(self._serialize_value(v))
        sql = (
            f"UPDATE {table} SET {', '.join(set_parts)} "
            f"OUTPUT INSERTED.* WHERE {' AND '.join(where_parts)}"
        )
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(vals))
            row = await cursor.fetchone()
            result = self._row_to_dict(cursor, row) if row else None
            await conn.commit()
            return result

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
        for k, v in filters.items():
            conditions.append(f"{k} = ?")
            vals.append(self._serialize_value(v))
        sql = f"DELETE FROM {table} WHERE {' AND '.join(conditions)}"
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(vals))
            await conn.commit()

    # ── Domain Methods ─────────────────────────────────────────────────────────

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
            # Convert ISO strings to datetime objects if needed
            if isinstance(current_period_end, str):
                current_period_end = datetime.fromisoformat(current_period_end)
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
MERGE scan_usage AS target
USING (SELECT ? AS user_id, ? AS year_month) AS source
ON (target.user_id = source.user_id AND target.year_month = source.year_month)
WHEN MATCHED THEN UPDATE SET count = target.count + 1
WHEN NOT MATCHED THEN INSERT (user_id, year_month, count) VALUES (source.user_id, source.year_month, 1)
OUTPUT INSERTED.count;
"""
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, (user_id, year_month))
            row = await cursor.fetchone()
            count = row[0] if row else 1
            await conn.commit()
            return count


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

    async def incr(self, key: str, ttl: int | None = None) -> int:
        """Atomically increment a key and optionally set TTL on first creation.

        Returns the new value after increment.
        """
        if self._connected and self._client is not None:
            try:
                val = await self._client.incr(key)
                # Set expiry only when the key is first created (val == 1)
                if val == 1 and ttl is not None:
                    await self._client.expire(key, ttl)
                return val
            except Exception:
                logger.exception("Redis INCR failed for key '%s'", key)
        # In-memory fallback
        current = int(_memory_cache.get(key, 0))
        current += 1
        _memory_cache[key] = str(current)
        return current

    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        if self._connected and self._client is not None:
            try:
                return bool(await self._client.exists(key))
            except Exception:
                logger.exception("Redis EXISTS failed for key '%s'", key)
        return key in _memory_cache


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

# Select database backend — requires DATABASE_URL in production
db = MssqlClient()
cache = RedisClient()
