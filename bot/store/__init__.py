"""
Sigil Bot — Store Layer

Writes scan results and findings to the existing public_scans table
via the same database clients used by the API.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from bot.config import bot_settings
from bot.queue import ScanJob

logger = logging.getLogger(__name__)

# We reuse the API's database module if available; otherwise, we create
# a minimal asyncpg-based writer that matches the same schema.

_db = None


async def get_db():
    """Get or initialise the database connection."""
    global _db
    if _db is not None:
        return _db

    # Try the API's database module first
    try:
        from api.database import db as api_db

        if not api_db.connected:
            await api_db.connect()
        _db = api_db
        return _db
    except ImportError:
        pass

    # Standalone mode: use asyncpg directly
    if bot_settings.database_url:
        import asyncpg

        pool = await asyncpg.create_pool(
            bot_settings.database_url, min_size=1, max_size=5, ssl="require"
        )
        _db = _AsyncpgStore(pool)
        return _db

    raise RuntimeError("No database configured for bot store")


class _AsyncpgStore:
    """Minimal asyncpg wrapper matching the API db interface."""

    def __init__(self, pool):
        self._pool = pool

    @property
    def connected(self) -> bool:
        return self._pool is not None

    async def insert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        cols = list(data.keys())
        placeholders = [f"${i + 1}" for i in range(len(cols))]
        # Serialise dict/list values to JSON strings for jsonb columns
        values = []
        for c in cols:
            v = data[c]
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            values.append(v)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"VALUES ({', '.join(placeholders)}) RETURNING *"
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *values)
            return dict(row) if row else data

    async def upsert(
        self,
        table: str,
        data: dict[str, Any],
        conflict_columns: list[str] | None = None,
    ) -> dict[str, Any]:
        cols = list(data.keys())
        placeholders = [f"${i + 1}" for i in range(len(cols))]
        values = []
        for c in cols:
            v = data[c]
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            values.append(v)
        conflict = conflict_columns or ["id"]
        updates = [f"{c} = EXCLUDED.{c}" for c in cols if c not in conflict]
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"VALUES ({', '.join(placeholders)}) "
            f"ON CONFLICT ({', '.join(conflict)}) "
            f"DO UPDATE SET {', '.join(updates)} RETURNING *"
        )
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *values)
            return dict(row) if row else data

    async def select_one(
        self, table: str, filters: dict[str, Any]
    ) -> dict[str, Any] | None:
        conditions, vals = [], []
        for i, (k, v) in enumerate(filters.items(), 1):
            conditions.append(f"{k} = ${i}")
            vals.append(v)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM {table} {where} LIMIT 1"
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *vals)
            return dict(row) if row else None


async def store_scan_result(
    job: ScanJob,
    scan_output: dict[str, Any],
) -> str:
    """Store a scan result in public_scans + public_findings tables.

    Returns the scan_id.
    """
    db = await get_db()
    now = datetime.now(timezone.utc)
    scan_id = str(uuid4())

    findings = scan_output.get("findings", [])
    score = scan_output.get("score", 0.0)
    verdict = scan_output.get("verdict", "LOW_RISK")
    files_scanned = scan_output.get("files_scanned", 0)

    row = {
        "id": scan_id,
        "ecosystem": job.ecosystem,
        "package_name": job.name,
        "package_version": job.version,
        "risk_score": round(score, 2),
        "verdict": verdict,
        "findings_count": len(findings),
        "files_scanned": files_scanned,
        "findings_json": findings,
        "metadata_json": {
            **job.metadata,
            "bot_scan": True,
            "duration_ms": scan_output.get("duration_ms", 0),
            "scanner_version": "1.0.0",
        },
        "scanned_at": now.isoformat(),
        "created_at": now.isoformat(),
    }

    try:
        await db.upsert(
            "public_scans",
            row,
            conflict_columns=["ecosystem", "package_name", "package_version"],
        )
        logger.info(
            "Stored scan: %s/%s@%s → %s (score=%.1f, findings=%d)",
            job.ecosystem,
            job.name,
            job.version,
            verdict,
            score,
            len(findings),
        )
    except Exception:
        logger.exception("Failed to store scan for %s/%s", job.ecosystem, job.name)
        raise

    return scan_id


async def store_scan_error(job: ScanJob, error: str) -> None:
    """Store a failed scan attempt."""
    db = await get_db()
    now = datetime.now(timezone.utc)

    row = {
        "id": str(uuid4()),
        "ecosystem": job.ecosystem,
        "package_name": job.name,
        "package_version": job.version,
        "risk_score": -1,
        "verdict": "ERROR",
        "findings_count": 0,
        "files_scanned": 0,
        "findings_json": [],
        "metadata_json": {
            **job.metadata,
            "error": error,
            "bot_scan": True,
        },
        "scanned_at": now.isoformat(),
        "created_at": now.isoformat(),
    }

    try:
        await db.insert("public_scans", row)
    except Exception:
        logger.exception("Failed to store scan error for %s/%s", job.ecosystem, job.name)


async def has_been_scanned(
    ecosystem: str, name: str, version: str, content_hash: str = ""
) -> bool:
    """Check if this exact package+version has already been scanned."""
    db = await get_db()
    filters = {"ecosystem": ecosystem, "package_name": name}
    if version:
        filters["package_version"] = version
    row = await db.select_one("public_scans", filters)
    if not row:
        return False
    # If we have a content hash, check if it matches
    if content_hash:
        stored_hash = (row.get("metadata_json") or {}).get("content_hash", "")
        return stored_hash == content_hash
    return True
