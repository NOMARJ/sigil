"""
Sigil Bot — Store Layer

Writes scan results and findings to the existing public_scans table
via Azure SQL Database using aioodbc.
"""

from __future__ import annotations

import json
import logging
import struct
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from bot.config import bot_settings
from bot.queue import ScanJob

logger = logging.getLogger(__name__)

# We use aioodbc to connect to Azure SQL Database with a dedicated connection
# pool to avoid any in-memory fallback that might silently swallow writes.

_db = None


async def get_db():
    """Get or initialise the database connection.

    Always uses a dedicated aioodbc pool for Azure SQL Database.
    """
    global _db
    if _db is not None:
        return _db

    # Resolve the database URL — bot config first, then fall back to the
    # API-level env var (SIGIL_DATABASE_URL) which is also set on the
    # bot containers.
    import os

    db_url = bot_settings.database_url or os.environ.get("SIGIL_DATABASE_URL")

    if db_url:
        import aioodbc

        async def _configure_connection(raw_conn):
            """Register output converter for DATETIMEOFFSET (ODBC type -155)."""
            def handle_datetimeoffset(dto_value):
                tup = struct.unpack("<6hI2h", dto_value)
                return datetime(
                    tup[0], tup[1], tup[2], tup[3], tup[4], tup[5],
                    tup[6] // 1000,
                    timezone(timedelta(hours=tup[7], minutes=tup[8])),
                )
            raw_conn.add_output_converter(-155, handle_datetimeoffset)

        pool = await aioodbc.create_pool(
            dsn=db_url,
            minsize=1,
            maxsize=5,
            after_created=_configure_connection,
        )
        _db = _MssqlStore(pool)
        logger.info("Bot store: connected to Azure SQL Database via aioodbc")
        return _db

    raise RuntimeError("No database configured for bot store")


class _MssqlStore:
    """Minimal aioodbc wrapper for Azure SQL Database."""

    def __init__(self, pool):
        self._pool = pool

    @property
    def connected(self) -> bool:
        return self._pool is not None

    @staticmethod
    def _row_to_dict(cursor, row):
        """Convert a pyodbc row to a dictionary."""
        if row is None:
            return None
        return dict(zip([col[0] for col in cursor.description], row))

    async def insert(self, table: str, data: dict[str, Any]) -> dict[str, Any]:
        cols = list(data.keys())
        placeholders = ", ".join(["?" for _ in cols])
        # Serialise dict/list values to JSON strings for NVARCHAR(MAX) columns
        values = []
        for c in cols:
            v = data[c]
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            values.append(v)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) "
            f"OUTPUT INSERTED.* "
            f"VALUES ({placeholders})"
        )
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(values))
            row = await cursor.fetchone()
            result = self._row_to_dict(cursor, row)
            await conn.commit()
            return result if result else data

    async def upsert(
        self,
        table: str,
        data: dict[str, Any],
        conflict_columns: list[str] | None = None,
    ) -> dict[str, Any]:
        cols = list(data.keys())
        values = []
        for c in cols:
            v = data[c]
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            values.append(v)
        conflict = conflict_columns or ["id"]

        # Build MERGE statement for SQL Server
        merge_on = " AND ".join([f"target.{c} = source.{c}" for c in conflict])
        update_cols = [c for c in cols if c not in conflict]
        source_select = ", ".join([f"? AS {c}" for c in cols])
        insert_cols = ", ".join(cols)
        source_vals = ", ".join([f"source.{c}" for c in cols])

        matched_clause = ""
        if update_cols:
            set_clause = ", ".join([f"target.{c} = source.{c}" for c in update_cols])
            matched_clause = f"WHEN MATCHED THEN UPDATE SET {set_clause}"

        sql = f"""
        MERGE {table} AS target
        USING (SELECT {source_select}) AS source ({', '.join(cols)})
        ON ({merge_on})
        {matched_clause}
        WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({source_vals})
        OUTPUT INSERTED.*;
        """
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(values))
            row = await cursor.fetchone()
            result = self._row_to_dict(cursor, row)
            await conn.commit()
            return result if result else data

    async def select_one(
        self, table: str, filters: dict[str, Any]
    ) -> dict[str, Any] | None:
        conditions, vals = [], []
        for k, v in filters.items():
            conditions.append(f"{k} = ?")
            vals.append(v)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT TOP 1 * FROM {table} {where}"
        async with self._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, tuple(vals))
            row = await cursor.fetchone()
            return self._row_to_dict(cursor, row)


def _build_registry_url(ecosystem: str, name: str, version: str) -> str:
    """Build a direct link to the package on its registry."""
    if ecosystem == "npm":
        url = f"https://www.npmjs.com/package/{name}"
        if version:
            url += f"/v/{version}"
        return url
    elif ecosystem in ("pip", "pypi"):
        url = f"https://pypi.org/project/{name}/"
        if version:
            url += f"{version}/"
        return url
    elif ecosystem == "github":
        return f"https://github.com/{name}"
    elif ecosystem == "clawhub":
        return f"https://clawhub.com/skills/{name}"
    elif ecosystem == "skills":
        source = name.rsplit("/", 1)[0] if "/" in name else name
        return f"https://github.com/{source}"
    return ""


def _enrich_metadata(
    job: ScanJob,
    files_scanned: int,
    duration_ms: int,
) -> dict[str, Any]:
    """Build AEO-compliant scan_metadata from job + scan output.

    Ensures all required fields are present (source, bot_scan, description,
    files_scanned, scanner_version) and includes optional registry context
    (keywords, registry_url, published_at, download_count, repository_url)
    when available from the watcher.
    """
    meta = dict(job.metadata)

    # Required AEO fields (always present)
    meta["source"] = meta.get("source", "sigil-bot")
    meta["bot_scan"] = True
    meta["files_scanned"] = files_scanned
    meta["scanner_version"] = "1.0.0"
    meta["duration_ms"] = duration_ms

    # Truncate description to 200 chars per spec
    desc = meta.get("description", "")
    if desc and len(desc) > 200:
        meta["description"] = desc[:197] + "..."

    # Compute registry_url if not provided
    if "registry_url" not in meta:
        url = _build_registry_url(job.ecosystem, job.name, job.version)
        if url:
            meta["registry_url"] = url

    # Compute repository_url for GitHub-based ecosystems
    if "repository_url" not in meta:
        if job.ecosystem == "github":
            meta["repository_url"] = f"https://github.com/{job.name}"
        elif job.ecosystem == "skills" and meta.get("source"):
            source = meta.get("source", "")
            if source and "/" in source:
                meta["repository_url"] = f"https://github.com/{source}"

    # Normalize download_count from ecosystem-specific field names
    if "download_count" not in meta:
        for key in ("downloads", "weekly_downloads", "installs"):
            if key in meta:
                meta["download_count"] = meta[key]
                break

    # Provenance: where the package was actually downloaded/cloned from
    if job.download_url and "scanned_from" not in meta:
        meta["scanned_from"] = job.download_url

    return meta


async def store_scan_result(
    job: ScanJob,
    scan_output: dict[str, Any],
) -> str:
    """Store a scan result in public_scans table.

    Returns the scan_id.
    """
    db = await get_db()
    now = datetime.now(timezone.utc)
    scan_id = str(uuid4())

    findings = scan_output.get("findings", [])
    score = scan_output.get("score", 0.0)
    verdict = scan_output.get("verdict", "LOW_RISK")
    files_scanned = scan_output.get("files_scanned", 0)
    duration_ms = scan_output.get("duration_ms", 0)

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
        "metadata_json": _enrich_metadata(job, files_scanned, duration_ms),
        "scanned_at": now,
        "created_at": now,
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


async def store_scan_error(
    job: ScanJob,
    error: str,
    error_type: str = "scanner_crash",
) -> None:
    """Store a failed scan attempt with structured error output (AEO Action #10).

    Args:
        job: The scan job that failed.
        error: Human-readable error message.
        error_type: One of: timeout, download_failed, parse_error, scanner_crash.
    """
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
            "source": "sigil-bot",
            "bot_scan": True,
            "error": True,
            "error_type": error_type,
            "error_message": error,
            "scanner_version": "1.0.0",
            "registry_url": _build_registry_url(job.ecosystem, job.name, job.version),
        },
        "scanned_at": now,
        "created_at": now,
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
        metadata = row.get("metadata_json")
        if metadata:
            # Handle JSON string from database
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    return False
            stored_hash = metadata.get("content_hash", "")
            return stored_hash == content_hash
    return True
