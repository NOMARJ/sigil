"""
Sigil API — Registry Statistics Background Updater

Periodically computes and caches registry statistics to avoid expensive
table scans on the /registry/stats endpoint.

The updater runs every 15 minutes and computes:
- Total unique packages (by ecosystem:package_name)
- Total scans
- Threats found (HIGH_RISK + CRITICAL_RISK)
- Breakdown by ecosystem and verdict

The computed stats are stored in a single-row cache table that the
/registry/stats endpoint reads from.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from api.database import db

logger = logging.getLogger(__name__)

TABLE = "public_scans"
CACHE_TABLE = "registry_stats_cache"
UPDATE_INTERVAL_SECONDS = 15 * 60  # 15 minutes
CACHE_ROW_ID = "00000000-0000-0000-0000-000000000001"


class RegistryStatsUpdater:
    """Background task that updates registry statistics cache."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        """Start the background updater task."""
        print("[REGISTRY_STATS] Starting registry stats updater...")
        if self._running:
            logger.warning("Registry stats updater already running")
            print("[REGISTRY_STATS] WARNING: Already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run())
        logger.info(
            "Started registry stats updater (interval: %d seconds)",
            UPDATE_INTERVAL_SECONDS,
        )
        print(
            f"[REGISTRY_STATS] Background task created (interval: {UPDATE_INTERVAL_SECONDS}s)"
        )

    async def stop(self) -> None:
        """Stop the background updater task."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped registry stats updater")

    async def _run(self) -> None:
        """Main loop that updates stats periodically."""
        # Run first update after a short delay to avoid blocking startup
        # and give the DB pool time to fully initialize
        await asyncio.sleep(5)
        try:
            await asyncio.wait_for(self._update_stats(), timeout=60)
        except asyncio.TimeoutError:
            logger.error("Initial registry stats update timed out after 60s")
            print("[REGISTRY_STATS] ✗ Initial update timed out after 60s")
        except Exception:
            logger.exception("Initial registry stats update failed")

        # Then run every UPDATE_INTERVAL_SECONDS
        while self._running:
            try:
                await asyncio.sleep(UPDATE_INTERVAL_SECONDS)
                if self._running:  # Check again after sleep
                    await asyncio.wait_for(self._update_stats(), timeout=120)
            except asyncio.TimeoutError:
                logger.error("Registry stats update timed out after 120s")
                print("[REGISTRY_STATS] ✗ Periodic update timed out after 120s")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in registry stats updater loop")

    async def _update_stats(self) -> None:
        """Compute and update registry statistics cache."""
        start_time = datetime.now(timezone.utc)
        print(
            f"[REGISTRY_STATS] Computing registry statistics at {start_time.isoformat()}..."
        )
        logger.info("Computing registry statistics...")

        try:
            # Use raw SQL to avoid DATETIMEOFFSET issues with aioodbc
            # This query computes all stats directly in the database
            print("[REGISTRY_STATS] Computing stats via SQL aggregation...")

            if not db._pool:
                logger.warning("Database pool not available, skipping stats update")
                print("[REGISTRY_STATS] ✗ Database pool not available")
                return

            async with db._pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    cursor.timeout = 30  # 30s timeout per query
                    # Exclude ERROR scans — they represent failed scans, not results
                    _where = "WHERE verdict != 'ERROR'"

                    # Get total scans count
                    await cursor.execute(f"SELECT COUNT(*) FROM public_scans {_where}")
                    total_scans_row = await cursor.fetchone()
                    total_scans = total_scans_row[0] if total_scans_row else 0
                    print(f"[REGISTRY_STATS] Total scans: {total_scans}")

                    # Get unique packages count
                    await cursor.execute(f"""
                        SELECT COUNT(DISTINCT CONCAT(ecosystem, ':', package_name))
                        FROM public_scans {_where}
                    """)
                    packages_row = await cursor.fetchone()
                    total_packages = packages_row[0] if packages_row else 0
                    print(f"[REGISTRY_STATS] Unique packages: {total_packages}")

                    # Get threats count
                    await cursor.execute("""
                        SELECT COUNT(*)
                        FROM public_scans
                        WHERE verdict IN ('HIGH_RISK', 'CRITICAL_RISK')
                    """)
                    threats_row = await cursor.fetchone()
                    threats = threats_row[0] if threats_row else 0
                    print(f"[REGISTRY_STATS] Threats: {threats}")

                    # Get ecosystem breakdown
                    await cursor.execute(f"""
                        SELECT ecosystem, COUNT(*) as count
                        FROM public_scans {_where}
                        GROUP BY ecosystem
                    """)
                    ecosystems = {}
                    async for row in cursor:
                        ecosystems[row[0] or "unknown"] = row[1]
                    print(f"[REGISTRY_STATS] Ecosystems: {len(ecosystems)} types")

                    # Get verdict breakdown
                    await cursor.execute(f"""
                        SELECT verdict, COUNT(*) as count
                        FROM public_scans {_where}
                        GROUP BY verdict
                    """)
                    verdicts = {}
                    async for row in cursor:
                        verdicts[row[0] or "LOW_RISK"] = row[1]
                    print(f"[REGISTRY_STATS] Verdicts: {len(verdicts)} types")

            # Compute duration
            duration_ms = int(
                (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            )

            # Update cache table
            print("[REGISTRY_STATS] Updating cache table...")
            await db.upsert(
                CACHE_TABLE,
                {
                    "id": CACHE_ROW_ID,
                    "total_packages": total_packages,
                    "total_scans": total_scans,
                    "threats_found": threats,
                    "ecosystems_json": json.dumps(ecosystems),
                    "verdicts_json": json.dumps(verdicts),
                    "computed_at": datetime.now(timezone.utc),
                    "computation_duration_ms": duration_ms,
                },
                conflict_columns=["id"],
            )

            logger.info(
                "Registry stats updated: %d packages, %d scans, %d threats (took %dms)",
                total_packages,
                total_scans,
                threats,
                duration_ms,
            )
            print(
                f"[REGISTRY_STATS] ✓ Updated: {total_packages} packages, {total_scans} scans, {threats} threats ({duration_ms}ms)"
            )

        except Exception as e:
            logger.exception("Failed to update registry stats")
            print(f"[REGISTRY_STATS] ✗ ERROR: {type(e).__name__}: {e}")


# Singleton instance
_updater = RegistryStatsUpdater()


async def start_updater() -> None:
    """Start the registry stats updater background task."""
    await _updater.start()


async def stop_updater() -> None:
    """Stop the registry stats updater background task."""
    await _updater.stop()


async def get_cached_stats() -> dict[str, Any] | None:
    """Get the cached registry statistics.

    Returns None if no stats are available yet.
    """
    try:
        row = await asyncio.wait_for(
            db.select_one(CACHE_TABLE, {"id": CACHE_ROW_ID}),
            timeout=10,
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning("Failed to fetch cached stats: %s", e)
        return None

    if not row:
        return None

    return {
        "total_packages": row.get("total_packages", 0),
        "total_scans": row.get("total_scans", 0),
        "threats_found": row.get("threats_found", 0),
        "ecosystems": json.loads(row.get("ecosystems_json", "{}")),
        "verdicts": json.loads(row.get("verdicts_json", "{}")),
        "computed_at": row.get("computed_at"),
        "computation_duration_ms": row.get("computation_duration_ms", 0),
    }
