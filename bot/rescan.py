"""
Sigil Bot — Rescan Scheduler (AEO Action #9)

Periodically queries the database for previously-scanned packages that are
due for a rescan based on their verdict and age:

  | Condition                              | Rescan interval |
  |----------------------------------------|-----------------|
  | HIGH_RISK or CRITICAL_RISK verdict     | Weekly (7 days) |
  | >10,000 downloads (download_count)     | Monthly (30 d)  |
  | All other scanned packages             | Quarterly (90d) |

Rescan jobs are enqueued at "low" priority so they never block new-package
scanning.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from bot.config import bot_settings
from bot.queue import JobQueue, ScanJob

logger = logging.getLogger(__name__)

# Check for rescans every 6 hours
RESCAN_CHECK_INTERVAL = 21600


async def _get_packages_due_for_rescan(
    limit: int = 50,
) -> list[dict]:
    """Query public_scans for packages due for rescanning."""
    from bot.store import get_db

    db = await get_db()
    now = datetime.now(timezone.utc)

    # Build SQL that selects the most recent scan per package and checks age
    sql = """
    WITH latest AS (
        SELECT
            ecosystem,
            package_name,
            package_version,
            verdict,
            metadata_json,
            scanned_at,
            ROW_NUMBER() OVER (
                PARTITION BY ecosystem, package_name
                ORDER BY scanned_at DESC
            ) AS rn
        FROM public_scans
        WHERE verdict != 'ERROR'
    )
    SELECT TOP (?)
        ecosystem,
        package_name,
        package_version,
        verdict,
        metadata_json,
        scanned_at
    FROM latest
    WHERE rn = 1
    AND (
        (verdict IN ('HIGH_RISK', 'CRITICAL_RISK') AND DATEDIFF(day, scanned_at, GETUTCDATE()) >= ?)
        OR DATEDIFF(day, scanned_at, GETUTCDATE()) >= ?
    )
    ORDER BY
        CASE WHEN verdict IN ('HIGH_RISK', 'CRITICAL_RISK') THEN 0 ELSE 1 END,
        scanned_at ASC
    """

    results = []
    try:
        async with db._pool.acquire() as conn:
            cursor = await conn.cursor()
            await cursor.execute(sql, (
                limit,
                bot_settings.rescan_high_risk_days,
                bot_settings.rescan_default_days,
            ))
            cols = [col[0] for col in cursor.description]
            rows = await cursor.fetchall()
            for row in rows:
                results.append(dict(zip(cols, row)))
    except Exception:
        logger.exception("Failed to query packages for rescan")

    return results


async def rescan_loop(queue: JobQueue) -> None:
    """Main rescan scheduling loop."""
    logger.info("Rescan scheduler starting (check interval=%ds)", RESCAN_CHECK_INTERVAL)

    while True:
        try:
            packages = await _get_packages_due_for_rescan(limit=50)

            if packages:
                logger.info("Rescan scheduler: %d packages due for rescan", len(packages))

            enqueued = 0
            for pkg in packages:
                ecosystem = pkg["ecosystem"]
                name = pkg["package_name"]
                version = pkg.get("package_version", "")

                # Parse metadata for download URL
                meta = pkg.get("metadata_json", {})
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except json.JSONDecodeError:
                        meta = {}

                # Build download URL based on ecosystem
                download_url = meta.get("repository_url", "")
                if not download_url:
                    if ecosystem == "github":
                        download_url = f"https://github.com/{name}.git"
                    elif ecosystem == "skills":
                        source = meta.get("source", name)
                        download_url = f"https://github.com/{source}.git"

                job = ScanJob(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    download_url=download_url,
                    priority="low",
                    metadata={
                        **meta,
                        "rescan": True,
                        "previous_verdict": pkg.get("verdict", ""),
                    },
                )

                if await queue.enqueue(job):
                    enqueued += 1

            if enqueued:
                logger.info("Rescan scheduler: enqueued %d rescan jobs", enqueued)

        except Exception:
            logger.exception("Rescan scheduler error")

        await asyncio.sleep(RESCAN_CHECK_INTERVAL)
