"""
Sigil API — Forge Statistics Background Updater

Periodically computes and caches Forge statistics to avoid expensive
table scans on the /forge/stats endpoint.

Uses the same single-row cache pattern as registry_stats_updater.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from api.database import db

logger = logging.getLogger(__name__)

CACHE_TABLE = "forge_stats_cache"
CACHE_ROW_ID = "00000000-0000-0000-0000-000000000002"
UPDATE_INTERVAL_SECONDS = 15 * 60  # 15 minutes

# Category mapping to ensure snake_case (shared with endpoint)
CATEGORY_MAPPING = {
    "mcp": "api_integrations",
    "ml": "ai_llm_tools",
    "general": "code_tools",
    "skills": "code_tools",
    "security": "security_tools",
    "ai-agents": "ai_llm_tools",
    "web": "api_integrations",
    "data": "data_pipeline",
    "llm-tools": "ai_llm_tools",
    "crypto": "security_tools",
    "database": "database_connectors",
    "devops": "devops_tools",
    "testing": "testing_tools",
    "monitoring": "monitoring",
    "communication": "communication",
    "search": "search_tools",
    "file-system": "file_system_tools",
}


class ForgeStatsUpdater:
    """Background task that updates Forge statistics cache."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run())
        logger.info("Started Forge stats updater (interval: %ds)", UPDATE_INTERVAL_SECONDS)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped Forge stats updater")

    async def _run(self) -> None:
        # Delay to let DB pool initialize and avoid competing with registry updater
        await asyncio.sleep(15)
        try:
            await asyncio.wait_for(self._update_stats(), timeout=90)
        except asyncio.TimeoutError:
            logger.error("Initial Forge stats update timed out after 90s")
        except Exception:
            logger.exception("Initial Forge stats update failed")

        while self._running:
            try:
                await asyncio.sleep(UPDATE_INTERVAL_SECONDS)
                if self._running:
                    await asyncio.wait_for(self._update_stats(), timeout=120)
            except asyncio.TimeoutError:
                logger.error("Forge stats update timed out after 120s")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in Forge stats updater loop")

    async def _update_stats(self) -> None:
        start_time = datetime.now(timezone.utc)
        logger.info("Computing Forge statistics...")

        if not db._pool:
            logger.warning("Database pool not available, skipping Forge stats update")
            return

        try:
            async with db._pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    cursor.timeout = 30

                    # 1. Classification ecosystem/category counts via SQL
                    await cursor.execute("""
                        SELECT ecosystem, category, COUNT(*) as cnt
                        FROM forge_classification
                        GROUP BY ecosystem, category
                    """)
                    ecosystem_counts: dict[str, int] = {}
                    category_counts: dict[str, int] = {}
                    total_tools = 0
                    async for row in cursor:
                        eco, cat, cnt = row[0], row[1], row[2]
                        ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + cnt
                        mapped = CATEGORY_MAPPING.get(
                            cat.lower(),
                            cat.replace("-", "_").replace(" ", "_").lower(),
                        )
                        category_counts[mapped] = category_counts.get(mapped, 0) + cnt
                        total_tools += cnt

                    # 2. Total matches count
                    await cursor.execute("SELECT COUNT(*) FROM forge_matches")
                    row = await cursor.fetchone()
                    total_matches = row[0] if row else 0

                    # 3. Trust score distribution
                    await cursor.execute("""
                        SELECT
                            SUM(CASE WHEN COALESCE(risk_score, 0) <= 25 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN COALESCE(risk_score, 0) > 25 AND COALESCE(risk_score, 0) <= 60 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN COALESCE(risk_score, 0) > 60 AND COALESCE(risk_score, 0) <= 85 THEN 1 ELSE 0 END),
                            SUM(CASE WHEN COALESCE(risk_score, 0) > 85 THEN 1 ELSE 0 END)
                        FROM public_scans
                        WHERE verdict != 'ERROR'
                    """)
                    trust_row = await cursor.fetchone()
                    trust_distribution = {
                        "high": trust_row[0] or 0,
                        "medium": trust_row[1] or 0,
                        "low": trust_row[2] or 0,
                        "very_low": trust_row[3] or 0,
                    }

            # Derived counts
            mcp_servers = ecosystem_counts.get("mcp", 0) + ecosystem_counts.get("github", 0)
            skills_count = ecosystem_counts.get("skill", 0) + ecosystem_counts.get("clawhub", 0)
            npm_packages = ecosystem_counts.get("npm", 0)
            pypi_packages = ecosystem_counts.get("pypi", 0)

            top_categories = sorted(
                [{"name": k, "count": v} for k, v in category_counts.items()],
                key=lambda x: x["count"],
                reverse=True,
            )[:10]

            duration_ms = int(
                (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            )

            # Write to cache
            await db.upsert(
                CACHE_TABLE,
                {
                    "id": CACHE_ROW_ID,
                    "total_tools": total_tools,
                    "total_categories": len(category_counts),
                    "total_matches": total_matches,
                    "mcp_servers": mcp_servers,
                    "skills_count": skills_count,
                    "npm_packages": npm_packages,
                    "pypi_packages": pypi_packages,
                    "ecosystems_json": json.dumps(ecosystem_counts),
                    "categories_json": json.dumps(category_counts),
                    "trust_distribution_json": json.dumps(trust_distribution),
                    "top_categories_json": json.dumps(top_categories),
                    "computed_at": datetime.now(timezone.utc),
                    "computation_duration_ms": duration_ms,
                },
                conflict_columns=["id"],
            )

            logger.info(
                "Forge stats updated: %d tools, %d matches (took %dms)",
                total_tools,
                total_matches,
                duration_ms,
            )

        except Exception:
            logger.exception("Failed to update Forge stats")


# Singleton
_updater = ForgeStatsUpdater()


async def start_updater() -> None:
    await _updater.start()


async def stop_updater() -> None:
    await _updater.stop()


async def get_cached_stats() -> dict[str, Any] | None:
    """Get cached Forge statistics. Returns None if not available."""
    try:
        row = await asyncio.wait_for(
            db.select_one(CACHE_TABLE, {"id": CACHE_ROW_ID}),
            timeout=10,
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning("Failed to fetch cached Forge stats: %s", e)
        return None

    if not row:
        return None

    return {
        "total_tools": row.get("total_tools", 0),
        "total_categories": row.get("total_categories", 0),
        "total_matches": row.get("total_matches", 0),
        "mcp_servers": row.get("mcp_servers", 0),
        "skills_count": row.get("skills_count", 0),
        "npm_packages": row.get("npm_packages", 0),
        "pypi_packages": row.get("pypi_packages", 0),
        "ecosystems": json.loads(row.get("ecosystems_json", "{}")),
        "categories": json.loads(row.get("categories_json", "{}")),
        "trust_score_distribution": json.loads(row.get("trust_distribution_json", "{}")),
        "top_categories": json.loads(row.get("top_categories_json", "[]")),
        "computed_at": row.get("computed_at"),
        "computation_duration_ms": row.get("computation_duration_ms", 0),
    }
