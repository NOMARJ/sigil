"""
GitHub Metrics Service — Daily archival of GitHub traffic data.

Fetches clone, view, referrer, and repo snapshot data from the GitHub Traffic API
and stores it in MSSQL. Designed to run as an API-side scheduled task to avoid
Azure SQL firewall issues with external runners (GitHub Actions dynamic IPs).

GitHub retains traffic data for only 14 days — this service archives it permanently.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from api.config import settings
from api.database import db

logger = logging.getLogger(__name__)

# GitHub API base URL for the Sigil repo
_REPO = "NOMARJ/sigil"
_API_BASE = f"https://api.github.com/repos/{_REPO}"


class GitHubMetricsService:
    """Fetches and archives GitHub traffic data to MSSQL."""

    def __init__(self):
        self._running = False

    async def sync_all(self) -> dict[str, Any]:
        """Fetch all GitHub traffic data and store in MSSQL.

        Returns a summary of what was synced.
        """
        if not settings.github_token_configured:
            logger.info("GitHubMetricsService: no SIGIL_GITHUB_TOKEN, skipping sync")
            return {"status": "skipped", "reason": "SIGIL_GITHUB_TOKEN not configured"}

        results: dict[str, Any] = {}
        try:
            results["clones"] = await self._sync_clones()
            results["views"] = await self._sync_views()
            results["referrers"] = await self._sync_referrers()
            results["snapshot"] = await self._sync_repo_snapshot()
            results["downloads"] = await self._sync_downloads()
            results["status"] = "ok"
            results["synced_at"] = datetime.now(timezone.utc).isoformat()
            logger.info("GitHubMetricsService: sync complete — %s", results)
        except Exception as e:
            logger.exception("GitHubMetricsService: sync failed: %s", e)
            results["status"] = "error"
            results["error"] = str(e)

        return results

    async def _fetch_github(self, path: str) -> Any:
        """Make an authenticated GET request to the GitHub API."""
        import httpx

        url = f"{_API_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {settings.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def _sync_clones(self) -> dict[str, Any]:
        """Fetch and store daily clone data."""
        data = await self._fetch_github("/traffic/clones")
        clones = data.get("clones", [])
        inserted = 0

        for c in clones:
            date_str = c["timestamp"][:10]  # "2026-03-20T00:00:00Z" → "2026-03-20"
            await db.upsert(
                "github_traffic_clones",
                {
                    "date": date_str,
                    "total_clones": c["count"],
                    "unique_cloners": c["uniques"],
                },
                conflict_columns=["date"],
            )
            inserted += 1

        return {
            "rows": inserted,
            "total": data.get("count", 0),
            "uniques": data.get("uniques", 0),
        }

    async def _sync_views(self) -> dict[str, Any]:
        """Fetch and store daily view data."""
        data = await self._fetch_github("/traffic/views")
        views = data.get("views", [])
        inserted = 0

        for v in views:
            date_str = v["timestamp"][:10]
            await db.upsert(
                "github_traffic_views",
                {
                    "date": date_str,
                    "total_views": v["count"],
                    "unique_visitors": v["uniques"],
                },
                conflict_columns=["date"],
            )
            inserted += 1

        return {
            "rows": inserted,
            "total": data.get("count", 0),
            "uniques": data.get("uniques", 0),
        }

    async def _sync_referrers(self) -> dict[str, Any]:
        """Fetch and store today's referrer data.

        Uses execute_raw_sql with a T-SQL MERGE statement because the `[unique]`
        column is a reserved word in T-SQL and cannot be handled by the generic
        upsert helper without bracketing.
        """
        referrers = await self._fetch_github("/traffic/popular/referrers")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        inserted = 0

        for r in referrers:
            sql = """
                MERGE github_traffic_referrers AS target
                USING (SELECT ? AS date, ? AS referrer) AS source
                ON target.date = source.date AND target.referrer = source.referrer
                WHEN MATCHED THEN
                    UPDATE SET total = ?, [unique] = ?
                WHEN NOT MATCHED THEN
                    INSERT (date, referrer, total, [unique])
                    VALUES (?, ?, ?, ?);
            """
            await db.execute_raw_sql(
                sql,
                (
                    today,
                    r["referrer"],
                    r["count"],
                    r["uniques"],
                    today,
                    r["referrer"],
                    r["count"],
                    r["uniques"],
                ),
            )
            inserted += 1

        return {"rows": inserted, "date": today}

    async def _sync_repo_snapshot(self) -> dict[str, Any]:
        """Fetch and store today's repo metadata snapshot."""
        meta = await self._fetch_github("")  # repo root endpoint
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        await db.upsert(
            "github_repo_snapshots",
            {
                "date": today,
                "stars": meta.get("stargazers_count", 0),
                "forks": meta.get("forks_count", 0),
                "open_issues": meta.get("open_issues_count", 0),
                "watchers": meta.get("watchers_count", 0),
            },
            conflict_columns=["date"],
        )

        return {
            "date": today,
            "stars": meta.get("stargazers_count", 0),
            "forks": meta.get("forks_count", 0),
        }

    async def _sync_downloads(self) -> dict[str, Any]:
        """Fetch and store release download counts from GitHub Releases API."""
        try:
            releases = await self._fetch_github("/releases")
        except Exception:
            logger.debug("No releases found or releases API unavailable")
            return {"rows": 0}

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        total_downloads = 0

        for release in releases:
            for asset in release.get("assets", []):
                total_downloads += asset.get("download_count", 0)

        if total_downloads > 0:
            sql = """
                MERGE github_download_counts AS target
                USING (SELECT ? AS date, ? AS source) AS source_tbl
                ON target.date = source_tbl.date AND target.source = source_tbl.source
                WHEN MATCHED THEN
                    UPDATE SET download_count = ?
                WHEN NOT MATCHED THEN
                    INSERT (date, source, download_count)
                    VALUES (?, ?, ?);
            """
            await db.execute_raw_sql(
                sql,
                (
                    today,
                    "github_releases",
                    total_downloads,
                    today,
                    "github_releases",
                    total_downloads,
                ),
            )

        return {
            "rows": 1 if total_downloads > 0 else 0,
            "total_downloads": total_downloads,
        }


# Singleton
github_metrics_service = GitHubMetricsService()
