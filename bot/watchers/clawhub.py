"""
Sigil Bot — ClawHub Watcher

Monitors ClawHub skill registry for new and updated skills.
Integrates with the existing clawhub_crawler.py for enumeration.

Polling: paginate with sort=updated every 6 hours.
Scope: ALL skills (no keyword filtering needed).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from bot.config import bot_settings
from bot.filters import determine_priority
from bot.queue import JobQueue, ScanJob
from bot.watchers.base import BaseWatcher

logger = logging.getLogger(__name__)

CLAWHUB_BASE = "https://clawhub.ai/api/v1"


class ClawHubWatcher(BaseWatcher):
    """Monitors ClawHub registry for new/updated skills."""

    def __init__(self, queue: JobQueue) -> None:
        super().__init__(queue)
        self._seen_slugs: dict[str, str] = {}  # slug -> updated_at

    @property
    def name(self) -> str:
        return "clawhub"

    @property
    def poll_interval_seconds(self) -> int:
        return bot_settings.clawhub_interval

    async def poll(self) -> list[ScanJob]:
        """Paginate ClawHub with sort=updated to find new/changed skills."""
        import httpx

        jobs: list[ScanJob] = []
        cursor: str | None = None
        checkpoint = await self.load_checkpoint()
        last_updated = checkpoint or ""
        newest_updated = last_updated

        async with httpx.AsyncClient(timeout=30) as client:
            pages = 0
            while pages < 300:  # Safety limit (~6000 skills at 20/page)
                params: dict = {"limit": 20, "sort": "updated"}
                if cursor:
                    params["cursor"] = cursor

                try:
                    resp = await client.get(
                        f"{CLAWHUB_BASE}/skills", params=params
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    logger.exception("ClawHub API error on page %d", pages)
                    break

                items = data.get("items", data.get("skills", []))
                if not items:
                    break

                for item in items:
                    slug = item.get("slug", item.get("name", ""))
                    updated = item.get("updatedAt", item.get("updated_at", ""))
                    version = item.get("version", item.get("latestVersion", ""))

                    if not slug:
                        continue

                    # Skip if we've already seen this version
                    if updated and updated <= last_updated:
                        # Once we hit skills older than checkpoint, stop
                        await self.save_checkpoint(newest_updated or updated)
                        return jobs

                    if updated and updated > newest_updated:
                        newest_updated = updated

                    download_url = (
                        f"{CLAWHUB_BASE}/download?slug={slug}"
                        + (f"&version={version}" if version else "")
                    )

                    job = ScanJob(
                        ecosystem="clawhub",
                        name=slug,
                        version=version,
                        download_url=download_url,
                        priority=determine_priority("clawhub", slug),
                        metadata={
                            "author": item.get("author", item.get("owner", "")),
                            "description": item.get("description", ""),
                            "stars": item.get("stars", item.get("starCount", 0)),
                            "downloads": item.get(
                                "downloads", item.get("downloadCount", 0)
                            ),
                            "updated_at": updated,
                        },
                    )
                    jobs.append(job)

                cursor = data.get("nextCursor", data.get("cursor"))
                if not cursor:
                    break
                pages += 1

                # Rate limit: ~120 req/min → ~0.5s between
                import asyncio

                await asyncio.sleep(0.5)

        if newest_updated:
            await self.save_checkpoint(newest_updated)

        return jobs
