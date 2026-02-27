"""
Sigil Bot — PyPI Watcher

Monitors PyPI for new and updated packages via:
  1. RSS feeds (https://pypi.org/rss/packages.xml, /updates.xml) — every 5 min
  2. XML-RPC changelog serial API — every 60 sec for completeness

Scope: AI ecosystem keyword filtering.
"""

from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from bot.config import bot_settings
from bot.filters import determine_priority, matches_ai_keywords
from bot.queue import JobQueue, ScanJob
from bot.watchers.base import BaseWatcher

logger = logging.getLogger(__name__)

PYPI_RSS_NEW = "https://pypi.org/rss/packages.xml"
PYPI_RSS_UPDATES = "https://pypi.org/rss/updates.xml"
PYPI_JSON_API = "https://pypi.org/pypi"


class PyPIWatcher(BaseWatcher):
    """Monitors PyPI via RSS feeds + changelog serial API."""

    def __init__(self, queue: JobQueue) -> None:
        super().__init__(queue)
        self._last_serial: int | None = None
        self._poll_count = 0

    @property
    def name(self) -> str:
        return "pypi"

    @property
    def poll_interval_seconds(self) -> int:
        # Alternate between RSS (5 min) and changelog (60s)
        # Use the faster interval; the poll method handles the logic
        return bot_settings.pypi_changelog_interval

    async def poll(self) -> list[ScanJob]:
        """Poll PyPI for new packages."""
        jobs: list[ScanJob] = []

        self._poll_count += 1

        # Every 5th poll (~5 min), also check RSS feeds
        if self._poll_count % 5 == 1:
            rss_jobs = await self._poll_rss()
            jobs.extend(rss_jobs)

        # Every poll: check changelog serial
        changelog_jobs = await self._poll_changelog()
        jobs.extend(changelog_jobs)

        return jobs

    async def _poll_rss(self) -> list[ScanJob]:
        """Parse PyPI RSS feeds for new/updated packages."""
        import httpx

        jobs: list[ScanJob] = []

        async with httpx.AsyncClient(timeout=30) as client:
            for feed_url in [PYPI_RSS_NEW, PYPI_RSS_UPDATES]:
                try:
                    resp = await client.get(feed_url)
                    resp.raise_for_status()
                    root = ET.fromstring(resp.text)

                    for item in root.findall(".//item"):
                        title = item.findtext("title", "")
                        link = item.findtext("link", "")

                        # Parse "package-name 1.2.3" from title
                        parts = title.rsplit(" ", 1)
                        name = parts[0].strip() if parts else title.strip()
                        version = parts[1].strip() if len(parts) > 1 else ""

                        if not name:
                            continue

                        # Fetch package metadata for keyword filtering
                        meta = await self._fetch_package_meta(client, name)
                        description = meta.get("summary", "")
                        keywords_list = meta.get("keywords", "").split(",")
                        weekly_downloads = meta.get("downloads", {}).get(
                            "last_week", 0
                        )

                        if not matches_ai_keywords(name, description, keywords_list):
                            continue

                        priority = determine_priority(
                            "pypi",
                            name,
                            description,
                            keywords_list,
                            weekly_downloads,
                        )

                        jobs.append(
                            ScanJob(
                                ecosystem="pypi",
                                name=name,
                                version=version,
                                download_url="",  # pip download handles this
                                priority=priority,
                                metadata={
                                    "author": meta.get("author", ""),
                                    "description": description,
                                    "keywords": keywords_list,
                                    "published_at": item.findtext("pubDate", ""),
                                    "source": "rss",
                                },
                            )
                        )

                except Exception:
                    logger.exception("PyPI RSS poll failed for %s", feed_url)

        return jobs

    async def _poll_changelog(self) -> list[ScanJob]:
        """Use XML-RPC changelog_since_serial for incremental updates."""
        import xmlrpc.client

        jobs: list[ScanJob] = []

        try:
            # Run XML-RPC calls in a thread to avoid blocking
            def _xmlrpc_call():
                client = xmlrpc.client.ServerProxy(
                    "https://pypi.org/pypi", use_builtin_types=True
                )
                if self._last_serial is None:
                    # First run: get current serial, don't backfill
                    checkpoint = None  # Will be loaded async
                    serial = client.changelog_last_serial()
                    return serial, []
                changes = client.changelog_since_serial(self._last_serial)
                new_serial = client.changelog_last_serial()
                return new_serial, changes

            # Load checkpoint if first run
            if self._last_serial is None:
                cp = await self.load_checkpoint()
                if cp:
                    self._last_serial = int(cp)

            new_serial, changes = await asyncio.to_thread(_xmlrpc_call)

            if self._last_serial is None:
                # First run: just store the serial
                self._last_serial = new_serial
                await self.save_checkpoint(str(new_serial))
                logger.info("PyPI changelog: initial serial=%d", new_serial)
                return jobs

            # Process changes: each is (name, version, timestamp, action, serial)
            seen: set[str] = set()
            for change in changes:
                if len(change) < 4:
                    continue
                name, version, _ts, action = change[:4]

                # Only care about new file uploads
                if "new" not in str(action).lower() and "create" not in str(action).lower():
                    continue

                dedup_key = f"{name}:{version}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Quick keyword check on name alone (no API call for changelog events)
                if not matches_ai_keywords(name):
                    continue

                priority = determine_priority("pypi", name)

                jobs.append(
                    ScanJob(
                        ecosystem="pypi",
                        name=name,
                        version=version or "",
                        download_url="",
                        priority=priority,
                        metadata={"source": "changelog", "action": str(action)},
                    )
                )

            self._last_serial = new_serial
            await self.save_checkpoint(str(new_serial))

        except Exception:
            logger.exception("PyPI changelog poll failed")

        return jobs

    async def _fetch_package_meta(
        self, client, name: str
    ) -> dict:
        """Fetch package metadata from PyPI JSON API."""
        try:
            resp = await client.get(f"{PYPI_JSON_API}/{name}/json")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("info", {})
        except Exception:
            pass
        return {}
