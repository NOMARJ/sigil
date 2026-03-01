"""
Sigil Bot — npm Watcher

Monitors npm registry via CouchDB _changes feed.

Feed: https://replicate.npmjs.com/registry/_changes
Polling: every 60 seconds with since={last_seq}&limit=100
Scope: AI keyword filtering + npm scope allowlist.
"""

from __future__ import annotations

import asyncio
import logging

from bot.config import bot_settings
from bot.filters import determine_priority, matches_ai_keywords, matches_npm_scope
from bot.queue import JobQueue, ScanJob
from bot.watchers.base import BaseWatcher

logger = logging.getLogger(__name__)

NPM_CHANGES_URL = "https://replicate.npmjs.com/registry/_changes"
NPM_REGISTRY_URL = "https://registry.npmjs.org"


class NpmWatcher(BaseWatcher):
    """Monitors npm via CouchDB _changes feed."""

    def __init__(self, queue: JobQueue) -> None:
        super().__init__(queue)
        self._last_seq: str | None = None

    @property
    def name(self) -> str:
        return "npm"

    @property
    def poll_interval_seconds(self) -> int:
        return bot_settings.npm_changes_interval

    async def poll(self) -> list[ScanJob]:
        """Follow the CouchDB _changes feed for new/updated packages."""
        import httpx

        jobs: list[ScanJob] = []

        # Load checkpoint
        if self._last_seq is None:
            cp = await self.load_checkpoint()
            if cp:
                self._last_seq = cp

        async with httpx.AsyncClient(timeout=60) as client:
            try:
                params: dict[str, str | int] = {"limit": 100}
                if self._last_seq:
                    params["since"] = self._last_seq
                else:
                    # First run: get current update_seq from the DB root,
                    # don't backfill all of npm.  The replicate service no
                    # longer supports _changes?limit=0.
                    resp = await client.get(
                        "https://replicate.npmjs.com/"
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    self._last_seq = str(
                        data.get("update_seq", data.get("committed_update_seq", "0"))
                    )
                    await self.save_checkpoint(self._last_seq)
                    logger.info("npm: initial seq=%s", self._last_seq)
                    return jobs

                resp = await client.get(NPM_CHANGES_URL, params=params)
                resp.raise_for_status()
                data = resp.json()

                results = data.get("results", [])
                for change in results:
                    pkg_name = change.get("id", "")
                    if not pkg_name or pkg_name.startswith("_design/"):
                        continue

                    # Check scope allowlist first (fast path)
                    in_scope = matches_npm_scope(pkg_name)

                    if not in_scope:
                        # Need to check AI keywords — fetch metadata
                        meta = await self._fetch_package_meta(client, pkg_name)
                        description = meta.get("description", "")
                        keywords = meta.get("keywords", [])
                        if not matches_ai_keywords(pkg_name, description, keywords):
                            continue
                    else:
                        meta = await self._fetch_package_meta(client, pkg_name)
                        description = meta.get("description", "")
                        keywords = meta.get("keywords", [])

                    # Get latest version
                    version = ""
                    dist_tags = meta.get("dist-tags", {})
                    if dist_tags:
                        version = dist_tags.get("latest", "")

                    priority = determine_priority(
                        "npm",
                        pkg_name,
                        description,
                        keywords,
                    )

                    tarball_url = ""
                    if version and "versions" in meta:
                        ver_info = meta.get("versions", {}).get(version, {})
                        tarball_url = ver_info.get("dist", {}).get("tarball", "")

                    jobs.append(
                        ScanJob(
                            ecosystem="npm",
                            name=pkg_name,
                            version=version,
                            download_url=tarball_url,
                            priority=priority,
                            metadata={
                                "author": meta.get("author", {}).get("name", "")
                                if isinstance(meta.get("author"), dict)
                                else str(meta.get("author", "")),
                                "description": description,
                                "keywords": keywords or [],
                                "source": "changes_feed",
                            },
                        )
                    )

                # Update checkpoint
                new_seq = str(data.get("last_seq", self._last_seq))
                if new_seq != self._last_seq:
                    self._last_seq = new_seq
                    await self.save_checkpoint(self._last_seq)

            except Exception:
                logger.exception("npm _changes poll failed")

        return jobs

    async def _fetch_package_meta(self, client, name: str) -> dict:
        """Fetch abbreviated package metadata from npm registry."""
        try:
            resp = await client.get(
                f"{NPM_REGISTRY_URL}/{name}",
                headers={"Accept": "application/vnd.npm.install-v1+json"},
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}
