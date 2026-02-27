"""
Sigil Bot — GitHub Watcher

Monitors GitHub for MCP server repositories via:
  1. Search API sweep every 12 hours (rotating queries)
  2. Events API every 30 minutes (PushEvents to known repos)

Scope: MCP server patterns, >0 stars or >1 commit.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from bot.config import bot_settings
from bot.filters import determine_priority
from bot.queue import JobQueue, ScanJob
from bot.watchers.base import BaseWatcher

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# Rotate through these search queries
SEARCH_QUERIES = [
    "mcp server",
    "model context protocol",
    "topic:mcp-server",
    "filename:mcp.json",
    '"McpServer" language:typescript',
    '"@modelcontextprotocol" language:python',
]


class GitHubWatcher(BaseWatcher):
    """Monitors GitHub for MCP server repositories."""

    def __init__(self, queue: JobQueue) -> None:
        super().__init__(queue)
        self._known_repos: dict[str, str] = {}  # full_name -> last_sha
        self._search_index = 0
        self._poll_count = 0

    @property
    def name(self) -> str:
        return "github"

    @property
    def poll_interval_seconds(self) -> int:
        return bot_settings.github_events_interval

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if bot_settings.github_token:
            headers["Authorization"] = f"Bearer {bot_settings.github_token}"
        return headers

    async def poll(self) -> list[ScanJob]:
        """Poll GitHub for new/updated MCP server repos."""
        import httpx

        jobs: list[ScanJob] = []
        self._poll_count += 1

        async with httpx.AsyncClient(timeout=30, headers=self._headers()) as client:
            # Every 24th poll (~12 hours at 30-min interval): search sweep
            if self._poll_count % 24 == 1:
                search_jobs = await self._search_sweep(client)
                jobs.extend(search_jobs)

            # Every poll: check events for known repos
            event_jobs = await self._check_events(client)
            jobs.extend(event_jobs)

        return jobs

    async def _search_sweep(self, client) -> list[ScanJob]:
        """Search GitHub for MCP server repos using rotating queries."""
        jobs: list[ScanJob] = []
        query = SEARCH_QUERIES[self._search_index % len(SEARCH_QUERIES)]
        self._search_index += 1

        logger.info("GitHub search sweep: %r", query)

        try:
            page = 1
            while page <= 10:  # Max 10 pages per query
                resp = await client.get(
                    f"{GITHUB_API}/search/repositories",
                    params={
                        "q": query,
                        "sort": "updated",
                        "order": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                if resp.status_code == 403:
                    logger.warning("GitHub rate limit hit during search")
                    break
                resp.raise_for_status()
                data = resp.json()

                items = data.get("items", [])
                if not items:
                    break

                for repo in items:
                    full_name = repo.get("full_name", "")
                    stars = repo.get("stargazers_count", 0)
                    default_branch = repo.get("default_branch", "main")
                    pushed_at = repo.get("pushed_at", "")

                    # Filter: >0 stars or not a fork
                    if stars == 0 and repo.get("fork", False):
                        continue

                    # Check if we've already scanned this version
                    last_sha = self._known_repos.get(full_name, "")
                    current_sha = repo.get("pushed_at", "")  # Approximate

                    if last_sha == current_sha and last_sha:
                        continue

                    self._known_repos[full_name] = current_sha

                    clone_url = repo.get("clone_url", "")
                    jobs.append(
                        ScanJob(
                            ecosystem="github",
                            name=full_name,
                            version=pushed_at[:10] if pushed_at else "",
                            download_url=clone_url,
                            priority=determine_priority("github", full_name),
                            metadata={
                                "stars": stars,
                                "description": repo.get("description", "") or "",
                                "language": repo.get("language", ""),
                                "default_branch": default_branch,
                                "pushed_at": pushed_at,
                                "source": "search",
                            },
                        )
                    )

                page += 1
                await asyncio.sleep(2)  # Respect rate limits

        except Exception:
            logger.exception("GitHub search sweep failed")

        return jobs

    async def _check_events(self, client) -> list[ScanJob]:
        """Check GitHub Events API for PushEvents to known MCP repos."""
        jobs: list[ScanJob] = []

        if not self._known_repos:
            return jobs

        try:
            resp = await client.get(
                f"{GITHUB_API}/events",
                params={"per_page": 100},
            )
            if resp.status_code != 200:
                return jobs

            events = resp.json()
            for event in events:
                if event.get("type") != "PushEvent":
                    continue

                repo = event.get("repo", {})
                full_name = repo.get("name", "")

                if full_name not in self._known_repos:
                    continue

                # New push to a known MCP repo — rescan
                payload = event.get("payload", {})
                head_sha = payload.get("head", "")

                if self._known_repos.get(full_name) == head_sha:
                    continue

                self._known_repos[full_name] = head_sha

                jobs.append(
                    ScanJob(
                        ecosystem="github",
                        name=full_name,
                        version=head_sha[:8] if head_sha else "",
                        download_url=f"https://github.com/{full_name}.git",
                        priority="high",
                        metadata={
                            "head_sha": head_sha,
                            "source": "push_event",
                        },
                    )
                )

        except Exception:
            logger.exception("GitHub events poll failed")

        return jobs
