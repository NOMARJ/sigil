"""
Sigil Bot — Skills.sh Watcher

Monitors the skills.sh agent skill directory for new and updated skills.
Enumerates skills via the search API, fetches third-party audit assessments,
and enqueues scan jobs for each skill's GitHub repository.

This feeds into Initiative 2 (State of Agent Skill Security Report) by:
  - Scanning skills with Sigil's six-phase engine
  - Recording Snyk/Socket/Gen assessments for comparison
  - Storing results with ecosystem="skills" in public_scans
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

import httpx

from bot.config import bot_settings
from bot.filters import determine_priority
from bot.queue import JobQueue, ScanJob
from bot.watchers.base import BaseWatcher
from bot.watchers.skills_client import SkillsClient, SkillInfo

logger = logging.getLogger(__name__)


class SkillsWatcher(BaseWatcher):
    """Monitors skills.sh for new and updated agent skills."""

    def __init__(self, queue: JobQueue) -> None:
        super().__init__(queue)
        self._client = SkillsClient()
        self._known_skills: set[str] = set()  # skill IDs already enqueued
        self._initial_crawl_done = False
        self._discovery_index = 0

    @property
    def name(self) -> str:
        return "skills"

    @property
    def poll_interval_seconds(self) -> int:
        return bot_settings.skills_poll_interval

    async def poll(self) -> list[ScanJob]:
        """Discover skills and enqueue scan jobs for new ones."""
        jobs: list[ScanJob] = []

        # Load checkpoint (set of known skill IDs)
        if not self._known_skills:
            cp = await self.load_checkpoint()
            if cp:
                self._known_skills = set(cp.split(",")) if cp else set()
                self._initial_crawl_done = bool(self._known_skills)

        async with httpx.AsyncClient(timeout=30) as client:
            if not self._initial_crawl_done:
                # Initial crawl: discover all skills systematically
                jobs = await self._initial_crawl(client)
                self._initial_crawl_done = True
            else:
                # Subsequent polls: incremental discovery with rotating queries
                jobs = await self._incremental_poll(client)

        # Save checkpoint
        if self._known_skills:
            # Limit checkpoint size — store the most recent 10K skill IDs
            checkpoint_ids = sorted(self._known_skills)[-10000:]
            await self.save_checkpoint(",".join(checkpoint_ids))

        return jobs

    async def _initial_crawl(self, client: httpx.AsyncClient) -> list[ScanJob]:
        """Run a full discovery crawl using systematic search queries."""
        logger.info("Skills watcher: starting initial crawl")

        skills = await self._client.discover_all(client=client, delay=1.0)
        return await self._process_skills(skills, client)

    async def _incremental_poll(self, client: httpx.AsyncClient) -> list[ScanJob]:
        """Check for new skills using a subset of search queries per poll."""
        from bot.watchers.skills_client import _DISCOVERY_QUERIES

        # Rotate through 5 queries per poll cycle
        batch_size = 5
        queries = _DISCOVERY_QUERIES
        start = self._discovery_index % len(queries)
        batch = queries[start : start + batch_size]
        if len(batch) < batch_size:
            batch += queries[: batch_size - len(batch)]
        self._discovery_index += batch_size

        all_skills: list[SkillInfo] = []
        for query in batch:
            results = await self._client.search(query, limit=50, client=client)
            all_skills.extend(results)
            await asyncio.sleep(0.5)

        # Only process skills we haven't seen
        new_skills = [s for s in all_skills if s.id not in self._known_skills]
        if new_skills:
            logger.info(
                "Skills watcher: found %d new skills in incremental poll",
                len(new_skills),
            )
        return await self._process_skills(new_skills, client)

    async def _process_skills(
        self,
        skills: list[SkillInfo],
        client: httpx.AsyncClient,
    ) -> list[ScanJob]:
        """Convert discovered skills into scan jobs with audit data."""
        if not skills:
            return []

        # Deduplicate
        unique: dict[str, SkillInfo] = {}
        for s in skills:
            if s.id and s.id not in self._known_skills:
                unique[s.id] = s

        if not unique:
            return []

        # Group skills by source repo for batched audit fetches
        by_source: dict[str, list[SkillInfo]] = defaultdict(list)
        for skill in unique.values():
            if skill.source:
                by_source[skill.source].append(skill)

        # Fetch audit data in batches per source repo
        audit_data: dict[str, dict] = {}  # skill_id -> provider assessments
        for source, source_skills in by_source.items():
            slugs = [s.skill_id for s in source_skills]
            # Batch in groups of 10 to avoid URL length limits
            for i in range(0, len(slugs), 10):
                batch_slugs = slugs[i : i + 10]
                try:
                    results = await self._client.fetch_audits(
                        source, batch_slugs, client=client
                    )
                    for skill_name, audit_result in results.items():
                        # Map back to full skill ID
                        for sk in source_skills:
                            if sk.skill_id == skill_name or sk.name == skill_name:
                                audit_data[sk.id] = audit_result.to_metadata()
                                break
                except Exception:
                    logger.debug(
                        "Failed to fetch audits for %s", source, exc_info=True
                    )
                await asyncio.sleep(0.5)

        # Build scan jobs
        jobs: list[ScanJob] = []
        for skill_id, skill in unique.items():
            if not skill.source:
                continue

            # Build GitHub clone URL from source (owner/repo)
            clone_url = f"https://github.com/{skill.source}.git"

            metadata = {
                "skill_id": skill.skill_id,
                "skill_name": skill.name,
                "source": skill.source,
                "installs": skill.installs,
                "skill_path": f"skills/{skill.skill_id}",
                "provider_assessments": audit_data.get(skill_id, {}),
            }

            jobs.append(
                ScanJob(
                    ecosystem="skills",
                    name=skill_id,  # e.g. "vercel-labs/skills/find-skills"
                    version="",  # Skills don't have traditional versions
                    download_url=clone_url,
                    priority=determine_priority("skills", skill_id),
                    metadata=metadata,
                )
            )

            self._known_skills.add(skill_id)

        logger.info(
            "Skills watcher: enqueuing %d scan jobs (%d total known)",
            len(jobs),
            len(self._known_skills),
        )
        return jobs
