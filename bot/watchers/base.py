"""
Sigil Bot — Watcher Base Class

Abstract base for registry watchers. Each watcher polls a single registry
feed, deduplicates, applies scope filters, and enqueues scan jobs.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from bot.config import bot_settings
from bot.queue import JobQueue, ScanJob

logger = logging.getLogger(__name__)


class BaseWatcher(ABC):
    """Abstract base class for registry watchers.

    Subclasses implement:
      - name: unique watcher identifier (used for checkpointing)
      - poll_interval_seconds: how often to poll
      - poll(): fetch new packages from the registry, return ScanJobs
    """

    def __init__(self, queue: JobQueue) -> None:
        self.queue = queue
        self._running = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique watcher name used for checkpoint keys."""
        ...

    @property
    @abstractmethod
    def poll_interval_seconds(self) -> int:
        """Seconds between poll cycles."""
        ...

    @abstractmethod
    async def poll(self) -> list[ScanJob]:
        """Poll the registry and return new scan jobs to enqueue.

        Must handle its own checkpointing (load/save via self.queue).
        """
        ...

    async def load_checkpoint(self) -> str | None:
        """Load last checkpoint from Redis."""
        return await self.queue.load_checkpoint(self.name)

    async def save_checkpoint(self, value: str) -> None:
        """Persist checkpoint to Redis."""
        await self.queue.save_checkpoint(self.name, value)

    async def run(self) -> None:
        """Main polling loop. Runs until stopped."""
        self._running = True
        logger.info(
            "Watcher [%s] starting (interval=%ds)",
            self.name,
            self.poll_interval_seconds,
        )

        while self._running:
            try:
                jobs = await self.poll()
                enqueued = 0
                for job in jobs:
                    if await self.queue.enqueue(job):
                        enqueued += 1

                if jobs:
                    logger.info(
                        "Watcher [%s] poll: %d new, %d enqueued (dedup filtered %d)",
                        self.name,
                        len(jobs),
                        enqueued,
                        len(jobs) - enqueued,
                    )

            except Exception:
                logger.exception("Watcher [%s] poll error", self.name)

            await asyncio.sleep(self.poll_interval_seconds)

    def stop(self) -> None:
        """Signal the watcher to stop."""
        self._running = False
        logger.info("Watcher [%s] stopping", self.name)
