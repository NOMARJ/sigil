"""Sigil Bot — Redis-backed priority queue with retry and dead-letter support."""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import redis.asyncio as aioredis

from bot.config import bot_settings

logger = logging.getLogger(__name__)

# Queue key names in Redis
QUEUE_PREFIX = "sigil:queue"
QUEUE_CRITICAL = f"{QUEUE_PREFIX}:critical"
QUEUE_HIGH = f"{QUEUE_PREFIX}:high"
QUEUE_NORMAL = f"{QUEUE_PREFIX}:normal"
PROCESSING_SET = f"{QUEUE_PREFIX}:processing"
DEAD_LETTER = f"{QUEUE_PREFIX}:dead_letter"
DEDUP_SET = "sigil:dedup"
CHECKPOINT_PREFIX = "sigil:checkpoint"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"


@dataclass
class ScanJob:
    """A scan job payload."""

    id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:12]}")
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    download_url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"
    enqueued_at: str = ""
    retries: int = 0
    max_retries: int = 3

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": self.id,
                "ecosystem": self.ecosystem,
                "name": self.name,
                "version": self.version,
                "download_url": self.download_url,
                "metadata": self.metadata,
                "priority": self.priority,
                "enqueued_at": self.enqueued_at,
                "retries": self.retries,
                "max_retries": self.max_retries,
            }
        )

    @classmethod
    def from_json(cls, data: str) -> ScanJob:
        d = json.loads(data)
        return cls(**d)

    @property
    def dedup_key(self) -> str:
        content_hash = self.metadata.get("content_hash", "")
        return f"{self.ecosystem}:{self.name}:{self.version}:{content_hash}"


class JobQueue:
    """Redis-backed priority queue with retry and dead-letter support."""

    def __init__(self) -> None:
        self._redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        self._redis = aioredis.from_url(
            bot_settings.redis_url, decode_responses=True
        )
        await self._redis.ping()
        logger.info("Queue connected to Redis at %s", bot_settings.redis_url)

    async def disconnect(self) -> None:
        if self._redis:
            await self._redis.aclose()

    def _queue_key(self, priority: str) -> str:
        if priority == Priority.CRITICAL:
            return QUEUE_CRITICAL
        if priority == Priority.HIGH:
            return QUEUE_HIGH
        return QUEUE_NORMAL

    async def enqueue(self, job: ScanJob) -> bool:
        """Add a job to the queue. Returns False if deduplicated."""
        assert self._redis
        # Dedup check
        if await self._redis.sismember(DEDUP_SET, job.dedup_key):
            logger.debug("Dedup: skipping %s", job.dedup_key)
            return False

        if not job.enqueued_at:
            from datetime import datetime, timezone

            job.enqueued_at = datetime.now(timezone.utc).isoformat()

        queue_key = self._queue_key(job.priority)
        # Use LPUSH so RPOP gives FIFO within each priority
        await self._redis.lpush(queue_key, job.to_json())
        await self._redis.sadd(DEDUP_SET, job.dedup_key)
        logger.info(
            "Enqueued %s %s@%s [%s]",
            job.ecosystem,
            job.name,
            job.version,
            job.priority,
        )
        return True

    async def dequeue(self, timeout: int = 30) -> ScanJob | None:
        """Pop the highest-priority job. Blocks up to `timeout` seconds."""
        assert self._redis
        # Check queues in priority order
        for queue_key in [QUEUE_CRITICAL, QUEUE_HIGH, QUEUE_NORMAL]:
            result = await self._redis.rpop(queue_key)
            if result:
                job = ScanJob.from_json(result)
                # Track as processing
                await self._redis.hset(
                    PROCESSING_SET, job.id, str(int(time.time()))
                )
                return job

        # If all empty, block-wait on all three (BRPOP)
        result = await self._redis.brpop(
            [QUEUE_CRITICAL, QUEUE_HIGH, QUEUE_NORMAL], timeout=timeout
        )
        if result:
            _queue_name, data = result
            job = ScanJob.from_json(data)
            await self._redis.hset(
                PROCESSING_SET, job.id, str(int(time.time()))
            )
            return job
        return None

    async def complete(self, job: ScanJob) -> None:
        """Mark a job as completed."""
        assert self._redis
        await self._redis.hdel(PROCESSING_SET, job.id)

    async def retry(self, job: ScanJob) -> None:
        """Re-enqueue a job with incremented retry count."""
        assert self._redis
        await self._redis.hdel(PROCESSING_SET, job.id)
        job.retries += 1
        # Exponential backoff: add delay score
        delay_map = {1: 60, 2: 300, 3: 1800}
        delay = delay_map.get(job.retries, 1800)
        # Use a sorted set for delayed retry
        retry_key = f"{QUEUE_PREFIX}:retry"
        score = time.time() + delay
        await self._redis.zadd(retry_key, {job.to_json(): score})
        logger.warning(
            "Retry #%d for %s %s@%s in %ds",
            job.retries,
            job.ecosystem,
            job.name,
            job.version,
            delay,
        )

    async def dead_letter(self, job: ScanJob, error: str) -> None:
        """Move a job to the dead-letter queue."""
        assert self._redis
        await self._redis.hdel(PROCESSING_SET, job.id)
        payload = json.dumps(
            {
                "job": json.loads(job.to_json()),
                "error": error,
                "dead_at": time.time(),
            }
        )
        await self._redis.lpush(DEAD_LETTER, payload)
        logger.error(
            "Dead-lettered %s %s@%s: %s",
            job.ecosystem,
            job.name,
            job.version,
            error,
        )

    async def promote_delayed(self) -> int:
        """Move delayed-retry jobs whose time has come back into the main queue."""
        assert self._redis
        retry_key = f"{QUEUE_PREFIX}:retry"
        now = time.time()
        ready = await self._redis.zrangebyscore(retry_key, "-inf", str(now))
        count = 0
        for data in ready:
            job = ScanJob.from_json(data)
            queue_key = self._queue_key(job.priority)
            await self._redis.lpush(queue_key, job.to_json())
            await self._redis.zrem(retry_key, data)
            count += 1
        return count

    # -- Checkpoint persistence -------------------------------------------------

    async def save_checkpoint(self, watcher_name: str, value: str) -> None:
        """Persist a watcher checkpoint (serial number, cursor, timestamp)."""
        assert self._redis
        await self._redis.set(f"{CHECKPOINT_PREFIX}:{watcher_name}", value)

    async def load_checkpoint(self, watcher_name: str) -> str | None:
        """Load a watcher checkpoint."""
        assert self._redis
        return await self._redis.get(f"{CHECKPOINT_PREFIX}:{watcher_name}")

    # -- Monitoring helpers -----------------------------------------------------

    async def queue_depth(self) -> dict[str, int]:
        """Return current queue lengths."""
        assert self._redis
        return {
            "critical": await self._redis.llen(QUEUE_CRITICAL),
            "high": await self._redis.llen(QUEUE_HIGH),
            "normal": await self._redis.llen(QUEUE_NORMAL),
            "processing": await self._redis.hlen(PROCESSING_SET),
            "dead_letter": await self._redis.llen(DEAD_LETTER),
        }
