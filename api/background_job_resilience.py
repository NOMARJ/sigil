"""
Sigil API — Background Job Resilience and Recovery

Implements error recovery mechanisms for background jobs and task processing
with dead letter queues, retry logic, and job state management.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar

from api.circuit_breakers import CircuitBreaker, CircuitBreakerConfig
from api.errors import (
    ErrorCategory,
    ErrorSeverity,
    SigilError,
    error_tracker,
)
from api.retry import RetryConfig, retry_with_backoff

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Job States and Priority
# ---------------------------------------------------------------------------


class JobState(str, Enum):
    """Background job execution states."""

    PENDING = "pending"  # Job queued but not started
    RUNNING = "running"  # Job currently executing
    COMPLETED = "completed"  # Job finished successfully
    FAILED = "failed"  # Job failed permanently
    RETRYING = "retrying"  # Job failed, retrying
    CANCELLED = "cancelled"  # Job was cancelled
    DEAD_LETTER = "dead_letter"  # Job moved to dead letter queue


class JobPriority(int, Enum):
    """Job priority levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Job Definition and Metadata
# ---------------------------------------------------------------------------


@dataclass
class JobMetadata:
    """Metadata for tracking job execution."""

    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_type: str = "unknown"
    priority: JobPriority = JobPriority.MEDIUM

    # Execution tracking
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_attempt_at: Optional[datetime] = None

    # State and progress
    state: JobState = JobState.PENDING
    progress: float = 0.0  # 0.0 to 1.0
    result: Optional[Any] = None
    error: Optional[str] = None

    # Retry and recovery
    attempt_count: int = 0
    max_attempts: int = 3
    retry_delays: List[float] = field(default_factory=list)

    # Context and correlation
    user_id: Optional[str] = None
    correlation_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    # Resource management
    timeout_seconds: Optional[float] = None
    memory_limit_mb: Optional[int] = None
    cpu_limit_percent: Optional[int] = None


@dataclass
class Job:
    """Background job with execution function and metadata."""

    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    metadata: JobMetadata = field(default_factory=JobMetadata)

    def __post_init__(self):
        # Set job type from function name if not specified
        if self.metadata.job_type == "unknown":
            self.metadata.job_type = getattr(self.func, "__name__", "unknown")


# ---------------------------------------------------------------------------
# Dead Letter Queue Management
# ---------------------------------------------------------------------------


class DeadLetterQueue:
    """Manages jobs that have failed permanently."""

    def __init__(self):
        self._dead_jobs: Dict[str, Job] = {}
        self._max_dead_jobs = 10000  # Prevent memory growth

    def add_job(self, job: Job, reason: str) -> None:
        """Add a job to the dead letter queue."""
        job.metadata.state = JobState.DEAD_LETTER
        job.metadata.error = reason
        job.metadata.completed_at = datetime.now(timezone.utc)

        # Store the job
        self._dead_jobs[job.metadata.job_id] = job

        # Cleanup old jobs to prevent memory growth
        if len(self._dead_jobs) > self._max_dead_jobs:
            self._cleanup_old_jobs()

        logger.error(
            "Job moved to dead letter queue: %s (type=%s, reason=%s)",
            job.metadata.job_id,
            job.metadata.job_type,
            reason,
        )

        # Track this as a high-severity error
        error_tracker.track_error(
            SigilError(
                message=f"Job permanently failed: {reason}",
                code="job_failed",
                category=ErrorCategory.PERMANENT,
                severity=ErrorSeverity.HIGH,
                context={
                    "job_id": job.metadata.job_id,
                    "job_type": job.metadata.job_type,
                    "attempts": job.metadata.attempt_count,
                    "user_id": job.metadata.user_id,
                    "correlation_id": job.metadata.correlation_id,
                },
            )
        )

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get a job from the dead letter queue."""
        return self._dead_jobs.get(job_id)

    def list_jobs(
        self,
        job_type: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Job]:
        """List jobs in the dead letter queue."""
        jobs = list(self._dead_jobs.values())

        # Apply filters
        if job_type:
            jobs = [job for job in jobs if job.metadata.job_type == job_type]
        if user_id:
            jobs = [job for job in jobs if job.metadata.user_id == user_id]

        # Sort by completion time (most recent first)
        jobs.sort(
            key=lambda j: (
                j.metadata.completed_at or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )

        return jobs[:limit]

    def requeue_job(self, job_id: str) -> Optional[Job]:
        """Remove a job from dead letter queue for requeuing."""
        job = self._dead_jobs.pop(job_id, None)
        if job:
            job.metadata.state = JobState.PENDING
            job.metadata.error = None
            job.metadata.attempt_count = 0
            job.metadata.retry_delays = []
            logger.info("Job requeued from dead letter queue: %s", job_id)
        return job

    def _cleanup_old_jobs(self) -> None:
        """Remove old jobs to prevent memory growth."""
        # Keep only the most recent 80% of jobs
        target_count = int(self._max_dead_jobs * 0.8)
        jobs = list(self._dead_jobs.values())
        jobs.sort(
            key=lambda j: (
                j.metadata.completed_at or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )

        jobs_to_keep = jobs[:target_count]
        self._dead_jobs = {job.metadata.job_id: job for job in jobs_to_keep}

        logger.info(
            "Dead letter queue cleanup: kept %d/%d jobs",
            len(self._dead_jobs),
            len(jobs),
        )


# ---------------------------------------------------------------------------
# Job Queue with Resilience
# ---------------------------------------------------------------------------


class ResilientJobQueue:
    """Job queue with resilience patterns and error recovery."""

    def __init__(self, max_concurrent_jobs: int = 10):
        self._pending_jobs: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._running_jobs: Dict[str, Job] = {}
        self._completed_jobs: Dict[str, Job] = {}
        self._dead_letter_queue = DeadLetterQueue()

        self._max_concurrent_jobs = max_concurrent_jobs
        self._worker_tasks: Set[asyncio.Task] = set()
        self._shutdown = False

        # Circuit breaker for job execution
        self._setup_circuit_breaker()

    def _setup_circuit_breaker(self):
        """Setup circuit breaker for job execution."""
        config = CircuitBreakerConfig(
            service_name="job_executor",
            failure_threshold=10,
            success_threshold=3,
            timeout_duration=120.0,
            call_timeout=300.0,  # 5 minute default job timeout
            monitoring_window=600.0,
            min_calls_in_window=5,
        )
        self.circuit_breaker = CircuitBreaker(config)

    async def start_workers(self) -> None:
        """Start background worker tasks."""
        for i in range(self._max_concurrent_jobs):
            task = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self._worker_tasks.add(task)

        logger.info("Started %d job workers", self._max_concurrent_jobs)

    async def stop_workers(self) -> None:
        """Stop background worker tasks."""
        self._shutdown = True

        # Cancel all workers
        for task in self._worker_tasks:
            task.cancel()

        # Wait for workers to finish
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)

        self._worker_tasks.clear()
        logger.info("Stopped all job workers")

    async def submit_job(
        self,
        func: Callable,
        *args: Any,
        priority: JobPriority = JobPriority.MEDIUM,
        max_attempts: int = 3,
        timeout_seconds: Optional[float] = None,
        user_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Submit a job to the queue."""
        metadata = JobMetadata(
            job_type=getattr(func, "__name__", "unknown"),
            priority=priority,
            max_attempts=max_attempts,
            timeout_seconds=timeout_seconds,
            user_id=user_id,
            correlation_id=correlation_id,
            context=context or {},
        )

        job = Job(
            func=func,
            args=args,
            kwargs=kwargs,
            metadata=metadata,
        )

        # Priority queue uses (priority, item) tuples
        # Lower numbers = higher priority, so we negate the priority value
        await self._pending_jobs.put((-priority.value, job))

        logger.info(
            "Job submitted: %s (type=%s, priority=%s)",
            job.metadata.job_id,
            job.metadata.job_type,
            priority.name,
        )

        return job.metadata.job_id

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a job."""
        # Check running jobs
        if job_id in self._running_jobs:
            job = self._running_jobs[job_id]
            return self._job_to_status(job)

        # Check completed jobs
        if job_id in self._completed_jobs:
            job = self._completed_jobs[job_id]
            return self._job_to_status(job)

        # Check dead letter queue
        dead_job = self._dead_letter_queue.get_job(job_id)
        if dead_job:
            return self._job_to_status(dead_job)

        return None

    def _job_to_status(self, job: Job) -> Dict[str, Any]:
        """Convert job to status dictionary."""
        return {
            "job_id": job.metadata.job_id,
            "job_type": job.metadata.job_type,
            "state": job.metadata.state.value,
            "priority": job.metadata.priority.name,
            "progress": job.metadata.progress,
            "created_at": job.metadata.created_at.isoformat(),
            "started_at": job.metadata.started_at.isoformat()
            if job.metadata.started_at
            else None,
            "completed_at": job.metadata.completed_at.isoformat()
            if job.metadata.completed_at
            else None,
            "attempt_count": job.metadata.attempt_count,
            "max_attempts": job.metadata.max_attempts,
            "error": job.metadata.error,
            "result": job.metadata.result,
            "user_id": job.metadata.user_id,
            "correlation_id": job.metadata.correlation_id,
        }

    async def _worker_loop(self, worker_name: str) -> None:
        """Main worker loop for processing jobs."""
        logger.info("Worker %s started", worker_name)

        while not self._shutdown:
            try:
                # Get next job with timeout to allow shutdown
                try:
                    priority, job = await asyncio.wait_for(
                        self._pending_jobs.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                # Process the job
                await self._process_job(job, worker_name)

            except Exception as exc:
                logger.error("Worker %s error: %s", worker_name, exc)
                await asyncio.sleep(1)  # Brief pause on error

        logger.info("Worker %s stopped", worker_name)

    async def _process_job(self, job: Job, worker_name: str) -> None:
        """Process a single job with resilience patterns."""
        job_id = job.metadata.job_id

        try:
            # Move job to running state
            job.metadata.state = JobState.RUNNING
            job.metadata.started_at = datetime.now(timezone.utc)
            self._running_jobs[job_id] = job

            logger.info(
                "Worker %s processing job: %s (type=%s, attempt=%d)",
                worker_name,
                job_id,
                job.metadata.job_type,
                job.metadata.attempt_count + 1,
            )

            # Execute the job with retry logic
            await self._execute_job_with_retry(job)

        except Exception as exc:
            logger.error(
                "Job %s failed permanently: %s",
                job_id,
                exc,
            )

            # Move to dead letter queue
            self._dead_letter_queue.add_job(job, str(exc))

        finally:
            # Remove from running jobs
            self._running_jobs.pop(job_id, None)

    async def _execute_job_with_retry(self, job: Job) -> None:
        """Execute a job with retry logic."""
        retry_config = RetryConfig(
            max_attempts=job.metadata.max_attempts,
            base_delay=1.0,
            max_delay=60.0,
            service_name="job_executor",
            operation_name=job.metadata.job_type,
            total_timeout=job.metadata.timeout_seconds,
        )

        async def job_execution():
            job.metadata.attempt_count += 1
            job.metadata.last_attempt_at = datetime.now(timezone.utc)

            # Execute with circuit breaker protection
            result = await self.circuit_breaker.call(
                job.func,
                *job.args,
                **job.kwargs,
            )

            return result

        try:
            # Execute with retry
            result = await retry_with_backoff(job_execution, retry_config)

            # Job completed successfully
            job.metadata.state = JobState.COMPLETED
            job.metadata.completed_at = datetime.now(timezone.utc)
            job.metadata.progress = 1.0
            job.metadata.result = result

            # Store in completed jobs (with size limit)
            self._completed_jobs[job.metadata.job_id] = job
            self._cleanup_completed_jobs()

            logger.info(
                "Job completed successfully: %s (attempts=%d)",
                job.metadata.job_id,
                job.metadata.attempt_count,
            )

        except Exception as exc:
            # Job failed permanently
            job.metadata.state = JobState.FAILED
            job.metadata.completed_at = datetime.now(timezone.utc)
            job.metadata.error = str(exc)
            raise

    def _cleanup_completed_jobs(self, max_completed: int = 1000) -> None:
        """Clean up old completed jobs to prevent memory growth."""
        if len(self._completed_jobs) > max_completed:
            # Keep only the most recent jobs
            jobs = list(self._completed_jobs.values())
            jobs.sort(
                key=lambda j: (
                    j.metadata.completed_at or datetime.min.replace(tzinfo=timezone.utc)
                ),
                reverse=True,
            )

            jobs_to_keep = jobs[:max_completed]
            self._completed_jobs = {job.metadata.job_id: job for job in jobs_to_keep}

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            "pending_jobs": self._pending_jobs.qsize(),
            "running_jobs": len(self._running_jobs),
            "completed_jobs": len(self._completed_jobs),
            "dead_letter_jobs": len(self._dead_letter_queue._dead_jobs),
            "active_workers": len([t for t in self._worker_tasks if not t.done()]),
            "circuit_breaker_status": self.circuit_breaker.get_status(),
        }

    async def requeue_dead_job(self, job_id: str) -> bool:
        """Requeue a job from the dead letter queue."""
        job = self._dead_letter_queue.requeue_job(job_id)
        if job:
            await self._pending_jobs.put((-job.metadata.priority.value, job))
            return True
        return False


# ---------------------------------------------------------------------------
# Job Recovery Utilities
# ---------------------------------------------------------------------------


class JobRecoveryManager:
    """Manages job recovery and maintenance tasks."""

    def __init__(self, job_queue: ResilientJobQueue):
        self.job_queue = job_queue
        self._recovery_task: Optional[asyncio.Task] = None

    async def start_recovery_monitoring(self):
        """Start background recovery monitoring."""
        if not self._recovery_task:
            self._recovery_task = asyncio.create_task(self._recovery_loop())
            logger.info("Job recovery monitoring started")

    async def stop_recovery_monitoring(self):
        """Stop background recovery monitoring."""
        if self._recovery_task:
            self._recovery_task.cancel()
            try:
                await self._recovery_task
            except asyncio.CancelledError:
                pass
            self._recovery_task = None
            logger.info("Job recovery monitoring stopped")

    async def _recovery_loop(self):
        """Background loop for job recovery tasks."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self._check_stalled_jobs()
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Recovery loop error: %s", exc)

    async def _check_stalled_jobs(self):
        """Check for and recover stalled jobs."""
        now = datetime.now(timezone.utc)
        stalled_jobs = []

        for job in self.job_queue._running_jobs.values():
            if job.metadata.started_at:
                runtime = (now - job.metadata.started_at).total_seconds()
                timeout = job.metadata.timeout_seconds or 3600  # 1 hour default

                if runtime > timeout:
                    stalled_jobs.append(job)

        for job in stalled_jobs:
            logger.warning(
                "Stalled job detected: %s (runtime=%.0fs)",
                job.metadata.job_id,
                (now - job.metadata.started_at).total_seconds(),
            )

            # Move to dead letter queue
            self.job_queue._running_jobs.pop(job.metadata.job_id, None)
            self.job_queue._dead_letter_queue.add_job(job, "Job timed out")

    async def _cleanup_old_data(self):
        """Clean up old job data to prevent memory growth."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=24)

        # Clean up completed jobs older than 24 hours
        old_completed = [
            job_id
            for job_id, job in self.job_queue._completed_jobs.items()
            if job.metadata.completed_at and job.metadata.completed_at < cutoff
        ]

        for job_id in old_completed:
            del self.job_queue._completed_jobs[job_id]

        if old_completed:
            logger.info("Cleaned up %d old completed jobs", len(old_completed))


# ---------------------------------------------------------------------------
# Global Job Queue Instance
# ---------------------------------------------------------------------------

# Initialize global job queue
job_queue = ResilientJobQueue(max_concurrent_jobs=10)
job_recovery_manager = JobRecoveryManager(job_queue)


# ---------------------------------------------------------------------------
# Decorator for Background Job Processing
# ---------------------------------------------------------------------------


def background_job(
    priority: JobPriority = JobPriority.MEDIUM,
    max_attempts: int = 3,
    timeout_seconds: Optional[float] = None,
):
    """
    Decorator to mark a function as a background job.

    Usage:
        @background_job(priority=JobPriority.HIGH, max_attempts=5)
        async def process_scan(repo_url: str):
            # This function will be executed as a background job
            pass
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Submit job to queue instead of executing directly
            job_id = await job_queue.submit_job(
                func,
                *args,
                priority=priority,
                max_attempts=max_attempts,
                timeout_seconds=timeout_seconds,
                **kwargs,
            )
            return {"job_id": job_id, "status": "submitted"}

        # Keep original function available for direct calls if needed
        wrapper.original_func = func
        wrapper.submit_job = lambda *args, **kwargs: job_queue.submit_job(
            func,
            *args,
            priority=priority,
            max_attempts=max_attempts,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Startup and Shutdown Functions
# ---------------------------------------------------------------------------


async def start_background_jobs():
    """Start the background job processing system."""
    await job_queue.start_workers()
    await job_recovery_manager.start_recovery_monitoring()
    logger.info("Background job system started")


async def stop_background_jobs():
    """Stop the background job processing system."""
    await job_recovery_manager.stop_recovery_monitoring()
    await job_queue.stop_workers()
    logger.info("Background job system stopped")
