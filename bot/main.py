"""
Sigil Bot — Main Entry Point

Launches all watcher processes and scanner workers as asyncio tasks.
Designed to run as a long-lived container (Azure Container Apps / Docker).

Usage:
    python -m bot.main                      # Run all watchers + workers
    python -m bot.main --watchers-only      # Run watchers only
    python -m bot.main --workers-only       # Run workers only
    python -m bot.main --watcher clawhub    # Run single watcher
    python -m bot.main --backfill clawhub   # Run initial backfill
    python -m bot.main --pr-worker          # Run PR comment posting worker
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from typing import Any

from bot.config import bot_settings
from bot.queue import JobQueue

logger = logging.getLogger(__name__)


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Quieten noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def _build_watchers(queue: JobQueue, names: list[str] | None = None):
    """Instantiate watcher objects."""
    from bot.watchers.clawhub import ClawHubWatcher
    from bot.watchers.pypi import PyPIWatcher
    from bot.watchers.npm import NpmWatcher
    from bot.watchers.github import GitHubWatcher
    from bot.watchers.skills import SkillsWatcher

    all_watchers = {
        "clawhub": ClawHubWatcher,
        "pypi": PyPIWatcher,
        "npm": NpmWatcher,
        "github": GitHubWatcher,
        "skills": SkillsWatcher,
    }

    if names:
        return [all_watchers[n](queue) for n in names if n in all_watchers]
    return [cls(queue) for cls in all_watchers.values()]


async def run_bot(
    watcher_names: list[str] | None = None,
    num_workers: int = 2,
    watchers_only: bool = False,
    workers_only: bool = False,
) -> None:
    """Main bot coroutine: starts watchers + workers."""
    queue = JobQueue()
    await queue.connect()
    logger.info("Bot queue connected")

    tasks: list[asyncio.Task] = []
    watchers = []

    # Start watchers
    if not workers_only:
        watchers = _build_watchers(queue, watcher_names)
        for w in watchers:
            task = asyncio.create_task(w.run(), name=f"watcher-{w.name}")
            tasks.append(task)
        logger.info("Started %d watchers: %s", len(watchers), [w.name for w in watchers])

    # Start workers
    if not watchers_only:
        from bot.worker import worker_loop

        for i in range(num_workers):
            task = asyncio.create_task(
                worker_loop(queue, worker_id=i), name=f"worker-{i}"
            )
            tasks.append(task)
        logger.info("Started %d scanner workers", num_workers)

    # Graceful shutdown on SIGTERM/SIGINT
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        for w in watchers:
            w.stop()
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass  # Windows

    logger.info("Sigil Bot running. Press Ctrl+C to stop.")

    # Wait for shutdown signal
    await stop_event.wait()

    # Cancel remaining tasks
    for task in tasks:
        task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)
    await queue.disconnect()
    logger.info("Sigil Bot stopped.")


async def run_backfill(ecosystem: str) -> None:
    """Run initial backfill for a specific ecosystem."""
    queue = JobQueue()
    await queue.connect()

    if ecosystem == "clawhub":
        from bot.watchers.clawhub import ClawHubWatcher

        watcher = ClawHubWatcher(queue)
        logger.info("Starting ClawHub full backfill...")
        jobs = await watcher.poll()
        enqueued = 0
        for job in jobs:
            if await queue.enqueue(job):
                enqueued += 1
        logger.info("ClawHub backfill: %d jobs enqueued", enqueued)

        # Now run workers to process them
        from bot.worker import worker_loop

        workers = []
        for i in range(bot_settings.max_concurrent_scans):
            workers.append(
                asyncio.create_task(worker_loop(queue, worker_id=i))
            )

        # Wait until queue is drained
        while True:
            depth = await queue.queue_depth()
            total = sum(depth.values())
            if total == 0:
                break
            logger.info("Backfill progress: %s", depth)
            await asyncio.sleep(10)

        for w in workers:
            w.cancel()

    elif ecosystem == "pypi":
        logger.info("PyPI backfill: scanning top AI packages...")
        # Enqueue top packages by keyword search
        from bot.watchers.pypi import PyPIWatcher

        watcher = PyPIWatcher(queue)
        jobs = await watcher.poll()
        for job in jobs:
            await queue.enqueue(job)
        logger.info("PyPI backfill: %d jobs enqueued", len(jobs))

    elif ecosystem == "npm":
        logger.info("npm backfill: scanning top AI packages...")
        from bot.watchers.npm import NpmWatcher

        watcher = NpmWatcher(queue)
        jobs = await watcher.poll()
        for job in jobs:
            await queue.enqueue(job)
        logger.info("npm backfill: %d jobs enqueued", len(jobs))

    else:
        logger.error("Unknown ecosystem for backfill: %s", ecosystem)

    await queue.disconnect()


def main() -> None:
    _setup_logging()

    parser = argparse.ArgumentParser(description="Sigil Bot — Registry Monitor & Scanner")
    parser.add_argument("--watchers-only", action="store_true", help="Run watchers only")
    parser.add_argument("--workers-only", action="store_true", help="Run workers only")
    parser.add_argument(
        "--watcher",
        nargs="+",
        choices=["clawhub", "pypi", "npm", "github"],
        help="Run specific watcher(s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=bot_settings.max_concurrent_scans,
        help="Number of scanner workers",
    )
    parser.add_argument(
        "--backfill",
        choices=["clawhub", "pypi", "npm", "github"],
        help="Run initial backfill for ecosystem",
    )
    parser.add_argument(
        "--pr-worker",
        action="store_true",
        help="Run the PR comment posting worker",
    )
    args = parser.parse_args()

    if args.pr_worker:
        from bot.worker.pr_comments import pr_comment_worker

        asyncio.run(pr_comment_worker())
    elif args.backfill:
        asyncio.run(run_backfill(args.backfill))
    else:
        asyncio.run(
            run_bot(
                watcher_names=args.watcher,
                num_workers=args.workers,
                watchers_only=args.watchers_only,
                workers_only=args.workers_only,
            )
        )


if __name__ == "__main__":
    main()
