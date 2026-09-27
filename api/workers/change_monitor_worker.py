"""
Sigil API — Website Change Monitor Worker

Background worker for the watched-URL queue defined in
``api/services/change_monitor.py``. It polls the sources that are due, records
what actually happened, and leaves a real audit trail behind.

What one batch does, per source:

    select_due_sources -> process_source (conditional GET, hash, classify,
    persist the source row, persist the event, flag it for rescan) -> count it

Every counter this worker reports is derived from a ``ChangeEvent`` that came
back from a real HTTP observation. Nothing here estimates, simulates or
back-fills a result: a fetch that fails is counted as a failure and backed off,
never as "unchanged" and never as a change.

EXPLICIT BOUNDARY — this worker does not run scans, and does not drain the
rescan queue.
    A change event carries a URL, not a package identity. ``RescanQueue``
    selects ``public_scans`` rows by (ecosystem, package_name, package_version),
    and there is no truthful way to derive that triple from an arbitrary watched
    URL here. ``change_monitor.mark_rescan_enqueued`` means "a scanner has taken
    this item"; calling it without an actual handoff would clear the backlog
    while stamping ``rescan_enqueued_at`` on work nobody did. So this worker
    reports the backlog (:meth:`ChangeMonitorWorker.pending_rescan_backlog`) and
    lets whoever owns scanning drain it. Wiring that up means resolving a source
    to a scannable artifact first — that resolution does not exist yet, and is
    not faked here.

Rate limiting is owned by this worker, matching ``clawhub_crawler``'s
caller-side model: ``change_monitor`` never sleeps, the loop below does.

Usage:
    python -m api.workers.change_monitor_worker                  # one batch
    python -m api.workers.change_monitor_worker --continuous
    python -m api.workers.change_monitor_worker --batch-size 50
    python -m api.workers.change_monitor_worker --status
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from api.services.change_monitor import (
    DEFAULT_BATCH_SIZE,
    REQUEST_DELAY,
    ChangeEvent,
    Fetcher,
    MonitoredSource,
    get_queue_status,
    pending_rescan_events,
    process_source,
    select_due_sources,
)

logger = logging.getLogger(__name__)

#: Seconds between batches in ``--continuous`` mode. Sources carry their own
#: per-source ``check_interval_minutes``; this is only how often the worker
#: wakes up to ask whether anything has become due.
DEFAULT_CHECK_INTERVAL_SECONDS = 300


@dataclass
class BatchReport:
    """Tally of one batch. Every field is counted from a real event.

    ``polled`` is the number of sources that produced a classified observation,
    so ``polled`` minus the sum of the outcome buckets is always zero unless a
    source raised — those are counted in ``crashed`` and named in ``errors``.
    """

    polled: int = 0
    unchanged: int = 0
    changed: int = 0
    failed: int = 0
    queued_for_rescan: int = 0
    crashed: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def record(self, event: ChangeEvent) -> None:
        """Fold one observed event into the tally."""
        self.polled += 1
        self.by_kind[event.change_kind] = self.by_kind.get(event.change_kind, 0) + 1
        if event.is_failure:
            self.failed += 1
        elif event.is_change:
            self.changed += 1
        else:
            self.unchanged += 1
        if event.queued_for_rescan:
            self.queued_for_rescan += 1

    def record_crash(self, source_id: str, detail: str) -> None:
        """Record a source that raised instead of returning an event.

        ``detail`` is a description of what happened, not a reconstruction of
        the exception — the exception itself, with its traceback, is logged by
        :meth:`ChangeMonitorWorker.poll_source` where it was actually caught.
        """
        self.crashed += 1
        self.errors.append(f"{source_id}: {detail}")

    def as_dict(self) -> dict[str, Any]:
        """Plain-data view for logging and for the CLI's JSON output."""
        return {
            "polled": self.polled,
            "unchanged": self.unchanged,
            "changed": self.changed,
            "failed": self.failed,
            "queued_for_rescan": self.queued_for_rescan,
            "crashed": self.crashed,
            "by_kind": dict(sorted(self.by_kind.items())),
            "errors": list(self.errors),
        }


class ChangeMonitorWorker:
    """Polls due monitored sources and persists the real outcome of each poll.

    The worker holds no state beyond its tunables and the ``running`` flag; all
    durable state lives in ``monitored_sources`` / ``source_change_events``.

    Args:
        batch_size: Maximum sources polled per batch.
        request_delay: Seconds slept between polls (politeness budget). Tests
            pass ``0.0`` so they never sleep.
        fetcher: Injectable HTTP fetcher passed through to
            ``change_monitor.process_source``. ``None`` uses the service's
            ``default_fetcher``; tests inject their own and stay offline.
    """

    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        request_delay: float = REQUEST_DELAY,
        fetcher: Fetcher | None = None,
    ):
        self.batch_size = max(int(batch_size), 1)
        self.request_delay = max(float(request_delay), 0.0)
        self.fetcher = fetcher
        self.running = False
        # True only while run_continuous owns the loop, so that a standalone
        # process_batch call is never cut short by the flag being False.
        self._continuous = False

    async def poll_source(
        self, source: MonitoredSource, *, now: datetime | None = None
    ) -> ChangeEvent | None:
        """Poll one source and persist everything that follows from it.

        Returns the classified event, or ``None`` if the source raised. One bad
        source must never take the batch down, so every failure mode ends here:
        ``process_source`` does not raise on a failed *observation* (that comes
        back as an ``error`` event), but it does raise when the outcome could
        not be persisted — which lands in ``crashed``/``errors`` rather than
        being counted as a poll that was recorded and queued.
        """
        try:
            event = await process_source(source, fetcher=self.fetcher, now=now)
        except Exception as e:
            logger.exception(
                "Failed to poll source %s (%s): %s", source.id, source.url, e
            )
            return None

        log = logger.warning if event.is_failure else logger.info
        log(
            "Polled %s (%s): %s status=%s failures=%d%s",
            source.url,
            source.source_type,
            event.change_kind,
            event.http_status,
            source.consecutive_failures,
            " [queued for rescan]" if event.queued_for_rescan else "",
        )
        return event

    async def process_batch(
        self, batch_size: int | None = None, *, now: datetime | None = None
    ) -> BatchReport:
        """Poll every source that is due, up to ``batch_size``.

        Sleeps ``request_delay`` seconds between polls (never before the first
        or after the last) so a batch cannot exceed the polite request budget.
        """
        limit = max(int(batch_size or self.batch_size), 1)
        report = BatchReport()

        try:
            sources = await select_due_sources(limit, now=now)
        except Exception as e:
            logger.exception("Failed to select due sources: %s", e)
            report.errors.append(f"select_due_sources: {type(e).__name__}: {e}")
            return report

        if not sources:
            logger.debug("No monitored sources are due")
            return report

        logger.info("Polling %d due monitored source(s)", len(sources))

        for index, source in enumerate(sources):
            if self._continuous and not self.running:
                logger.info("Stop requested, ending batch after %d source(s)", index)
                break

            event = await self.poll_source(source, now=now)
            if event is None:
                report.record_crash(source.id, "poll raised; see logged traceback")
            else:
                report.record(event)

            if self.request_delay and index < len(sources) - 1:
                await asyncio.sleep(self.request_delay)

        logger.info("Batch complete: %s", report.as_dict())
        return report

    async def pending_rescan_backlog(
        self, limit: int = DEFAULT_BATCH_SIZE
    ) -> list[ChangeEvent]:
        """Change events still waiting for a rescan, oldest first.

        Read-only on purpose — see the module docstring's boundary note. This
        worker surfaces the backlog so it can be alerted on; it does not clear
        it, because it has no scanner to hand the items to.
        """
        events = await pending_rescan_events(limit=limit)
        if events:
            logger.info(
                "%d change event(s) awaiting rescan handoff (oldest: %s)",
                len(events),
                events[0].detected_at,
            )
        return events

    async def run_continuous(
        self, check_interval: int = DEFAULT_CHECK_INTERVAL_SECONDS
    ) -> None:
        """Run batches forever, ``check_interval`` seconds apart.

        Args:
            check_interval: Seconds between batches (default: 5 minutes).
        """
        logger.info(
            "Starting continuous change monitor worker "
            "(batch size: %d, request delay: %.2fs, check interval: %ds)",
            self.batch_size,
            self.request_delay,
            check_interval,
        )
        self.running = True
        self._continuous = True

        try:
            while self.running:
                try:
                    await self.process_batch()
                    await self.pending_rescan_backlog()
                except Exception as e:
                    logger.exception("Error processing change monitor batch: %s", e)

                # Sleep in one-second slices so stop() is responsive.
                for _ in range(max(int(check_interval), 1)):
                    if not self.running:
                        break
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Change monitor worker cancelled")
        finally:
            self.running = False
            self._continuous = False
            logger.info("Change monitor worker stopped")

    def stop(self) -> None:
        """Stop the continuous worker after the in-flight poll finishes."""
        self.running = False


async def main() -> None:
    """CLI entry point for the change monitor worker."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sigil website change monitoring worker"
    )
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Sources polled per batch (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_CHECK_INTERVAL_SECONDS,
        help=(
            "Seconds between batches in --continuous mode "
            f"(default: {DEFAULT_CHECK_INTERVAL_SECONDS})"
        ),
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=REQUEST_DELAY,
        help=f"Seconds between individual polls (default: {REQUEST_DELAY})",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print real queue counters and exit without polling",
    )

    args = parser.parse_args()

    if args.status:
        print(json.dumps(await get_queue_status(), indent=2))
        return

    worker = ChangeMonitorWorker(
        batch_size=args.batch_size, request_delay=args.request_delay
    )

    if args.continuous:
        logger.info("Starting continuous change monitor worker...")
        try:
            await worker.run_continuous(check_interval=args.interval)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping worker...")
            worker.stop()
    else:
        logger.info("Processing single batch...")
        report = await worker.process_batch()
        await worker.pending_rescan_backlog()
        print(json.dumps(report.as_dict(), indent=2))


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    asyncio.run(main())
