"""
Sigil Bot — Scanner Worker

Pulls jobs from the queue, downloads packages, runs Sigil scans,
stores results, and triggers publishing.

Each worker is a long-lived asyncio task. Can run multiple concurrently.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
from pathlib import Path

from bot.config import bot_settings
from bot.queue import JobQueue, ScanJob
from bot.store import store_scan_result, store_scan_error

logger = logging.getLogger(__name__)


async def _download_and_extract(job: ScanJob, dest: str) -> bool:
    """Download and extract a package to dest directory.

    Delegates to the existing crawler's download functions.
    """
    try:
        from api.services.crawler import (
            CrawlTarget,
            _download_npm,
            _download_pip,
            _download_git,
        )

        target = CrawlTarget(
            ecosystem=job.ecosystem,
            name=job.name,
            version=job.version,
            url=job.download_url,
        )

        if job.ecosystem == "npm":
            return await _download_npm(target, dest)
        elif job.ecosystem in ("pip", "pypi"):
            return await _download_pip(target, dest)
        elif job.ecosystem == "clawhub":
            # ClawHub uses ZIP download via httpx
            from api.services.clawhub_crawler import ClawHubSkill, download_skill

            skill = ClawHubSkill(
                slug=job.name, version=job.version
            )
            return await download_skill(skill, dest)
        elif job.ecosystem == "github":
            return await _download_git(target, dest)
        else:
            return await _download_git(target, dest)

    except ImportError:
        # Fallback: use subprocess commands directly
        return await _download_fallback(job, dest)


async def _download_fallback(job: ScanJob, dest: str) -> bool:
    """Fallback download using subprocess commands."""
    try:
        if job.ecosystem == "npm":
            pkg_spec = f"{job.name}@{job.version}" if job.version else job.name
            proc = await asyncio.create_subprocess_exec(
                "npm", "pack", pkg_spec, "--pack-destination", dest,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                return False
            # Extract tarballs
            for tgz in Path(dest).glob("*.tgz"):
                await asyncio.create_subprocess_exec(
                    "tar", "xzf", str(tgz), "-C", dest,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            return True

        elif job.ecosystem in ("pip", "pypi"):
            pkg_spec = f"{job.name}=={job.version}" if job.version else job.name
            proc = await asyncio.create_subprocess_exec(
                "pip", "download", "--no-deps", "-d", dest, pkg_spec,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                return False
            for archive in Path(dest).glob("*.tar.gz"):
                await asyncio.create_subprocess_exec(
                    "tar", "xzf", str(archive), "-C", dest,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            return True

        else:
            # Git clone
            url = job.download_url or f"https://github.com/{job.name}.git"
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", url, f"{dest}/repo",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            return proc.returncode == 0

    except Exception as e:
        logger.warning("Download fallback failed for %s/%s: %s", job.ecosystem, job.name, e)
        return False


async def _run_scan(directory: str) -> dict | None:
    """Run Sigil scan on a directory. Returns parsed scan output."""
    # Prefer the Python scanner directly
    try:
        from api.services.scanner import scan_directory, count_scannable_files
        from api.services.scoring import compute_verdict

        start = time.monotonic()
        findings = scan_directory(directory)
        score, verdict = compute_verdict(findings)
        file_count = count_scannable_files(directory)
        elapsed = int((time.monotonic() - start) * 1000)

        return {
            "score": round(score, 2),
            "verdict": verdict.value,
            "files_scanned": file_count,
            "findings": [f.model_dump(mode="json") for f in findings],
            "duration_ms": elapsed,
        }
    except ImportError:
        pass

    # Fallback to CLI
    try:
        proc = await asyncio.create_subprocess_exec(
            bot_settings.sigil_bin, "--format", "json", "scan", directory,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=bot_settings.scan_timeout
        )
        import json
        if stdout.strip():
            return json.loads(stdout.decode())
    except Exception as e:
        logger.warning("Sigil CLI scan failed: %s", e)

    return None


async def process_job(job: ScanJob, queue: JobQueue) -> None:
    """Process a single scan job: download → scan → store → publish."""
    # Validate package name — reject names that contain spaces or other
    # invalid characters that would break pip/npm download commands.
    if " " in job.name or not job.name:
        logger.warning("Skipping invalid package name: %r", job.name)
        await queue.complete(job)
        return

    with tempfile.TemporaryDirectory(
        prefix=f"sigil-bot-{job.ecosystem}-"
    ) as tmpdir:
        try:
            # 1. Download
            ok = await _download_and_extract(job, tmpdir)
            if not ok:
                raise RuntimeError(f"Download failed for {job.ecosystem}/{job.name}")

            # 2. Scan
            scan_output = await asyncio.wait_for(
                _run_scan(tmpdir),
                timeout=bot_settings.scan_timeout,
            )
            if not scan_output:
                raise RuntimeError(f"Scan produced no output for {job.ecosystem}/{job.name}")

            # 3. Store
            scan_id = await store_scan_result(job, scan_output)

            # 4. Publish
            try:
                from bot.publisher import publish_scan
                await publish_scan(scan_id, job, scan_output)
            except Exception:
                logger.exception("Publish failed for %s (non-fatal)", scan_id)

            # 5. Intelligence extraction (async, non-blocking)
            try:
                from bot.intelligence import extract_intelligence
                await extract_intelligence(job, scan_output)
            except Exception:
                logger.debug("Intelligence extraction skipped: %s", job.name)

            # Mark complete
            await queue.complete(job)

        except asyncio.TimeoutError:
            await store_scan_error(job, f"Scan timed out after {bot_settings.scan_timeout}s")
            await queue.complete(job)

        except Exception as e:
            logger.exception(
                "Worker error for %s/%s@%s", job.ecosystem, job.name, job.version
            )
            if job.retries < job.max_retries:
                await queue.retry(job)
            else:
                await queue.dead_letter(job, str(e))


async def worker_loop(queue: JobQueue, worker_id: int = 0) -> None:
    """Main worker loop: dequeue → process → repeat."""
    logger.info("Scanner worker #%d starting", worker_id)

    while True:
        try:
            # Promote any delayed retries
            promoted = await queue.promote_delayed()
            if promoted:
                logger.info("Promoted %d delayed retry jobs", promoted)

            # Dequeue next job
            job = await queue.dequeue(timeout=30)
            if not job:
                continue

            logger.info(
                "Worker #%d processing: %s/%s@%s [%s]",
                worker_id,
                job.ecosystem,
                job.name,
                job.version,
                job.priority,
            )
            await process_job(job, queue)

        except Exception:
            logger.exception("Worker #%d unexpected error", worker_id)
            await asyncio.sleep(5)
