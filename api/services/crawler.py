"""
Sigil API — Package Registry Crawler

Automated pipeline for scanning packages from ClawHub, PyPI, and npm.
Scans packages and stores results in the public scan database.

This can be run as a standalone script or triggered via API endpoints.

Usage:
    # Scan a single package
    python -m api.services.crawler --ecosystem clawhub --package my-skill

    # Crawl trending packages
    python -m api.services.crawler --ecosystem pypi --trending

    # Full ClawHub scan
    python -m api.services.crawler --ecosystem clawhub --all
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

SIGIL_BINARY = os.environ.get("SIGIL_BINARY", "sigil")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class CrawlTarget:
    """A package to be crawled and scanned."""

    ecosystem: str  # clawhub, npm, pip, mcp
    name: str
    version: str = ""
    url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CrawlResult:
    """Result of scanning a crawled package."""

    target: CrawlTarget
    scan_id: str = ""
    risk_score: float = 0.0
    verdict: str = "CLEAN"
    findings_count: int = 0
    files_scanned: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


async def scan_package(target: CrawlTarget) -> CrawlResult:
    """Scan a single package using the Sigil CLI.

    Downloads the package to a temporary directory, runs the scan,
    and returns structured results.
    """
    scan_id = uuid4().hex[:16]
    result = CrawlResult(target=target, scan_id=scan_id)
    start = datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory(prefix="sigil-crawl-") as tmpdir:
        try:
            # Determine how to download based on ecosystem
            if target.ecosystem == "npm":
                download_ok = await _download_npm(target, tmpdir)
            elif target.ecosystem in ("pip", "pypi"):
                download_ok = await _download_pip(target, tmpdir)
            elif target.ecosystem in ("clawhub", "mcp"):
                download_ok = await _download_git(target, tmpdir)
            else:
                download_ok = await _download_git(target, tmpdir)

            if not download_ok:
                result.error = f"Failed to download {target.ecosystem}/{target.name}"
                return result

            # Run Sigil scan
            scan_output = await _run_sigil_scan(tmpdir)

            if scan_output:
                result.risk_score = scan_output.get("score", 0.0)
                result.verdict = scan_output.get("verdict", "CLEAN")
                result.findings_count = len(scan_output.get("findings", []))
                result.files_scanned = scan_output.get("files_scanned", 0)
                result.findings = scan_output.get("findings", [])

        except Exception as e:
            logger.exception("Crawl error for %s/%s", target.ecosystem, target.name)
            result.error = str(e)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    result.duration_ms = int(elapsed * 1000)

    return result


async def _download_npm(target: CrawlTarget, dest: str) -> bool:
    """Download an npm package to dest directory."""
    cmd = ["npm", "pack", target.name, "--pack-destination", dest]
    if target.version:
        cmd = ["npm", "pack", f"{target.name}@{target.version}", "--pack-destination", dest]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=dest,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode != 0:
            logger.warning("npm pack failed for %s: %s", target.name, stderr.decode())
            return False

        # Unpack the tarball
        tarballs = list(Path(dest).glob("*.tgz"))
        if tarballs:
            unpack_cmd = ["tar", "xzf", str(tarballs[0]), "-C", dest]
            proc2 = await asyncio.create_subprocess_exec(
                *unpack_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=30)

        return True
    except (asyncio.TimeoutError, OSError) as e:
        logger.warning("npm download timeout/error for %s: %s", target.name, e)
        return False


async def _download_pip(target: CrawlTarget, dest: str) -> bool:
    """Download a pip package to dest directory."""
    cmd = [
        "pip", "download", "--no-deps", "--no-binary", ":all:",
        "-d", dest, target.name,
    ]
    if target.version:
        cmd[-1] = f"{target.name}=={target.version}"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode != 0:
            logger.warning("pip download failed for %s: %s", target.name, stderr.decode())
            return False

        # Unpack archives
        for archive in Path(dest).glob("*.tar.gz"):
            unpack_cmd = ["tar", "xzf", str(archive), "-C", dest]
            proc2 = await asyncio.create_subprocess_exec(
                *unpack_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=30)

        for archive in Path(dest).glob("*.zip"):
            unpack_cmd = ["unzip", "-o", str(archive), "-d", dest]
            proc2 = await asyncio.create_subprocess_exec(
                *unpack_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=30)

        return True
    except (asyncio.TimeoutError, OSError) as e:
        logger.warning("pip download timeout/error for %s: %s", target.name, e)
        return False


async def _download_git(target: CrawlTarget, dest: str) -> bool:
    """Clone a git repository to dest directory."""
    url = target.url
    if not url:
        # Construct URL based on ecosystem
        if target.ecosystem == "clawhub":
            url = f"https://github.com/{target.name}"
        elif target.ecosystem == "mcp":
            url = f"https://github.com/{target.name}"
        else:
            logger.warning("No URL for git download of %s", target.name)
            return False

    cmd = ["git", "clone", "--depth", "1", url, os.path.join(dest, "repo")]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode != 0:
            logger.warning("git clone failed for %s: %s", target.name, stderr.decode())
            return False

        return True
    except (asyncio.TimeoutError, OSError) as e:
        logger.warning("git clone timeout/error for %s: %s", target.name, e)
        return False


async def _run_sigil_scan(directory: str) -> dict[str, Any] | None:
    """Run the Sigil scanner on a directory and return parsed JSON output."""
    # Use the Python scanner directly if available
    try:
        from api.services.scanner import scan_directory, count_scannable_files
        from api.services.scoring import compute_verdict
        from api.models import Finding

        findings = scan_directory(directory)
        score, verdict = compute_verdict(findings)
        file_count = count_scannable_files(directory)

        return {
            "score": round(score, 2),
            "verdict": verdict.value,
            "files_scanned": file_count,
            "findings": [f.model_dump(mode="json") for f in findings],
        }
    except ImportError:
        pass

    # Fall back to CLI
    try:
        proc = await asyncio.create_subprocess_exec(
            SIGIL_BINARY, "--format", "json", "scan", directory,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode()

        if output.strip():
            return json.loads(output)
    except (asyncio.TimeoutError, OSError, json.JSONDecodeError) as e:
        logger.warning("Sigil CLI scan failed: %s", e)

    return None


# ---------------------------------------------------------------------------
# Batch crawler
# ---------------------------------------------------------------------------


async def crawl_batch(
    targets: list[CrawlTarget],
    concurrency: int = 5,
) -> list[CrawlResult]:
    """Scan a batch of packages with bounded concurrency."""
    semaphore = asyncio.Semaphore(concurrency)
    results: list[CrawlResult] = []

    async def _scan_with_semaphore(target: CrawlTarget) -> CrawlResult:
        async with semaphore:
            logger.info("Scanning %s/%s...", target.ecosystem, target.name)
            return await scan_package(target)

    tasks = [_scan_with_semaphore(t) for t in targets]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return results


async def store_crawl_results(results: list[CrawlResult]) -> int:
    """Store crawl results in the public scan database. Returns count stored."""
    stored = 0
    for result in results:
        if result.error:
            logger.warning(
                "Skipping errored crawl: %s/%s: %s",
                result.target.ecosystem,
                result.target.name,
                result.error,
            )
            continue

        now = datetime.now(timezone.utc)
        row = {
            "id": result.scan_id,
            "ecosystem": result.target.ecosystem,
            "package_name": result.target.name,
            "package_version": result.target.version,
            "risk_score": result.risk_score,
            "verdict": result.verdict,
            "findings_count": result.findings_count,
            "files_scanned": result.files_scanned,
            "findings_json": result.findings,
            "metadata_json": {
                "url": result.target.url,
                "duration_ms": result.duration_ms,
                "crawler_version": "1.0.0",
                **result.target.metadata,
            },
            "scanned_at": now.isoformat(),
            "created_at": now.isoformat(),
        }

        try:
            # Import here to avoid circular imports at module level
            from api.database import db
            await db.insert("public_scans", row)
            stored += 1
        except Exception:
            logger.exception(
                "Failed to store crawl result for %s/%s",
                result.target.ecosystem,
                result.target.name,
            )

    return stored


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    """CLI entry point for the crawler."""
    import argparse

    parser = argparse.ArgumentParser(description="Sigil Package Crawler")
    parser.add_argument("--ecosystem", required=True, help="Ecosystem to scan")
    parser.add_argument("--package", help="Single package to scan")
    parser.add_argument("--url", help="Git URL to scan")
    parser.add_argument("--version", default="", help="Package version")
    parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent scans")
    args = parser.parse_args()

    targets = []
    if args.package:
        targets.append(
            CrawlTarget(
                ecosystem=args.ecosystem,
                name=args.package,
                version=args.version,
                url=args.url or "",
            )
        )

    if not targets:
        print("No targets specified. Use --package or provide a target list.")
        return

    results = await crawl_batch(targets, concurrency=args.concurrency)

    for r in results:
        status = "ERROR" if r.error else r.verdict
        print(
            f"  {r.target.ecosystem}/{r.target.name}: "
            f"{status} (score={r.risk_score:.1f}, findings={r.findings_count})"
        )

    # Store results
    from api.database import db
    await db.connect()
    stored = await store_crawl_results(results)
    print(f"\nStored {stored}/{len(results)} results in public scan database.")


if __name__ == "__main__":
    asyncio.run(_main())
