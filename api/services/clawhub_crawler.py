"""
Sigil API — ClawHub Registry Crawler

Automated pipeline for scanning every skill on ClawHub.

ClawHub API:
    Base URL: https://clawhub.ai/api/v1
    Auth: None required
    Rate limit: 120 reads/min per IP

Pipeline:
    1. Paginate /api/v1/skills to enumerate all skills
    2. Download each skill ZIP via /api/v1/download
    3. Run Sigil scan engine (all 8 phases including OpenClaw-specific)
    4. Store results in public_scans table
    5. Delta sync every 6 hours, full rescan weekly

Usage:
    # Full scan
    python -m api.services.clawhub_crawler --full

    # Delta scan (recently updated only)
    python -m api.services.clawhub_crawler --delta

    # Single skill
    python -m api.services.clawhub_crawler --skill todoist-cli
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

CLAWHUB_BASE = "https://clawhub.ai/api/v1"
RATE_LIMIT_PER_MIN = 120
REQUEST_DELAY = 60.0 / RATE_LIMIT_PER_MIN  # ~0.5s between requests


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ClawHubSkill:
    """A skill from the ClawHub registry."""

    slug: str
    name: str = ""
    description: str = ""
    version: str = ""
    author: str = ""
    stars: int = 0
    downloads: int = 0
    updated_at: str = ""
    homepage_url: str = ""
    source_url: str = ""
    moderation_status: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClawHubScanResult:
    """Result of scanning a ClawHub skill."""

    skill: ClawHubSkill
    scan_id: str = ""
    risk_score: float = 0.0
    verdict: str = "CLEAN"
    findings_count: int = 0
    files_scanned: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------


async def _http_get(
    url: str,
    params: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any] | bytes | None:
    """Make an HTTP GET request with rate limiting."""
    try:
        import httpx
    except ImportError:
        # Fall back to urllib — run in thread to avoid blocking the event loop
        import urllib.request
        import urllib.parse

        full_url = url
        if params:
            full_url = f"{url}?{urllib.parse.urlencode(params)}"

        def _sync_get() -> dict[str, Any] | bytes | None:
            _req = urllib.request.Request(full_url, headers={"Accept": "application/json"})
            try:
                with urllib.request.urlopen(_req, timeout=timeout) as resp:
                    _data = resp.read()
                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type:
                        return json.loads(_data)
                    return _data
            except Exception as e:
                logger.warning("HTTP GET failed: %s: %s", full_url, e)
                return None

        return await asyncio.to_thread(_sync_get)

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type:
                return resp.json()
            return resp.content
        except Exception as e:
            logger.warning("HTTP GET failed: %s: %s", url, e)
            return None


async def enumerate_skills(
    limit_per_page: int = 20,
    sort: str = "stars",
    max_pages: int | None = None,
) -> list[ClawHubSkill]:
    """Paginate through ClawHub to enumerate all skills.

    At 20 skills/page and ~5,700 total, this is ~285 pages.
    At 120 req/min, full enumeration takes ~2.4 minutes.
    """
    skills: list[ClawHubSkill] = []
    cursor: str | None = None
    page = 0

    while True:
        params: dict[str, Any] = {"limit": limit_per_page, "sort": sort}
        if cursor:
            params["cursor"] = cursor

        logger.info("Enumerating skills: page=%d cursor=%s", page, cursor or "start")
        data = await _http_get(f"{CLAWHUB_BASE}/skills", params=params)

        if not data or not isinstance(data, dict):
            break

        items = data.get("items", data.get("skills", []))
        if not items:
            break

        for item in items:
            skills.append(
                ClawHubSkill(
                    slug=item.get("slug", item.get("name", "")),
                    name=item.get("name", item.get("slug", "")),
                    description=item.get("description", ""),
                    version=item.get("version", item.get("latestVersion", "")),
                    author=item.get("author", item.get("owner", "")),
                    stars=item.get("stars", item.get("starCount", 0)),
                    downloads=item.get("downloads", item.get("downloadCount", 0)),
                    updated_at=item.get("updatedAt", item.get("updated_at", "")),
                    homepage_url=item.get("homepageUrl", ""),
                    source_url=item.get("sourceUrl", item.get("repository", "")),
                    moderation_status=item.get("moderationStatus", ""),
                    metadata=item,
                )
            )

        # Get next cursor
        cursor = data.get("nextCursor", data.get("cursor"))
        if not cursor:
            break

        page += 1
        if max_pages and page >= max_pages:
            logger.info("Reached max_pages=%d, stopping enumeration", max_pages)
            break

        # Rate limiting
        await asyncio.sleep(REQUEST_DELAY)

    logger.info("Enumerated %d skills from ClawHub", len(skills))
    return skills


async def download_skill(skill: ClawHubSkill, dest_dir: str) -> bool:
    """Download a skill ZIP and extract to dest_dir.

    Uses /api/v1/download?slug={slug}&version={version}
    """
    params: dict[str, Any] = {"slug": skill.slug}
    if skill.version:
        params["version"] = skill.version

    data = await _http_get(f"{CLAWHUB_BASE}/download", params=params, timeout=60)

    if not data or not isinstance(data, bytes):
        # Try fetching individual file
        file_data = await _http_get(
            f"{CLAWHUB_BASE}/skills/{skill.slug}/file",
            params={"path": "SKILL.md", "version": skill.version or "latest"},
        )
        if file_data:
            skill_md_path = os.path.join(dest_dir, "SKILL.md")
            if isinstance(file_data, bytes):
                Path(skill_md_path).write_bytes(file_data)
            elif isinstance(file_data, dict):
                content = file_data.get("content", json.dumps(file_data))
                Path(skill_md_path).write_text(content)
            else:
                Path(skill_md_path).write_text(str(file_data))
            return True
        logger.warning("Failed to download skill: %s", skill.slug)
        return False

    # Extract ZIP with path traversal protection
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            dest = Path(dest_dir).resolve()
            for member in zf.namelist():
                member_path = (dest / member).resolve()
                if not str(member_path).startswith(str(dest)):
                    logger.warning(
                        "Zip-slip attempt in skill %s: %s", skill.slug, member
                    )
                    return False
            zf.extractall(dest_dir)
        return True
    except zipfile.BadZipFile:
        # Maybe it's raw content, not a ZIP
        try:
            content = data.decode("utf-8", errors="replace")
            Path(os.path.join(dest_dir, "SKILL.md")).write_text(content)
            return True
        except Exception:
            logger.warning("Failed to extract skill ZIP: %s", skill.slug)
            return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


async def scan_skill(skill: ClawHubSkill) -> ClawHubScanResult:
    """Download and scan a single ClawHub skill."""
    scan_id = str(uuid4())
    result = ClawHubScanResult(skill=skill, scan_id=scan_id)
    start = datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory(prefix=f"sigil-clawhub-{skill.slug}-") as tmpdir:
        try:
            # Download
            ok = await download_skill(skill, tmpdir)
            if not ok:
                result.error = f"Failed to download skill: {skill.slug}"
                return result

            # Scan with OpenClaw-specific rules
            from api.services.openclaw_rules import scan_openclaw_directory
            from api.services.scoring import compute_verdict

            findings = scan_openclaw_directory(tmpdir)
            score, verdict = compute_verdict(findings)

            from api.services.scanner import count_scannable_files

            file_count = count_scannable_files(tmpdir)

            result.risk_score = round(score, 2)
            result.verdict = verdict.value
            result.findings_count = len(findings)
            result.files_scanned = file_count
            result.findings = [f.model_dump(mode="json") for f in findings]

        except Exception as e:
            logger.exception("Scan error for skill: %s", skill.slug)
            result.error = str(e)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    result.duration_ms = int(elapsed * 1000)

    return result


# ---------------------------------------------------------------------------
# Batch pipeline
# ---------------------------------------------------------------------------


async def scan_all_skills(
    concurrency: int = 5,
    max_skills: int | None = None,
    sort: str = "stars",
) -> list[ClawHubScanResult]:
    """Full ClawHub scan pipeline.

    1. Enumerate all skills
    2. Download and scan each with bounded concurrency
    3. Return results for storage
    """
    skills = await enumerate_skills(sort=sort)
    if max_skills:
        skills = skills[:max_skills]

    logger.info("Starting scan of %d ClawHub skills (concurrency=%d)", len(skills), concurrency)

    semaphore = asyncio.Semaphore(concurrency)
    results: list[ClawHubScanResult] = []

    async def _scan_with_limit(skill: ClawHubSkill) -> ClawHubScanResult:
        async with semaphore:
            await asyncio.sleep(REQUEST_DELAY)  # Rate limit
            return await scan_skill(skill)

    tasks = [_scan_with_limit(s) for s in skills]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions, converting them to error results
    results: list[ClawHubScanResult] = []
    for i, r in enumerate(raw_results):
        if isinstance(r, BaseException):
            logger.error("Scan task %d failed: %s", i, r)
            results.append(ClawHubScanResult(skill=skills[i], error=str(r)))
        else:
            results.append(r)

    # Summary
    verdicts: dict[str, int] = {}
    errors = 0
    for r in results:
        if r.error:
            errors += 1
        else:
            verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

    logger.info(
        "ClawHub scan complete: %d skills, %d errors, verdicts=%s",
        len(results),
        errors,
        verdicts,
    )

    return results


async def scan_delta(
    concurrency: int = 5,
    max_pages: int = 5,
) -> list[ClawHubScanResult]:
    """Delta scan — only recently updated skills.

    Used for the 6-hour cron sync.
    """
    skills = await enumerate_skills(sort="updated", max_pages=max_pages)
    logger.info("Delta scan: %d recently updated skills", len(skills))

    semaphore = asyncio.Semaphore(concurrency)

    async def _scan_with_limit(skill: ClawHubSkill) -> ClawHubScanResult:
        async with semaphore:
            await asyncio.sleep(REQUEST_DELAY)
            return await scan_skill(skill)

    return await asyncio.gather(*[_scan_with_limit(s) for s in skills])


async def store_clawhub_results(results: list[ClawHubScanResult]) -> int:
    """Store ClawHub scan results in the public_scans table."""
    from api.database import db

    stored = 0
    for result in results:
        if result.error:
            continue

        now = datetime.now(timezone.utc)
        row = {
            "id": result.scan_id,
            "ecosystem": "clawhub",
            "package_name": result.skill.slug,
            "package_version": result.skill.version,
            "risk_score": result.risk_score,
            "verdict": result.verdict,
            "findings_count": result.findings_count,
            "files_scanned": result.files_scanned,
            "findings_json": result.findings,
            "metadata_json": {
                "author": result.skill.author,
                "description": result.skill.description,
                "stars": result.skill.stars,
                "downloads": result.skill.downloads,
                "homepage_url": result.skill.homepage_url,
                "source_url": result.skill.source_url,
                "moderation_status": result.skill.moderation_status,
                "duration_ms": result.duration_ms,
                "sigil_version": "1.0.5",
                "crawler": "clawhub_crawler/1.0.0",
            },
            "scanned_at": now.isoformat(),
            "created_at": now.isoformat(),
        }

        try:
            await db.upsert(
                "public_scans",
                row,
                conflict_columns=["ecosystem", "package_name", "package_version"],
            )
            stored += 1
        except Exception:
            logger.exception("Failed to store result for skill: %s", result.skill.slug)

    return stored


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Sigil ClawHub Crawler")
    parser.add_argument("--full", action="store_true", help="Full registry scan")
    parser.add_argument("--delta", action="store_true", help="Delta scan (recent updates)")
    parser.add_argument("--skill", help="Scan a single skill by slug")
    parser.add_argument("--max", type=int, help="Max skills to scan")
    parser.add_argument("--concurrency", type=int, default=5, help="Max concurrent scans")
    parser.add_argument("--store", action="store_true", help="Store results in database")
    args = parser.parse_args()

    results: list[ClawHubScanResult] = []

    if args.skill:
        skill = ClawHubSkill(slug=args.skill, name=args.skill)
        result = await scan_skill(skill)
        results = [result]
    elif args.delta:
        results = await scan_delta(concurrency=args.concurrency)
    elif args.full:
        results = await scan_all_skills(
            concurrency=args.concurrency, max_skills=args.max
        )
    else:
        print("Specify --full, --delta, or --skill <slug>")
        return

    # Print summary
    print(f"\n{'='*60}")
    print(f"ClawHub Scan Results: {len(results)} skills")
    print(f"{'='*60}")

    verdicts: dict[str, int] = {}
    for r in results:
        status = "ERROR" if r.error else r.verdict
        verdicts[status] = verdicts.get(status, 0) + 1
        emoji = {"CLEAN": "+", "LOW_RISK": "~", "MEDIUM_RISK": "!", "HIGH_RISK": "!!", "CRITICAL": "!!!", "ERROR": "X"}.get(status, "?")
        print(f"  [{emoji}] {r.skill.slug}: {status} (score={r.risk_score:.1f}, findings={r.findings_count})")

    print(f"\nSummary: {verdicts}")

    if args.store:
        from api.database import db
        await db.connect()
        stored = await store_clawhub_results(results)
        print(f"Stored {stored}/{len(results)} results in database.")


if __name__ == "__main__":
    asyncio.run(_main())
