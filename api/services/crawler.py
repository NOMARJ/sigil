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
import base64
import hashlib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
from uuid import uuid4

logger = logging.getLogger(__name__)

SIGIL_BINARY = os.environ.get("SIGIL_BINARY", "sigil")

# PyPI packages are fetched as files: `pip download` would prepare a source
# distribution's metadata by running its setup.py or build backend on this
# host, before anything is scanned.
PYPI_JSON_BASE = "https://pypi.org/pypi"
PYPI_FILES_HOST = "files.pythonhosted.org"
MAX_PACKAGE_BYTES = 100 * 1024 * 1024

# npm packages are fetched as files too, from the public registry: `npm pack`
# runs a directory's or git checkout's prepare script even with
# --ignore-scripts, and packing by name follows whatever tarball the
# configured registry names, a git repository or `file:` path included.
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_TARBALL_HOST = "registry.npmjs.org"
# The abbreviated metadata npm itself installs from: versions, dist-tags and
# each version's `dist` (tarball URL, integrity, shasum).
NPM_METADATA_ACCEPT = "application/vnd.npm.install-v1+json"

# Registry names only. Anything else (a path, URL, git spec, `owner/repo`,
# an npm alias, a leading `-`) is refused before a URL is built from it.
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_PYPI_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
_NPM_NAME_RE = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$"
)
_NPM_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
# npm-package-arg's isFileType (its `.` inside `tar.gz` matches any
# character): npm reads a name or version ending so as a local tarball path,
# never as a registry package.
_NPM_FILE_TYPE_RE = re.compile(r"[.](?:tgz|tar.gz|tar)$", re.IGNORECASE)
_SHA1_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_PYPI_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.(?:tar\.gz|zip|whl)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    verdict: str = "LOW_RISK"
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
                result.verdict = scan_output.get("verdict", "LOW_RISK")
                result.findings_count = len(scan_output.get("findings", []))
                result.files_scanned = scan_output.get("files_scanned", 0)
                result.findings = scan_output.get("findings", [])

        except Exception as e:
            logger.exception("Crawl error for %s/%s", target.ecosystem, target.name)
            result.error = str(e)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    result.duration_ms = int(elapsed * 1000)

    return result


def _npm_metadata_url(target: CrawlTarget) -> str | None:
    """The registry metadata URL for a registry package name (a version, if
    given, must look like a version or tag); None for anything npm would
    read as a directory, tarball, URL, git spec or alias."""
    if not _NPM_NAME_RE.match(target.name) or _NPM_FILE_TYPE_RE.search(target.name):
        return None
    if target.version and (
        not _NPM_VERSION_RE.match(target.version)
        or _NPM_FILE_TYPE_RE.search(target.version)
    ):
        return None
    # A scoped name's `/` is escaped, as npm sends it (`@scope%2Fname`).
    return f"{NPM_REGISTRY}/{quote(target.name, safe='@')}"


def _npm_pick_release(meta: Any, version: str) -> tuple[str, dict[str, Any]] | None:
    """The release `version` names (an exact version, else a dist-tag;
    `latest` when empty) and its `dist`, from registry metadata."""
    versions = meta.get("versions") if isinstance(meta, dict) else None
    tags = meta.get("dist-tags") if isinstance(meta, dict) else None
    if not isinstance(versions, dict):
        return None
    wanted = version or "latest"
    if wanted not in versions and isinstance(tags, dict):
        tagged = tags.get(wanted)
        wanted = tagged if isinstance(tagged, str) else ""
    release = versions.get(wanted)
    dist = release.get("dist") if isinstance(release, dict) else None
    if not isinstance(dist, dict) or not _NPM_VERSION_RE.match(wanted):
        return None
    return wanted, dist


def _npm_integrity_ok(data: bytes, dist: dict[str, Any]) -> bool:
    """Check a tarball as npm checks a registry download: the strongest
    algorithm `dist.integrity` lists (Subresource Integrity) must match one
    of its hashes; without an integrity, `dist.shasum` (sha1, hex) must."""
    integrity = dist.get("integrity")
    if isinstance(integrity, str) and integrity.strip():
        hashes: list[tuple[str, str]] = []
        for item in integrity.split():
            algorithm, sep, rest = item.partition("-")
            if sep:
                hashes.append((algorithm, rest.split("?", 1)[0]))
        for algorithm in ("sha512", "sha384", "sha256", "sha1"):
            wanted = [digest for alg, digest in hashes if alg == algorithm]
            if wanted:
                got = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
                return got in wanted
        return False
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and _SHA1_HEX_RE.match(shasum):
        return hashlib.new("sha1", data).hexdigest() == shasum.lower()
    return False


async def _download_npm(target: CrawlTarget, dest: str) -> bool:
    """Download an npm registry package's tarball to dest and unpack it.

    No npm runs: `npm pack` runs a directory's or git checkout's prepare
    script even with --ignore-scripts, and packing by name follows whatever
    tarball the registry's metadata names. The crawler reads the public
    registry's metadata itself, takes the release's tarball only from the
    registry host over https, and keeps it only when it matches the
    registry's integrity (as `npm install` checks it), as the PyPI path
    checks its sha256.
    """
    meta_url = _npm_metadata_url(target)
    if meta_url is None:
        logger.warning(
            "Refusing npm target that is not a registry package: %r @ %r",
            target.name,
            target.version,
        )
        return False
    raw = await _http_get_bytes(
        meta_url, timeout=30, headers={"Accept": NPM_METADATA_ACCEPT}
    )
    if raw is None:
        return False
    try:
        meta = json.loads(raw)
    except ValueError:
        logger.warning("npm metadata for %s is not JSON", target.name)
        return False
    picked = _npm_pick_release(meta, target.version)
    if picked is None:
        logger.warning(
            "No npm release of %s matches %r", target.name, target.version or "latest"
        )
        return False
    version, dist = picked
    url = str(dist.get("tarball", ""))
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != NPM_TARBALL_HOST:
        logger.warning("Refusing npm tarball for %s: %r", target.name, url)
        return False
    data = await _http_get_bytes(url)
    if data is None:
        return False
    if not _npm_integrity_ok(data, dist):
        logger.warning("integrity mismatch for %s@%s", target.name, version)
        return False
    filename = f"{target.name.lstrip('@').replace('/', '-')}-{version}.tgz"
    tarball = Path(dest) / filename
    tarball.write_bytes(data)

    try:
        proc = await asyncio.create_subprocess_exec(
            "tar",
            "xzf",
            str(tarball),
            "-C",
            dest,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
        return True
    except (asyncio.TimeoutError, OSError) as e:
        logger.warning("unpack timeout/error for %s: %s", target.name, e)
        return False


def _pypi_json_url(target: CrawlTarget) -> str | None:
    """The PyPI JSON API URL for the target's release, or None when the name
    or version is not one PyPI could have."""
    if not _PYPI_NAME_RE.match(target.name):
        return None
    # PEP 503 normalisation, so the API answers without a redirect.
    name = re.sub(r"[-_.]+", "-", target.name).lower()
    if target.version:
        if not _PYPI_VERSION_RE.match(target.version):
            return None
        return f"{PYPI_JSON_BASE}/{quote(name)}/{quote(target.version)}/json"
    return f"{PYPI_JSON_BASE}/{quote(name)}/json"


def _pick_release_file(meta: Any) -> dict[str, Any] | None:
    """The release's source distribution (where setup.py-based attacks live),
    else its first wheel; never a yanked file or an unexpected file name."""
    files = meta.get("urls") if isinstance(meta, dict) else None
    if not isinstance(files, list):
        return None
    usable = [
        f
        for f in files
        if isinstance(f, dict)
        and not f.get("yanked")
        and _PYPI_FILE_RE.match(str(f.get("filename", "")))
    ]
    for kind in ("sdist", "bdist_wheel"):
        for f in usable:
            if f.get("packagetype") == kind:
                return f
    return None


async def _http_get_bytes(
    url: str, timeout: int = 120, headers: dict[str, str] | None = None
) -> bytes | None:
    """GET `url` with a size cap and no redirects. None on any failure."""
    try:
        import httpx
    except ImportError:
        logger.warning("httpx is not installed; cannot fetch %s", url)
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_PACKAGE_BYTES:
                        logger.warning("HTTP GET exceeded size limit: %s", url)
                        return None
                    chunks.append(chunk)
                return b"".join(chunks)
    except Exception as e:
        logger.warning("HTTP GET failed: %s: %s", url, e)
        return None


async def _download_pip(target: CrawlTarget, dest: str) -> bool:
    """Download a PyPI release file to dest directory without building it.

    `pip download` prepares a source distribution's metadata by running its
    setup.py or build backend on this host, before the scan. The crawler
    wants the sdist's source (setup.py is where install-time attacks live),
    so it takes the file from PyPI's JSON API and checks its sha256 instead:
    nothing in the package runs.
    """
    meta_url = _pypi_json_url(target)
    if meta_url is None:
        logger.warning(
            "Refusing PyPI target that is not a package name/version: %r @ %r",
            target.name,
            target.version,
        )
        return False
    raw = await _http_get_bytes(meta_url, timeout=30)
    if raw is None:
        return False
    try:
        meta = json.loads(raw)
    except ValueError:
        logger.warning("PyPI metadata for %s is not JSON", target.name)
        return False
    chosen = _pick_release_file(meta)
    if chosen is None:
        logger.warning("No downloadable release file for %s", target.name)
        return False
    url = str(chosen.get("url", ""))
    parsed = urlparse(url)
    filename = str(chosen["filename"])
    digests = chosen.get("digests")
    sha256 = str(digests.get("sha256", "") if isinstance(digests, dict) else "")
    if (
        parsed.scheme != "https"
        or parsed.hostname != PYPI_FILES_HOST
        or not _SHA256_RE.match(sha256)
    ):
        logger.warning("Refusing PyPI file for %s: %r", target.name, url)
        return False
    data = await _http_get_bytes(url)
    if data is None:
        return False
    if hashlib.sha256(data).hexdigest() != sha256:
        logger.warning("sha256 mismatch for %s (%s)", target.name, filename)
        return False
    (Path(dest) / filename).write_bytes(data)

    try:
        # Unpack archives
        for archive in Path(dest).glob("*.tar.gz"):
            unpack_cmd = ["tar", "xzf", str(archive), "-C", dest]
            proc2 = await asyncio.create_subprocess_exec(
                *unpack_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc2.communicate(), timeout=30)

        for pattern in ("*.zip", "*.whl"):
            for archive in Path(dest).glob(pattern):
                unpack_cmd = ["unzip", "-o", str(archive), "-d", dest]
                proc2 = await asyncio.create_subprocess_exec(
                    *unpack_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc2.communicate(), timeout=30)

        return True
    except (asyncio.TimeoutError, OSError) as e:
        logger.warning("unpack timeout/error for %s: %s", target.name, e)
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
            SIGIL_BINARY,
            "--format",
            "json",
            "scan",
            directory,
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
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Max concurrent scans"
    )
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
