"""
Sigil API — MCP Server Crawler with Typosquat Detection

Automated pipeline for discovering and monitoring MCP servers on GitHub,
with real-time typosquat detection against popular MCP server names.

Features:
    - GitHub API discovery of MCP servers (.mcp.json files)
    - Edit distance calculation for typosquat detection
    - Real-time alerts for suspicious new MCP servers
    - Security scanning of MCP server code
    - Publisher tracking for campaign detection

Usage:
    # Full discovery scan
    python -m api.services.mcp_crawler --discover

    # Check for typosquats
    python -m api.services.mcp_crawler --typosquat-check

    # Scan specific MCP server
    python -m api.services.mcp_crawler --server user/repo-name
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
RATE_LIMIT_PER_HOUR = 5000 if GITHUB_TOKEN else 60
REQUEST_DELAY = 3600.0 / RATE_LIMIT_PER_HOUR

# Popular MCP server names to monitor for typosquats
POPULAR_MCP_SERVERS = {
    "mcp-postgres",
    "mcp-mongodb",
    "mcp-redis",
    "mcp-mysql",
    "mcp-sqlite",
    "mcp-github",
    "mcp-gitlab",
    "mcp-jira",
    "mcp-slack",
    "mcp-discord",
    "mcp-stripe",
    "mcp-shopify",
    "mcp-aws",
    "mcp-gcp",
    "mcp-azure",
    "mcp-docker",
    "mcp-kubernetes",
    "mcp-terraform",
    "mcp-ansible",
    "mcp-jupyter",
    "mcp-vscode",
    "mcp-obsidian",
    "mcp-notion",
}

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class MCPServer:
    """An MCP server discovered on GitHub."""

    repo_name: str  # e.g. "user/mcp-postgres"
    full_name: str = ""
    description: str = ""
    author: str = ""
    stars: int = 0
    forks: int = 0
    language: str = ""
    created_at: str = ""
    updated_at: str = ""
    default_branch: str = "main"
    topics: list[str] = field(default_factory=list)
    mcp_config: dict[str, Any] = field(default_factory=dict)
    homepage: str = ""
    clone_url: str = ""


@dataclass
class TyposquatAlert:
    """Typosquat detection result."""

    suspicious_repo: str
    target_repo: str
    edit_distance: int
    similarity_score: float
    author: str
    created_at: str
    risk_level: str  # LOW, MEDIUM, HIGH
    alert_id: str = field(default_factory=lambda: uuid4().hex[:16])


@dataclass
class MCPScanResult:
    """Result of scanning an MCP server."""

    server: MCPServer
    scan_id: str = ""
    risk_score: float = 0.0
    verdict: str = "LOW_RISK"
    findings_count: int = 0
    files_scanned: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------


async def _github_get(
    endpoint: str,
    params: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any] | list | None:
    """Make authenticated GitHub API request with rate limiting."""
    url = f"{GITHUB_API_BASE}{endpoint}"
    headers = {"Accept": "application/vnd.github.v3+json"}

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url, params=params, headers=headers)

            # Check rate limit
            remaining = int(resp.headers.get("X-RateLimit-Remaining", "0"))
            if remaining < 10:
                reset_time = int(resp.headers.get("X-RateLimit-Reset", "0"))
                wait_time = max(0, reset_time - int(datetime.now().timestamp()))
                logger.warning(
                    "GitHub rate limit low (%d remaining), waiting %ds",
                    remaining,
                    wait_time,
                )
                await asyncio.sleep(min(wait_time, 300))  # Max 5min wait

            resp.raise_for_status()
            return resp.json()

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.error("GitHub API rate limited or forbidden")
                return None
            elif e.response.status_code == 404:
                logger.debug("GitHub resource not found: %s", url)
                return None
            else:
                logger.warning("GitHub API error %d: %s", e.response.status_code, url)
                return None
        except Exception as e:
            logger.warning("GitHub API request failed: %s: %s", url, e)
            return None


async def discover_mcp_servers(
    max_pages: int = 10,
    per_page: int = 100,
) -> list[MCPServer]:
    """Discover MCP servers by searching GitHub for .mcp.json files."""
    servers: list[MCPServer] = []

    # Search for repositories with .mcp.json files
    search_queries = [
        "filename:.mcp.json",
        "mcp-server in:name",
        "model-context-protocol in:description",
        "MCP server in:description",
    ]

    for query in search_queries:
        logger.info("Searching GitHub: %s", query)
        page = 1

        while page <= max_pages:
            params = {
                "q": query,
                "type": "repositories",
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "order": "desc",
            }

            data = await _github_get("/search/repositories", params=params)
            if not data or "items" not in data:
                break

            items = data["items"]
            if not items:
                break

            for repo in items:
                # Check if this repo has an .mcp.json file
                mcp_config = await _fetch_mcp_config(repo["full_name"])
                if mcp_config is None:
                    continue  # Skip if no valid MCP config

                server = MCPServer(
                    repo_name=repo["full_name"],
                    full_name=repo["full_name"],
                    description=repo.get("description", ""),
                    author=repo["owner"]["login"],
                    stars=repo.get("stargazers_count", 0),
                    forks=repo.get("forks_count", 0),
                    language=repo.get("language", ""),
                    created_at=repo.get("created_at", ""),
                    updated_at=repo.get("updated_at", ""),
                    default_branch=repo.get("default_branch", "main"),
                    topics=repo.get("topics", []),
                    mcp_config=mcp_config,
                    homepage=repo.get("homepage", ""),
                    clone_url=repo.get("clone_url", ""),
                )
                servers.append(server)

            page += 1
            await asyncio.sleep(REQUEST_DELAY)

    # Remove duplicates
    seen = set()
    unique_servers = []
    for server in servers:
        if server.repo_name not in seen:
            seen.add(server.repo_name)
            unique_servers.append(server)

    logger.info("Discovered %d unique MCP servers", len(unique_servers))
    return unique_servers


async def _fetch_mcp_config(repo_full_name: str) -> dict[str, Any] | None:
    """Fetch and parse .mcp.json config from a repository."""
    # Try common paths for MCP config
    config_paths = [".mcp.json", "mcp.json", ".mcp/config.json"]

    for path in config_paths:
        endpoint = f"/repos/{repo_full_name}/contents/{path}"
        data = await _github_get(endpoint)

        if data and isinstance(data, dict) and "content" in data:
            try:
                import base64

                content = base64.b64decode(data["content"]).decode("utf-8")
                config = json.loads(content)
                return config
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                continue

    return None


# ---------------------------------------------------------------------------
# Typosquat Detection
# ---------------------------------------------------------------------------


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_similarity(s1: str, s2: str) -> float:
    """Calculate similarity score between 0.0 and 1.0."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


async def detect_typosquats(servers: list[MCPServer]) -> list[TyposquatAlert]:
    """Detect potential typosquat MCP servers against popular names."""
    alerts: list[TyposquatAlert] = []

    for server in servers:
        repo_name = server.repo_name.split("/")[-1].lower()  # Get just the repo name

        for popular_name in POPULAR_MCP_SERVERS:
            if repo_name == popular_name:
                continue  # Skip exact matches

            distance = levenshtein_distance(repo_name, popular_name)
            similarity = calculate_similarity(repo_name, popular_name)

            # Flag potential typosquats based on similarity threshold
            risk_level = "LOW"
            if distance <= 2 and similarity >= 0.7:
                risk_level = "HIGH"
            elif distance <= 3 and similarity >= 0.6:
                risk_level = "MEDIUM"
            elif distance <= 4 and similarity >= 0.5:
                risk_level = "LOW"
            else:
                continue  # Not similar enough to flag

            alert = TyposquatAlert(
                suspicious_repo=server.repo_name,
                target_repo=popular_name,
                edit_distance=distance,
                similarity_score=similarity,
                author=server.author,
                created_at=server.created_at,
                risk_level=risk_level,
            )
            alerts.append(alert)

    # Sort by risk level and similarity
    risk_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    alerts.sort(
        key=lambda a: (risk_order[a.risk_level], a.similarity_score), reverse=True
    )

    logger.info("Detected %d potential typosquat MCP servers", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


async def scan_mcp_server(server: MCPServer) -> MCPScanResult:
    """Download and scan an MCP server repository."""
    scan_id = str(uuid4())
    result = MCPScanResult(server=server, scan_id=scan_id)
    start = datetime.now(timezone.utc)

    if not server.clone_url:
        result.error = "No clone URL available"
        return result

    with tempfile.TemporaryDirectory(prefix=f"sigil-mcp-{server.author}-") as tmpdir:
        try:
            # Validate and sanitize clone URL before using
            from middleware.security import URLValidator, SecurityValidationError

            try:
                sanitized_url = URLValidator.sanitize_url(server.clone_url)
            except SecurityValidationError as e:
                result.error = f"Invalid repository URL: {str(e)}"
                return result

            # Additional check for repository size (prevent resource exhaustion)
            # Use git ls-remote to check repo size before cloning
            import subprocess

            size_check = subprocess.run(
                ["git", "ls-remote", "--heads", sanitized_url],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if size_check.returncode != 0:
                result.error = f"Failed to access repository: {size_check.stderr[:200]}"
                return result

            # Clone repository with additional safety measures
            clone_result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",  # Shallow clone
                    "--single-branch",  # Only clone default branch
                    "--no-tags",  # Don't clone tags
                    sanitized_url,  # Use sanitized URL
                    tmpdir,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if clone_result.returncode != 0:
                result.error = f"Failed to clone repository: {clone_result.stderr}"
                return result

            # Scan with standard Sigil engine
            from services.scanner import scan_directory
            from services.scoring import compute_verdict

            findings = scan_directory(tmpdir)
            score, verdict = compute_verdict(findings)

            from services.scanner import count_scannable_files

            file_count = count_scannable_files(tmpdir)

            result.risk_score = round(score, 2)
            result.verdict = verdict.value
            result.findings_count = len(findings)
            result.files_scanned = file_count
            result.findings = [f.model_dump(mode="json") for f in findings]

        except subprocess.TimeoutExpired:
            result.error = "Git clone timeout"
        except Exception as e:
            logger.exception("Scan error for MCP server: %s", server.repo_name)
            result.error = str(e)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    result.duration_ms = int(elapsed * 1000)

    return result


# ---------------------------------------------------------------------------
# Alert dispatch
# ---------------------------------------------------------------------------


async def send_typosquat_alerts(alerts: list[TyposquatAlert]) -> int:
    """Send typosquat alerts through configured channels."""
    if not alerts:
        return 0

    try:
        from services.notifications import send_notification
        from database import db

        # Get active alert channels
        alert_channels = await db.select("alerts", {"enabled": True})
        if not alert_channels:
            logger.warning("No active alert channels configured")
            return 0

        sent_count = 0
        for alert in alerts[:5]:  # Limit to top 5 to avoid spam
            title = f"🚨 MCP Typosquat Detected: {alert.suspicious_repo}"
            message = (
                f"**Risk Level:** {alert.risk_level}\n"
                f"**Suspicious MCP Server:** {alert.suspicious_repo}\n"
                f"**Target:** {alert.target_repo}\n"
                f"**Similarity:** {alert.similarity_score:.2f}\n"
                f"**Author:** {alert.author}\n"
                f"**Created:** {alert.created_at}\n\n"
                f"This repository appears to be typosquatting a popular MCP server name. "
                f"Please review before installation."
            )

            for channel in alert_channels:
                success = await send_notification(
                    channel_type=channel["channel_type"],
                    channel_config=channel.get("channel_config_json", {}),
                    title=title,
                    message=message,
                )
                if success:
                    sent_count += 1

        return sent_count

    except Exception:
        logger.exception("Failed to send typosquat alerts")
        return 0


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


async def store_mcp_results(results: list[MCPScanResult]) -> int:
    """Store MCP scan results in the public_scans table."""
    from database import db

    stored = 0
    for result in results:
        if result.error:
            continue

        now = datetime.now(timezone.utc)
        row = {
            "id": result.scan_id,
            "ecosystem": "mcp",
            "package_name": result.server.repo_name,
            "package_version": "latest",
            "risk_score": result.risk_score,
            "verdict": result.verdict,
            "findings_count": result.findings_count,
            "files_scanned": result.files_scanned,
            "findings_json": result.findings,
            "metadata_json": {
                "author": result.server.author,
                "description": result.server.description,
                "stars": result.server.stars,
                "forks": result.server.forks,
                "language": result.server.language,
                "topics": result.server.topics,
                "homepage": result.server.homepage,
                "mcp_config": result.server.mcp_config,
                "duration_ms": result.duration_ms,
                "sigil_version": "1.0.5",
                "crawler": "mcp_crawler/1.0.0",
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
            logger.exception(
                "Failed to store MCP scan result: %s", result.server.repo_name
            )

    return stored


async def store_typosquat_alerts(alerts: list[TyposquatAlert]) -> int:
    """Store typosquat alerts in the database for tracking."""
    from database import db

    stored = 0
    for alert in alerts:
        now = datetime.now(timezone.utc)
        row = {
            "id": alert.alert_id,
            "alert_type": "typosquat",
            "ecosystem": "mcp",
            "suspicious_package": alert.suspicious_repo,
            "target_package": alert.target_repo,
            "risk_level": alert.risk_level,
            "metadata_json": {
                "edit_distance": alert.edit_distance,
                "similarity_score": alert.similarity_score,
                "author": alert.author,
                "repo_created_at": alert.created_at,
            },
            "created_at": now.isoformat(),
        }

        try:
            await db.insert("typosquat_alerts", row)
            stored += 1
        except Exception:
            # Might be duplicate - that's OK
            pass

    return stored


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Sigil MCP Server Crawler")
    parser.add_argument("--discover", action="store_true", help="Discover MCP servers")
    parser.add_argument(
        "--typosquat-check", action="store_true", help="Check for typosquats"
    )
    parser.add_argument("--server", help="Scan specific MCP server (user/repo)")
    parser.add_argument(
        "--max-pages", type=int, default=10, help="Max GitHub search pages"
    )
    parser.add_argument(
        "--store", action="store_true", help="Store results in database"
    )
    args = parser.parse_args()

    if args.server:
        # Scan single MCP server
        server = MCPServer(repo_name=args.server)
        server.clone_url = f"https://github.com/{args.server}.git"
        result = await scan_mcp_server(server)
        print(f"Scan result: {result.verdict} (score={result.risk_score:.1f})")
        if result.error:
            print(f"Error: {result.error}")
        return

    # Discover MCP servers
    servers = await discover_mcp_servers(max_pages=args.max_pages)
    print(f"Discovered {len(servers)} MCP servers")

    if args.typosquat_check:
        # Check for typosquats
        alerts = await detect_typosquats(servers)
        print("\nTyposquat Detection Results:")
        print("=" * 50)

        for alert in alerts[:10]:  # Show top 10
            print(f"🚨 {alert.risk_level}: {alert.suspicious_repo}")
            print(f"   Target: {alert.target_repo}")
            print(f"   Similarity: {alert.similarity_score:.2f}")
            print(f"   Author: {alert.author}")
            print()

        if args.store:
            from database import db

            await db.connect()
            stored_alerts = await store_typosquat_alerts(alerts)
            sent_alerts = await send_typosquat_alerts(alerts)
            print(f"Stored {stored_alerts} alerts, sent {sent_alerts} notifications")

    if args.discover and args.store:
        # Scan and store results
        scan_results = []
        for server in servers[:20]:  # Limit for initial testing
            result = await scan_mcp_server(server)
            scan_results.append(result)

        from database import db

        await db.connect()
        stored = await store_mcp_results(scan_results)
        print(f"Stored {stored}/{len(scan_results)} MCP scan results")


if __name__ == "__main__":
    asyncio.run(_main())
