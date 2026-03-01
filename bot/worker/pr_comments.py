"""
Sigil Bot — PR Comment Worker

Background worker that processes queued GitHub PR events:
  1. Polls github_pr_events table for pending events
  2. Fetches the PR diff via GitHub API
  3. Extracts newly added dependencies
  4. Looks up existing scan results (or triggers on-demand scans)
  5. Posts a formatted comment on the PR

Requires GitHub App credentials:
  - SIGIL_GITHUB_APP_ID
  - SIGIL_GITHUB_APP_PRIVATE_KEY
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# GitHub API base
GITHUB_API = "https://api.github.com"


# ---------------------------------------------------------------------------
# GitHub App authentication
# ---------------------------------------------------------------------------


def _generate_jwt(app_id: str, private_key: str) -> str:
    """Generate a GitHub App JWT for API authentication."""
    import jwt as pyjwt

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id,
    }
    return pyjwt.encode(payload, private_key, algorithm="RS256")


async def _get_installation_token(
    client: httpx.AsyncClient,
    app_id: str,
    private_key: str,
    installation_id: int,
) -> str | None:
    """Exchange a JWT for an installation access token."""
    try:
        jwt_token = _generate_jwt(app_id, private_key)
        resp = await client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
        return resp.json().get("token")
    except Exception:
        logger.exception(
            "Failed to get installation token for installation %d", installation_id
        )
        return None


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------


async def _fetch_pr_diff(
    client: httpx.AsyncClient,
    token: str,
    repo: str,
    pr_number: int,
) -> str | None:
    """Fetch the unified diff for a PR."""
    try:
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.diff",
            },
        )
        resp.raise_for_status()
        return resp.text
    except Exception:
        logger.exception("Failed to fetch diff for %s#%d", repo, pr_number)
        return None


async def _post_pr_comment(
    client: httpx.AsyncClient,
    token: str,
    repo: str,
    pr_number: int,
    body: str,
) -> str | None:
    """Post a comment on a PR. Returns the comment ID."""
    try:
        resp = await client.post(
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"body": body},
        )
        resp.raise_for_status()
        return str(resp.json().get("id", ""))
    except Exception:
        logger.exception("Failed to post comment on %s#%d", repo, pr_number)
        return None


async def _update_pr_comment(
    client: httpx.AsyncClient,
    token: str,
    repo: str,
    comment_id: str,
    body: str,
) -> bool:
    """Update an existing PR comment."""
    try:
        resp = await client.patch(
            f"{GITHUB_API}/repos/{repo}/issues/comments/{comment_id}",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"body": body},
        )
        resp.raise_for_status()
        return True
    except Exception:
        logger.exception("Failed to update comment %s on %s", comment_id, repo)
        return False


# ---------------------------------------------------------------------------
# Dependency extraction (re-uses logic from github_app router)
# ---------------------------------------------------------------------------

import re

_NPM_DEP_PATTERN = re.compile(r'^\+\s*"([^"]+)"\s*:\s*"([^"]+)"', re.MULTILINE)
_PIP_DEP_PATTERN = re.compile(r"^\+([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?$", re.MULTILINE)
_PYPROJECT_DEP_PATTERN = re.compile(
    r'^\+\s*"([a-zA-Z0-9_-]+)(?:[=<>!~]+([^"]+))?"', re.MULTILINE
)


def _extract_new_dependencies(diff: str) -> list[dict[str, str]]:
    """Parse a unified diff to extract newly added dependencies."""
    deps: list[dict[str, str]] = []
    current_file = ""

    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else ""
            continue

        if not line.startswith("+") or line.startswith("+++"):
            continue

        if current_file.endswith("package.json"):
            for match in _NPM_DEP_PATTERN.finditer(line):
                deps.append(
                    {
                        "ecosystem": "npm",
                        "name": match.group(1),
                        "version": match.group(2),
                        "file": current_file,
                    }
                )

        elif current_file.endswith(("requirements.txt", "requirements-dev.txt")):
            for match in _PIP_DEP_PATTERN.finditer(line):
                deps.append(
                    {
                        "ecosystem": "pip",
                        "name": match.group(1),
                        "version": match.group(2) or "latest",
                        "file": current_file,
                    }
                )

        elif current_file.endswith("pyproject.toml"):
            for match in _PYPROJECT_DEP_PATTERN.finditer(line):
                deps.append(
                    {
                        "ecosystem": "pip",
                        "name": match.group(1),
                        "version": match.group(2) or "latest",
                        "file": current_file,
                    }
                )

    return deps


# ---------------------------------------------------------------------------
# Scan result lookup
# ---------------------------------------------------------------------------


async def _lookup_scan(
    db: Any,
    ecosystem: str,
    name: str,
) -> dict[str, Any] | None:
    """Look up the latest scan result for a package from the public_scans table."""
    try:
        # Map "pip" ecosystem to "pypi" for DB lookup
        eco = "pypi" if ecosystem == "pip" else ecosystem
        rows = await db.select(
            "public_scans",
            filters={"ecosystem": eco, "package_name": name},
            limit=1,
        )
        return rows[0] if rows else None
    except Exception:
        logger.debug("Scan lookup failed for %s/%s", ecosystem, name)
        return None


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------


def _format_comment(
    deps: list[dict[str, str]],
    scan_results: list[dict[str, Any]],
    overall_verdict: str,
    overall_score: float,
) -> str:
    """Format the PR comment markdown."""
    verdict_emoji = {
        "LOW_RISK": ":white_check_mark:",
        "MEDIUM_RISK": ":warning:",
        "HIGH_RISK": ":x:",
        "CRITICAL_RISK": ":rotating_light:",
    }

    emoji = verdict_emoji.get(overall_verdict, ":question:")
    lines = [f"## {emoji} Sigil Security Scan", ""]

    if not deps:
        lines.extend([
            "No new dependencies detected in this PR.",
            "",
            f"**Overall: {overall_verdict}** (score: {overall_score:.0f})",
        ])
    else:
        lines.append(f"**{len(deps)} new dependency(ies) detected:**")
        lines.append("")

        for result in scan_results:
            dep_name = result.get("name", "unknown")
            dep_version = result.get("version", "")
            dep_eco = result.get("ecosystem", "")
            dep_verdict = result.get("verdict", "LOW_RISK")
            dep_score = result.get("risk_score", 0.0)
            dep_emoji = verdict_emoji.get(dep_verdict, ":question:")
            dep_findings = result.get("findings", [])

            version_str = (
                f"@{dep_version}" if dep_version and dep_version != "latest" else ""
            )
            lines.append(f"### {dep_emoji} `{dep_name}{version_str}` ({dep_eco})")
            lines.append(f"**Risk Score: {dep_score:.0f}** — **{dep_verdict}**")
            lines.append("")

            if dep_findings:
                for finding in dep_findings[:5]:
                    sev = finding.get("severity", "MEDIUM")
                    phase = finding.get("phase", "unknown")
                    desc = finding.get("description", finding.get("rule", ""))
                    file_path = finding.get("file", "")
                    line_no = finding.get("line", 0)
                    loc = f" `{file_path}:{line_no}`" if file_path else ""
                    lines.append(f"- **{sev}** [{phase}]{loc}: {desc}")

                if len(dep_findings) > 5:
                    lines.append(f"- ... and {len(dep_findings) - 5} more findings")
                lines.append("")

        lines.extend([
            "---",
            f"**Overall: {overall_verdict}** (score: {overall_score:.0f})",
        ])

    lines.extend([
        "",
        "---",
        "<sub>Automated scan by [Sigil](https://sigilsec.ai) "
        "&middot; [How this works](https://sigilsec.ai/bot) "
        "&middot; Results are not a security certification "
        "&middot; [sigilsec.ai/terms](https://sigilsec.ai/terms)</sub>",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Event processing
# ---------------------------------------------------------------------------


async def _process_pr_event(
    event: dict[str, Any],
    db: Any,
    client: httpx.AsyncClient,
    token: str,
) -> dict[str, Any]:
    """Process a single PR event: fetch diff, scan deps, post comment.

    Returns a dict with the processing results to store back on the event row.
    """
    repo = event["repo"]
    pr_number = event["pr_number"]

    # 1. Fetch PR diff
    diff = await _fetch_pr_diff(client, token, repo, pr_number)
    if not diff:
        return {"status": "error", "error": "Failed to fetch PR diff"}

    # 2. Extract new dependencies
    deps = _extract_new_dependencies(diff)
    logger.info(
        "PR %s#%d: found %d new dependencies",
        repo, pr_number, len(deps),
    )

    # 3. Look up scan results for each dependency
    scan_results: list[dict[str, Any]] = []
    max_score = 0.0
    worst_verdict = "LOW_RISK"
    verdict_rank = {"LOW_RISK": 0, "MEDIUM_RISK": 1, "HIGH_RISK": 2, "CRITICAL_RISK": 3}

    for dep in deps:
        scan = await _lookup_scan(db, dep["ecosystem"], dep["name"])
        if scan:
            result = {
                "name": dep["name"],
                "version": dep.get("version", ""),
                "ecosystem": dep["ecosystem"],
                "verdict": scan.get("verdict", "LOW_RISK"),
                "risk_score": scan.get("risk_score", 0.0),
                "findings": scan.get("findings", []),
            }
        else:
            # No existing scan — report as unknown
            result = {
                "name": dep["name"],
                "version": dep.get("version", ""),
                "ecosystem": dep["ecosystem"],
                "verdict": "LOW_RISK",
                "risk_score": 0.0,
                "findings": [],
                "note": "No prior scan available — package not yet in Sigil database",
            }

        scan_results.append(result)

        dep_score = result.get("risk_score", 0.0)
        dep_verdict = result.get("verdict", "LOW_RISK")
        if dep_score > max_score:
            max_score = dep_score
        if verdict_rank.get(dep_verdict, 0) > verdict_rank.get(worst_verdict, 0):
            worst_verdict = dep_verdict

    # 4. Format and post comment
    comment_body = _format_comment(deps, scan_results, worst_verdict, max_score)

    existing_comment_id = event.get("comment_id")
    if existing_comment_id:
        # Update existing comment (e.g., on synchronize events)
        ok = await _update_pr_comment(
            client, token, repo, existing_comment_id, comment_body
        )
        comment_id = existing_comment_id if ok else None
    else:
        comment_id = await _post_pr_comment(
            client, token, repo, pr_number, comment_body
        )

    return {
        "status": "completed" if comment_id else "error",
        "comment_id": comment_id,
        "scan_results": {
            "dependencies": len(deps),
            "overall_verdict": worst_verdict,
            "overall_score": max_score,
            "results": scan_results,
        },
    }


# ---------------------------------------------------------------------------
# Worker loop
# ---------------------------------------------------------------------------


async def pr_comment_worker(
    poll_interval: int = 30,
    batch_size: int = 5,
) -> None:
    """Long-running worker that polls github_pr_events for pending events.

    Processes events in batches, posts PR comments, and updates event status.
    Requires GitHub App credentials to be configured in the API settings.
    """
    from api.config import settings
    from api.database import db

    if not settings.github_app_configured:
        logger.error(
            "PR comment worker cannot start: GitHub App not configured. "
            "Set SIGIL_GITHUB_APP_ID and SIGIL_GITHUB_APP_PRIVATE_KEY."
        )
        return

    logger.info("PR comment worker starting (poll_interval=%ds)", poll_interval)

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            try:
                # Fetch pending events
                try:
                    events = await db.select(
                        "github_pr_events",
                        filters={"status": "pending"},
                        limit=batch_size,
                        order_by="created_at",
                        order_desc=False,
                    )
                except TypeError:
                    events = await db.select(
                        "github_pr_events",
                        filters={"status": "pending"},
                        limit=batch_size,
                    )

                if not events:
                    await asyncio.sleep(poll_interval)
                    continue

                logger.info("Processing %d pending PR events", len(events))

                for event in events:
                    event_id = event.get("id", "")
                    installation_id = event.get("installation_id", 0)

                    # Mark as processing
                    await db.update(
                        "github_pr_events",
                        {"id": event_id},
                        {"status": "processing"},
                    )

                    # Get installation token
                    token = await _get_installation_token(
                        client,
                        settings.github_app_id,
                        settings.github_app_private_key,
                        installation_id,
                    )
                    if not token:
                        await db.update(
                            "github_pr_events",
                            {"id": event_id},
                            {
                                "status": "error",
                                "processed_at": datetime.now(timezone.utc).isoformat(),
                            },
                        )
                        continue

                    # Process the event
                    result = await _process_pr_event(event, db, client, token)

                    # Update event with results
                    update_data: dict[str, Any] = {
                        "status": result["status"],
                        "processed_at": datetime.now(timezone.utc).isoformat(),
                    }
                    if result.get("comment_id"):
                        update_data["comment_id"] = result["comment_id"]
                    if result.get("scan_results"):
                        update_data["scan_results"] = json.dumps(result["scan_results"])

                    await db.update(
                        "github_pr_events",
                        {"id": event_id},
                        update_data,
                    )

                    logger.info(
                        "PR event %s: %s (%s#%d)",
                        event_id,
                        result["status"],
                        event.get("repo", ""),
                        event.get("pr_number", 0),
                    )

            except Exception:
                logger.exception("PR comment worker error")
                await asyncio.sleep(poll_interval)
