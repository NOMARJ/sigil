"""
Sigil API — GitHub App Router

Handles GitHub App webhook events to auto-scan dependencies introduced
in pull requests and post scan results as PR comments.

POST /github/webhook         — Receive GitHub webhook events
GET  /github/install         — Installation redirect
POST /github/setup           — Complete GitHub App installation

The PR comment becomes the ad unit — every developer who sees the scan
result and thinks "I want that on my repos" is a new install.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Header, Request, status
from pydantic import BaseModel, Field

from api.config import settings
from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/github", tags=["github-app"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GitHubInstallation(BaseModel):
    """GitHub App installation record."""

    installation_id: int
    account_login: str = ""
    account_type: str = "User"
    repository_selection: str = "all"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PRScanComment(BaseModel):
    """Structured PR scan comment data."""

    repo_full_name: str
    pr_number: int
    new_dependencies: list[dict[str, Any]] = Field(default_factory=list)
    scan_results: list[dict[str, Any]] = Field(default_factory=list)
    overall_verdict: str = "LOW_RISK"
    overall_score: float = 0.0


# ---------------------------------------------------------------------------
# Dependency detection patterns
# ---------------------------------------------------------------------------

# package.json dependency additions
_NPM_DEP_PATTERN = re.compile(r'^\+\s*"([^"]+)"\s*:\s*"([^"]+)"', re.MULTILINE)

# requirements.txt / pip additions
_PIP_DEP_PATTERN = re.compile(r"^\+([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?$", re.MULTILINE)

# pyproject.toml dependency additions
_PYPROJECT_DEP_PATTERN = re.compile(
    r'^\+\s*"([a-zA-Z0-9_-]+)(?:[=<>!~]+([^"]+))?"', re.MULTILINE
)


def _extract_new_dependencies(diff: str) -> list[dict[str, str]]:
    """Parse a unified diff to extract newly added dependencies."""
    deps: list[dict[str, str]] = []
    current_file = ""

    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            # Extract filename
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


def _format_pr_comment(scan: PRScanComment) -> str:
    """Format a PR comment with scan results."""
    verdict_emoji = {
        "LOW_RISK": "white_check_mark",
        "MEDIUM_RISK": "warning",
        "HIGH_RISK": "x",
        "CRITICAL_RISK": "rotating_light",
    }

    emoji = verdict_emoji.get(scan.overall_verdict, "question")

    lines = [
        f"## :{emoji}: Sigil Security Scan",
        "",
    ]

    if not scan.new_dependencies:
        lines.extend(
            [
                "No new dependencies detected in this PR.",
                "",
                f"**Overall: {scan.overall_verdict}** (score: {scan.overall_score:.0f})",
            ]
        )
    else:
        lines.append(f"**{len(scan.new_dependencies)} new dependency(ies) detected:**")
        lines.append("")

        for result in scan.scan_results:
            dep_name = result.get("name", "unknown")
            dep_version = result.get("version", "")
            dep_eco = result.get("ecosystem", "")
            dep_verdict = result.get("verdict", "LOW_RISK")
            dep_score = result.get("risk_score", 0.0)
            dep_emoji = verdict_emoji.get(dep_verdict, "question")
            dep_findings = result.get("findings", [])

            version_str = (
                f"@{dep_version}" if dep_version and dep_version != "latest" else ""
            )
            lines.append(f"### :{dep_emoji}: `{dep_name}{version_str}` ({dep_eco})")
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

        lines.extend(
            [
                "---",
                f"**Overall: {scan.overall_verdict}** (score: {scan.overall_score:.0f})",
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "<sub>Automated scan by [Sigil](https://sigilsec.ai) "
            "&middot; Results are not a security certification "
            "&middot; [sigilsec.ai/terms](https://sigilsec.ai/terms)</sub>",
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------


def _verify_webhook_signature(
    payload: bytes, signature: str | None, secret: str
) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature or not secret:
        return False

    if signature.startswith("sha256="):
        signature = signature[7:]

    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/webhook",
    status_code=status.HTTP_200_OK,
    summary="GitHub App webhook endpoint",
)
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
) -> dict[str, Any]:
    """Handle incoming GitHub webhook events.

    Supported events:
    - installation: Track app installations
    - pull_request: Scan new dependencies in PRs
    - push: (future) Scan pushes to default branch
    """
    body = await request.body()

    # Verify webhook signature — reject if secret is configured and signature is invalid
    webhook_secret = settings.github_webhook_secret or ""
    if not webhook_secret:
        logger.warning(
            "SECURITY: SIGIL_GITHUB_WEBHOOK_SECRET is not set — "
            "webhook signature verification is disabled"
        )
    elif not _verify_webhook_signature(body, x_hub_signature_256, webhook_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )

    event = x_github_event or ""
    action = payload.get("action", "")

    logger.info("GitHub webhook: event=%s action=%s", event, action)

    if event == "installation":
        return await _handle_installation(payload, action)
    elif event == "pull_request":
        return await _handle_pull_request(payload, action)
    elif event == "ping":
        return {"status": "pong", "zen": payload.get("zen", "")}

    return {"status": "ignored", "event": event, "action": action}


async def _handle_installation(payload: dict[str, Any], action: str) -> dict[str, Any]:
    """Handle installation/uninstallation events."""
    installation = payload.get("installation", {})
    installation_id = installation.get("id", 0)
    account = installation.get("account", {})
    account_login = account.get("login", "")

    if action == "created":
        logger.info(
            "GitHub App installed: installation=%d account=%s",
            installation_id,
            account_login,
        )
        try:
            await db.insert(
                "github_installations",
                {
                    "id": str(installation_id),
                    "installation_id": installation_id,
                    "account_login": account_login,
                    "account_type": account.get("type", "User"),
                    "repository_selection": installation.get(
                        "repository_selection", "all"
                    ),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            logger.exception("Failed to persist installation %d", installation_id)

        return {"status": "installed", "installation_id": installation_id}

    elif action == "deleted":
        logger.info(
            "GitHub App uninstalled: installation=%d account=%s",
            installation_id,
            account_login,
        )
        try:
            await db.delete("github_installations", {"id": str(installation_id)})
        except Exception:
            logger.exception("Failed to remove installation %d", installation_id)

        return {"status": "uninstalled", "installation_id": installation_id}

    return {"status": "ignored", "action": action}


async def _handle_pull_request(payload: dict[str, Any], action: str) -> dict[str, Any]:
    """Handle pull_request events — scan new dependencies and prepare comments."""
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "action": action}

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})
    repo_full_name = repo.get("full_name", "")
    pr_number = pr.get("number", 0)

    logger.info(
        "PR scan triggered: repo=%s pr=#%d action=%s",
        repo_full_name,
        pr_number,
        action,
    )

    # Store the webhook event for async processing
    # In production, this would be picked up by a background worker
    # that fetches the PR diff, extracts dependencies, scans them,
    # and posts a comment via the GitHub API
    event_data = {
        "id": f"pr-{repo_full_name}-{pr_number}",
        "repo": repo_full_name,
        "pr_number": pr_number,
        "action": action,
        "pr_title": pr.get("title", ""),
        "pr_head_sha": pr.get("head", {}).get("sha", ""),
        "installation_id": payload.get("installation", {}).get("id", 0),
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        await db.upsert("github_pr_events", event_data)
    except Exception:
        logger.exception(
            "Failed to persist PR event for %s#%d", repo_full_name, pr_number
        )

    return {
        "status": "queued",
        "repo": repo_full_name,
        "pr_number": pr_number,
    }


@router.get(
    "/install",
    summary="Redirect to GitHub App installation",
)
async def install_redirect() -> dict[str, str]:
    """Return the GitHub App installation URL."""
    return {
        "url": "https://github.com/apps/sigil-security-bot",
        "message": "Visit this URL to install Sigil on your repositories.",
    }


@router.post(
    "/comment/preview",
    response_model=dict[str, Any],
    summary="Preview a PR comment for scan results",
)
async def preview_pr_comment(scan: PRScanComment) -> dict[str, Any]:
    """Preview what a PR comment would look like for given scan results.

    Useful for testing the comment format before deploying the GitHub App.
    """
    comment = _format_pr_comment(scan)
    return {
        "markdown": comment,
        "repo": scan.repo_full_name,
        "pr_number": scan.pr_number,
        "verdict": scan.overall_verdict,
    }
