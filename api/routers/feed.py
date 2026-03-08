"""
Sigil API — Public Threat Feed Endpoints

RSS 2.0 feed and JSON API for recent scan results.
No authentication required — these are public outputs of the bot pipeline.

Endpoints:
    GET /feed.xml                   — RSS 2.0 feed (all scans, filterable)
    GET /feed/threats.xml           — RSS feed: HIGH_RISK + CRITICAL_RISK only
    GET /feed/clawhub.xml           — RSS feed: ClawHub ecosystem only
    GET /feed/pypi.xml              — RSS feed: PyPI ecosystem only
    GET /feed/npm.xml               — RSS feed: npm ecosystem only
    GET /feed/github.xml            — RSS feed: GitHub ecosystem only
    GET /api/v1/feed                — JSON feed with filtering
    GET /api/v1/feed/alerts         — Recent HIGH/CRITICAL alerts
    GET /api/v1/feed/stats          — Bot pipeline statistics
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query, HTTPException, status
from fastapi.responses import Response
from api.middleware.security import InputSanitizer, SecurityValidationError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["feed"])

# Minimal valid RSS feed returned when the bot publisher is unavailable
_FALLBACK_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sigil Security Scanner — Threat Feed</title>
    <link>https://sigilsec.ai/scans</link>
    <description>Automated security scan results for AI agent packages</description>
  </channel>
</rss>"""


async def _generate_rss(
    ecosystem: str | None = None,
    verdict: str | None = None,
) -> Response:
    """Shared helper: generate an RSS response with optional filters."""
    try:
        from bot.publisher import generate_rss_feed

        xml = await generate_rss_feed(ecosystem=ecosystem, verdict_filter=verdict)
        return Response(content=xml, media_type="application/rss+xml")
    except Exception:
        return Response(content=_FALLBACK_RSS, media_type="application/rss+xml")


# ---------------------------------------------------------------------------
# RSS 2.0 feed endpoints
# ---------------------------------------------------------------------------


@router.get("/feed.xml", summary="RSS 2.0 threat feed")
async def rss_feed(
    ecosystem: str | None = Query(
        None,
        description="Filter by ecosystem (clawhub, pypi, npm, github)",
        min_length=1,
        max_length=20,
    ),
    verdict: str | None = Query(
        None,
        description="Comma-separated verdicts (e.g. high_risk,critical_risk)",
        max_length=200,
    ),
) -> Response:
    """Return RSS 2.0 XML feed of recent scan results.

    Supports query parameter filtering:
    - `/feed.xml` — all scans, all ecosystems
    - `/feed.xml?verdict=high_risk,critical_risk` — threats only
    - `/feed.xml?ecosystem=clawhub` — ClawHub only
    - `/feed.xml?ecosystem=pypi&verdict=critical_risk` — combined filters
    """
    # Validate and sanitize inputs
    try:
        if ecosystem:
            ecosystem = InputSanitizer.sanitize_ecosystem(ecosystem)
        if verdict:
            verdict = InputSanitizer.sanitize_verdict(verdict)
    except SecurityValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return await _generate_rss(ecosystem=ecosystem, verdict=verdict)


@router.get("/feed/threats.xml", summary="RSS feed — threats only")
async def rss_threats() -> Response:
    """Return RSS feed containing only HIGH_RISK and CRITICAL_RISK scans."""
    return await _generate_rss(verdict="high_risk,critical_risk")


@router.get("/feed/clawhub.xml", summary="RSS feed — ClawHub only")
async def rss_clawhub() -> Response:
    """Return RSS feed for ClawHub ecosystem scans only."""
    return await _generate_rss(ecosystem="clawhub")


@router.get("/feed/pypi.xml", summary="RSS feed — PyPI only")
async def rss_pypi() -> Response:
    """Return RSS feed for PyPI ecosystem scans only."""
    return await _generate_rss(ecosystem="pypi")


@router.get("/feed/npm.xml", summary="RSS feed — npm only")
async def rss_npm() -> Response:
    """Return RSS feed for npm ecosystem scans only."""
    return await _generate_rss(ecosystem="npm")


@router.get("/feed/github.xml", summary="RSS feed — GitHub only")
async def rss_github() -> Response:
    """Return RSS feed for GitHub MCP server scans only."""
    return await _generate_rss(ecosystem="github")


@router.get("/feed/mcp.xml", summary="RSS feed — MCP servers only")
async def rss_mcp() -> Response:
    """Return RSS feed for MCP server scans only."""
    return await _generate_rss(ecosystem="mcp")


@router.get("/feed/watchdog.xml", summary="RSS feed — MCP Watchdog typosquat alerts")
async def rss_mcp_watchdog() -> Response:
    """Return RSS feed for MCP typosquat alerts from Sigil Watchdog."""
    try:
        from api.database import db

        # Get recent typosquat alerts
        alerts = await db.select(
            "typosquat_alerts",
            filters={"ecosystem": "mcp"},
            limit=50,
            order_by="created_at",
            order_desc=True,
        )

        # Generate RSS XML
        items = []
        for alert in alerts:
            metadata = alert.get("metadata_json", {})
            if isinstance(metadata, str):
                import json

                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            # Properly escape all user-controlled data for XML/RSS
            from xml.sax.saxutils import escape

            suspicious_pkg = escape(alert["suspicious_package"])
            target_pkg = escape(alert["target_package"])
            risk_level = escape(alert["risk_level"])
            author = escape(metadata.get("author", "unknown"))

            title = f"🚨 MCP Typosquat Alert: {suspicious_pkg}"
            description = (
                f"Risk Level: {risk_level}<br/>"
                f"Suspicious MCP: {suspicious_pkg}<br/>"
                f"Target: {target_pkg}<br/>"
                f"Similarity: {metadata.get('similarity_score', 0):.2f}<br/>"
                f"Author: {author}<br/><br/>"
                f"This MCP server appears to be typosquatting a popular name. "
                f"Exercise caution before installation."
            )
            link = (
                f"https://github.com/{escape(alert['suspicious_package'], quote=True)}"
            )

            items.append(f"""
    <item>
      <title>{escape(title)}</title>
      <description><![CDATA[{description}]]></description>
      <link>{escape(link)}</link>
      <guid>{escape(alert["id"])}</guid>
      <pubDate>{escape(str(alert["created_at"]))}</pubDate>
      <category>MCP Typosquat</category>
    </item>""")

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sigil MCP Watchdog — Typosquat Alerts</title>
    <link>https://sigilsec.ai/mcp-watchdog</link>
    <description>Real-time typosquat detection for MCP servers</description>
    <language>en-us</language>
    <lastBuildDate>{alerts[0]["created_at"] if alerts else ""}</lastBuildDate>
    {"".join(items)}
  </channel>
</rss>"""

        return Response(content=xml, media_type="application/rss+xml")

    except Exception:
        logger.exception("Failed to generate MCP watchdog RSS feed")
        return Response(content=_FALLBACK_RSS, media_type="application/rss+xml")


# ---------------------------------------------------------------------------
# JSON feed endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/feed",
    summary="JSON threat feed",
    response_model=list[dict[str, Any]],
)
async def json_feed(
    ecosystem: str | None = Query(
        None, description="Filter by ecosystem", min_length=1, max_length=20
    ),
    verdict: str | None = Query(None, description="Filter by verdict", max_length=200),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    since: str | None = Query(
        None,
        description="ISO datetime — return scans after this",
        max_length=50,
        pattern=r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?",  # Basic ISO datetime validation
    ),
) -> list[dict[str, Any]]:
    """Return recent scans as a JSON array. Filterable by ecosystem and verdict."""
    try:
        # Validate and sanitize inputs
        if ecosystem:
            ecosystem = InputSanitizer.sanitize_ecosystem(ecosystem)
        if verdict:
            verdict = InputSanitizer.sanitize_verdict(verdict)

        from api.database import db

        filters: dict[str, Any] = {}
        if ecosystem:
            filters["ecosystem"] = ecosystem
        if verdict:
            filters["verdict"] = verdict

        # Build select kwargs with optional ordering.
        select_kwargs: dict[str, Any] = {
            "table": "public_scans",
            "filters": filters if filters else None,
            "limit": limit,
        }
        try:
            rows = await db.select(
                **select_kwargs, order_by="created_at", order_desc=True
            )
        except TypeError:
            rows = await db.select(**select_kwargs)
            rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)

        results = []
        for row in rows:
            item: dict[str, Any] = {
                "scan_id": row.get("id"),
                "ecosystem": row.get("ecosystem"),
                "name": row.get("package_name"),
                "version": row.get("package_version"),
                "risk_score": row.get("risk_score"),
                "verdict": row.get("verdict"),
                "findings_count": row.get("findings_count", 0),
                "url": f"https://sigilsec.ai/scans/{row.get('ecosystem')}/{row.get('package_name')}",
                "scanned_at": str(row.get("scanned_at", row.get("created_at", ""))),
            }

            # Include attestation envelope if present
            raw_attestation = row.get("attestation")
            if raw_attestation:
                import json as _json

                att = raw_attestation
                if isinstance(att, str):
                    try:
                        att = _json.loads(att)
                    except (ValueError, _json.JSONDecodeError):
                        att = None
                if att:
                    item["attestation"] = att
                    item["verified"] = True
                    item["content_digest"] = row.get("content_digest")
            else:
                item["verified"] = False

            results.append(item)

        return results

    except Exception:
        logger.exception("Feed query failed")
        return []


@router.get("/api/v1/feed/alerts", summary="Recent high-risk alerts")
async def alerts_feed(
    limit: int = Query(20, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Return recent HIGH_RISK and CRITICAL_RISK scan alerts."""
    try:
        from api.database import cache

        raw_alerts = await cache.get("sigil:alerts")
        if raw_alerts:
            import json as _json

            alerts = _json.loads(f"[{raw_alerts}]") if raw_alerts else []
            return alerts[:limit]
    except Exception:
        pass

    # Fallback: query database
    try:
        from api.database import db

        rows = await db.select(
            "public_scans",
            filters=None,
            limit=limit,
            order_by="created_at",
            order_desc=True,
        )
        return [
            {
                "scan_id": r.get("id"),
                "ecosystem": r.get("ecosystem"),
                "name": r.get("package_name"),
                "verdict": r.get("verdict"),
                "score": r.get("risk_score"),
                "scanned_at": str(r.get("scanned_at", "")),
            }
            for r in rows
            if r.get("verdict") in ("HIGH_RISK", "CRITICAL_RISK")
        ]
    except Exception:
        return []


@router.get("/api/v1/feed/stats", summary="Bot pipeline statistics")
async def pipeline_stats() -> dict[str, Any]:
    """Return bot queue depth, scan rates, and health metrics."""
    stats: dict[str, Any] = {"status": "unknown"}

    try:
        from bot.queue import JobQueue

        queue = JobQueue()
        await queue.connect()
        depth = await queue.queue_depth()
        await queue.disconnect()
        stats["queue"] = depth
        stats["status"] = "running"
    except Exception:
        stats["queue"] = {"note": "Queue not available"}

    try:
        from api.database import db

        # Count recent scans
        rows = await db.select("public_scans", limit=1)
        stats["database"] = "connected" if rows is not None else "disconnected"
    except Exception:
        stats["database"] = "disconnected"

    return stats


@router.get(
    "/api/v1/feed/mcp-watchdog", summary="MCP Watchdog typosquat alerts JSON feed"
)
async def mcp_watchdog_feed(
    risk_level: str | None = Query(
        None,
        description="Filter by risk level (LOW, MEDIUM, HIGH)",
        pattern="^(LOW|MEDIUM|HIGH)$",
    ),
    limit: int = Query(20, ge=1, le=100, description="Max results"),
    resolved: bool | None = Query(False, description="Include resolved alerts"),
) -> list[dict[str, Any]]:
    """Return recent MCP typosquat alerts as JSON."""
    try:
        from api.database import db

        filters: dict[str, Any] = {"ecosystem": "mcp"}
        if risk_level:
            filters["risk_level"] = risk_level.upper()
        if resolved is not None:
            filters["resolved"] = resolved

        alerts = await db.select(
            "typosquat_alerts",
            filters=filters,
            limit=limit,
            order_by="created_at",
            order_desc=True,
        )

        results = []
        for alert in alerts:
            metadata = alert.get("metadata_json", {})
            if isinstance(metadata, str):
                import json

                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            item = {
                "alert_id": alert["id"],
                "suspicious_package": alert["suspicious_package"],
                "target_package": alert["target_package"],
                "risk_level": alert["risk_level"],
                "similarity_score": metadata.get("similarity_score", 0),
                "edit_distance": metadata.get("edit_distance", 0),
                "author": metadata.get("author", "unknown"),
                "repo_url": f"https://github.com/{alert['suspicious_package']}",
                "created_at": alert["created_at"],
                "resolved": alert.get("resolved", False),
            }
            results.append(item)

        return results

    except Exception:
        logger.exception("MCP watchdog feed query failed")
        return []


@router.get("/api/v1/feed/mcp-servers", summary="Discovered MCP servers JSON feed")
async def mcp_servers_feed(
    author: str | None = Query(None, description="Filter by author"),
    language: str | None = Query(None, description="Filter by programming language"),
    min_stars: int | None = Query(None, description="Minimum star count"),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
) -> list[dict[str, Any]]:
    """Return recently discovered MCP servers as JSON."""
    try:
        from api.database import db

        filters: dict[str, Any] = {}
        if author:
            filters["author"] = author
        if language:
            filters["language"] = language
        if min_stars is not None:
            # Note: This would need a proper SQL query with WHERE clause
            pass

        servers = await db.select(
            "mcp_servers",
            filters=filters if filters else None,
            limit=limit,
            order_by="last_updated",
            order_desc=True,
        )

        results = []
        for server in servers:
            topics = server.get("topics", "[]")
            if isinstance(topics, str):
                import json

                try:
                    topics = json.loads(topics)
                except (json.JSONDecodeError, TypeError):
                    topics = []

            mcp_config = server.get("mcp_config", "{}")
            if isinstance(mcp_config, str):
                import json

                try:
                    mcp_config = json.loads(mcp_config)
                except (json.JSONDecodeError, TypeError):
                    mcp_config = {}

            item = {
                "repo_name": server["repo_name"],
                "author": server["author"],
                "description": server.get("description", ""),
                "stars": server.get("stars", 0),
                "forks": server.get("forks", 0),
                "language": server.get("language", ""),
                "topics": topics,
                "homepage": server.get("homepage", ""),
                "clone_url": server.get("clone_url", ""),
                "mcp_config": mcp_config,
                "first_seen": server["first_seen"],
                "last_updated": server["last_updated"],
                "scan_status": server.get("scan_status", "pending"),
                "github_url": f"https://github.com/{server['repo_name']}",
            }

            # Add scan result if available
            scan_result = await db.select_one(
                "public_scans",
                {"ecosystem": "mcp", "package_name": server["repo_name"]},
            )
            if scan_result:
                item["scan_result"] = {
                    "risk_score": scan_result.get("risk_score", 0),
                    "verdict": scan_result.get("verdict", "UNKNOWN"),
                    "findings_count": scan_result.get("findings_count", 0),
                    "scanned_at": scan_result.get("scanned_at", ""),
                }

            results.append(item)

        return results

    except Exception:
        logger.exception("MCP servers feed query failed")
        return []


@router.get(
    "/feed/skillguard.xml", summary="RSS feed — SkillGuard prompt injection alerts"
)
async def rss_skillguard() -> Response:
    """Return RSS feed for AI skills with prompt injection patterns (SkillGuard Feed)."""
    try:
        from api.database import db

        # Get ClawHub skills with Phase 7 (prompt injection) findings
        scans = await db.select(
            "public_scans",
            filters={"ecosystem": "clawhub"},
            limit=100,
            order_by="created_at",
            order_desc=True,
        )

        # Filter for skills with prompt injection findings
        skill_alerts = []
        for scan in scans:
            findings = scan.get("findings_json", [])
            if isinstance(findings, str):
                import json

                try:
                    findings = json.loads(findings)
                except (json.JSONDecodeError, TypeError):
                    findings = []

            # Check if any findings are from Phase 7 (prompt injection)
            prompt_injection_findings = [
                f for f in findings if f.get("phase") == "PROMPT_INJECTION"
            ]

            if prompt_injection_findings:
                metadata = scan.get("metadata_json", {})
                if isinstance(metadata, str):
                    import json

                    try:
                        metadata = json.loads(metadata)
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}

                # Categorize risk level
                high_risk_patterns = [
                    f
                    for f in prompt_injection_findings
                    if f.get("severity") in ("CRITICAL", "HIGH")
                ]

                risk_level = "HIGH" if high_risk_patterns else "MEDIUM"

                skill_alerts.append(
                    {
                        "scan_id": scan["id"],
                        "skill_name": scan["package_name"],
                        "skill_version": scan["package_version"],
                        "risk_level": risk_level,
                        "verdict": scan["verdict"],
                        "author": metadata.get("author", "unknown"),
                        "description": metadata.get("description", ""),
                        "prompt_findings": prompt_injection_findings,
                        "scanned_at": scan["scanned_at"],
                    }
                )

        # Generate RSS XML
        items = []
        from xml.sax.saxutils import escape

        for alert in skill_alerts[:50]:  # Limit to 50 most recent
            # Escape all user-controlled data
            skill_name = escape(alert["skill_name"])
            risk_level = escape(alert["risk_level"])

            title = f"🛡️ SkillGuard Alert: {skill_name} ({risk_level} RISK)"

            # Summarize findings with proper escaping
            findings_summary = []
            for finding in alert["prompt_findings"][:3]:  # Top 3 findings
                finding_desc = escape(
                    finding.get("description", finding.get("rule", "Unknown"))
                )
                findings_summary.append(f"• {finding_desc}")

            # Build description with escaped data
            author = escape(alert["author"])
            verdict = escape(alert["verdict"])
            skill_version = escape(alert["skill_version"])
            desc_preview = escape(alert["description"][:200])

            description = f"""
<strong>Risk Level:</strong> {risk_level}<br/>
<strong>AI Skill:</strong> {skill_name} v{skill_version}<br/>
<strong>Author:</strong> {author}<br/>
<strong>Verdict:</strong> {verdict}<br/><br/>
<strong>Prompt Injection Patterns Detected:</strong><br/>
{"<br/>".join(findings_summary)}<br/><br/>
<strong>Description:</strong> {desc_preview}...<br/><br/>
This AI agent skill contains patterns that could be exploited for prompt injection attacks. 
Review the skill code before installation and use.
"""

            link = (
                f"https://clawhub.ai/skills/{escape(alert['skill_name'], quote=True)}"
            )

            items.append(f"""
    <item>
      <title>{escape(title)}</title>
      <description><![CDATA[{description}]]></description>
      <link>{escape(link)}</link>
      <guid>{escape(alert["scan_id"])}</guid>
      <pubDate>{escape(str(alert["scanned_at"]))}</pubDate>
      <category>SkillGuard Alert</category>
    </item>""")

        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sigil SkillGuard — AI Skill Prompt Injection Alerts</title>
    <link>https://sigilsec.ai/skillguard</link>
    <description>Real-time prompt injection detection for AI agent skills</description>
    <language>en-us</language>
    <lastBuildDate>{skill_alerts[0]["scanned_at"] if skill_alerts else ""}</lastBuildDate>
    {"".join(items)}
  </channel>
</rss>"""

        return Response(content=xml, media_type="application/rss+xml")

    except Exception:
        logger.exception("Failed to generate SkillGuard RSS feed")
        return Response(content=_FALLBACK_RSS, media_type="application/rss+xml")


@router.get(
    "/api/v1/feed/skillguard", summary="SkillGuard prompt injection alerts JSON feed"
)
async def skillguard_feed(
    risk_level: str | None = Query(
        None,
        description="Filter by risk level (LOW, MEDIUM, HIGH)",
        pattern="^(LOW|MEDIUM|HIGH)$",
    ),
    severity: str | None = Query(
        None,
        description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)",
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    ),
    limit: int = Query(30, ge=1, le=100, description="Max results"),
    include_descriptions: bool = Query(
        True, description="Include detailed finding descriptions"
    ),
) -> list[dict[str, Any]]:
    """Return AI skills with prompt injection patterns as JSON (SkillGuard Feed)."""
    try:
        from api.database import db

        # Get ClawHub skills with scan results
        scans = await db.select(
            "public_scans",
            filters={"ecosystem": "clawhub"},
            limit=200,  # Search larger set to filter
            order_by="created_at",
            order_desc=True,
        )

        skill_alerts = []
        for scan in scans:
            findings = scan.get("findings_json", [])
            if isinstance(findings, str):
                import json

                try:
                    findings = json.loads(findings)
                except (json.JSONDecodeError, TypeError):
                    findings = []

            # Filter for prompt injection findings
            prompt_findings = [
                f for f in findings if f.get("phase") == "PROMPT_INJECTION"
            ]

            if not prompt_findings:
                continue

            # Apply severity filter if specified
            if severity:
                prompt_findings = [
                    f
                    for f in prompt_findings
                    if f.get("severity", "").upper() == severity.upper()
                ]
                if not prompt_findings:
                    continue

            metadata = scan.get("metadata_json", {})
            if isinstance(metadata, str):
                import json

                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            # Determine risk level
            critical_findings = [
                f for f in prompt_findings if f.get("severity") == "CRITICAL"
            ]
            high_findings = [f for f in prompt_findings if f.get("severity") == "HIGH"]

            if critical_findings:
                calculated_risk = "HIGH"
            elif high_findings:
                calculated_risk = "MEDIUM"
            else:
                calculated_risk = "LOW"

            # Apply risk level filter
            if risk_level and calculated_risk != risk_level.upper():
                continue

            alert = {
                "scan_id": scan["id"],
                "skill_name": scan["package_name"],
                "skill_version": scan["package_version"],
                "risk_level": calculated_risk,
                "verdict": scan["verdict"],
                "risk_score": scan.get("risk_score", 0),
                "author": metadata.get("author", "unknown"),
                "description": metadata.get("description", ""),
                "stars": metadata.get("stars", 0),
                "downloads": metadata.get("downloads", 0),
                "findings_count": len(prompt_findings),
                "clawhub_url": f"https://clawhub.ai/skills/{scan['package_name']}",
                "scan_url": f"https://sigilsec.ai/scans/clawhub/{scan['package_name']}",
                "scanned_at": scan["scanned_at"],
            }

            # Include detailed findings if requested
            if include_descriptions:
                alert["findings"] = [
                    {
                        "rule": f.get("rule", "unknown"),
                        "severity": f.get("severity", "UNKNOWN"),
                        "description": f.get("description", ""),
                        "file": f.get("file", ""),
                        "line": f.get("line", 0),
                        "snippet": f.get("snippet", "")[:200]
                        + ("..." if len(f.get("snippet", "")) > 200 else ""),
                    }
                    for f in prompt_findings[:5]  # Limit to top 5 findings per skill
                ]
            else:
                # Just include rule IDs for compact response
                alert["rule_ids"] = [f.get("rule", "unknown") for f in prompt_findings]

            skill_alerts.append(alert)

            if len(skill_alerts) >= limit:
                break

        return skill_alerts

    except Exception:
        logger.exception("SkillGuard feed query failed")
        return []
