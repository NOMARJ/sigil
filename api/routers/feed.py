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

from fastapi import APIRouter, Query
from fastapi.responses import Response

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

        xml = await generate_rss_feed(
            ecosystem=ecosystem, verdict_filter=verdict
        )
        return Response(content=xml, media_type="application/rss+xml")
    except Exception:
        return Response(content=_FALLBACK_RSS, media_type="application/rss+xml")


# ---------------------------------------------------------------------------
# RSS 2.0 feed endpoints
# ---------------------------------------------------------------------------


@router.get("/feed.xml", summary="RSS 2.0 threat feed")
async def rss_feed(
    ecosystem: str | None = Query(None, description="Filter by ecosystem (clawhub, pypi, npm, github)"),
    verdict: str | None = Query(
        None, description="Comma-separated verdicts (e.g. high_risk,critical_risk)"
    ),
) -> Response:
    """Return RSS 2.0 XML feed of recent scan results.

    Supports query parameter filtering:
    - `/feed.xml` — all scans, all ecosystems
    - `/feed.xml?verdict=high_risk,critical_risk` — threats only
    - `/feed.xml?ecosystem=clawhub` — ClawHub only
    - `/feed.xml?ecosystem=pypi&verdict=critical_risk` — combined filters
    """
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


# ---------------------------------------------------------------------------
# JSON feed endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/feed",
    summary="JSON threat feed",
    response_model=list[dict[str, Any]],
)
async def json_feed(
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    verdict: str | None = Query(None, description="Filter by verdict"),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    since: str | None = Query(
        None, description="ISO datetime — return scans after this"
    ),
) -> list[dict[str, Any]]:
    """Return recent scans as a JSON array. Filterable by ecosystem and verdict."""
    try:
        from api.database import db

        filters: dict[str, Any] = {}
        if ecosystem:
            filters["ecosystem"] = ecosystem
        if verdict:
            filters["verdict"] = verdict.upper()

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
