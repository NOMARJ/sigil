"""
Sigil API — Public Threat Feed Endpoints

RSS 2.0 feed and JSON API for recent scan results.
No authentication required — these are public outputs of the bot pipeline.

Endpoints:
    GET /feed.xml               — RSS 2.0 feed (all scans)
    GET /api/v1/feed            — JSON feed with filtering
    GET /api/v1/feed/alerts     — Recent HIGH/CRITICAL alerts
    GET /api/v1/feed/stats      — Bot pipeline statistics
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import Response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["feed"])


@router.get("/feed.xml", summary="RSS 2.0 threat feed")
async def rss_feed(
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    verdict: str | None = Query(
        None, description="Comma-separated verdicts (e.g. high_risk,critical_risk)"
    ),
) -> Response:
    """Return RSS 2.0 XML feed of recent scan results."""
    try:
        from bot.publisher import generate_rss_feed

        xml = await generate_rss_feed(
            ecosystem=ecosystem, verdict_filter=verdict
        )
        return Response(content=xml, media_type="application/rss+xml")
    except Exception:
        # Fallback: return a minimal valid RSS feed
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sigil Security Scanner — Threat Feed</title>
    <link>https://sigilsec.ai/scans</link>
    <description>Automated security scan results for AI agent packages</description>
  </channel>
</rss>"""
        return Response(content=xml, media_type="application/rss+xml")


@router.get(
    "/api/v1/feed",
    summary="JSON threat feed",
    response_model=list[dict[str, Any]],
)
async def json_feed(
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    verdict: str | None = Query(None, description="Filter by verdict"),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    since: str | None = Query(None, description="ISO datetime — return scans after this"),
) -> list[dict[str, Any]]:
    """Return recent scans as a JSON array. Filterable by ecosystem and verdict."""
    try:
        from api.database import db

        filters: dict[str, Any] = {}
        if ecosystem:
            filters["ecosystem"] = ecosystem
        if verdict:
            filters["verdict"] = verdict.upper()

        rows = await db.select(
            "public_scans",
            filters=filters if filters else None,
            limit=limit,
            order_by="created_at",
            order_desc=True,
        )

        results = []
        for row in rows:
            results.append({
                "scan_id": row.get("id"),
                "ecosystem": row.get("ecosystem"),
                "name": row.get("package_name"),
                "version": row.get("package_version"),
                "risk_score": row.get("risk_score"),
                "verdict": row.get("verdict"),
                "findings_count": row.get("findings_count", 0),
                "url": f"https://sigilsec.ai/scans/{row.get('ecosystem')}/{row.get('package_name')}",
                "scanned_at": str(row.get("scanned_at", row.get("created_at", ""))),
            })

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
