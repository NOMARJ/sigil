"""
Sigil API — Badge Router

Generates SVG badges for scan results. Badges are embeddable in READMEs
and serve as both trust signals and backlinks for SEO/AEO.

GET /badge/{scan_id}                    — Badge for a specific scan
GET /badge/{ecosystem}/{package_name}   — Badge for the latest scan of a package
GET /badge/shield/{verdict}             — Generic verdict badge (shields.io style)
"""

from __future__ import annotations

import logging
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter
from fastapi.responses import Response

from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/badge", tags=["badge"])

# Badge colors by risk classification
VERDICT_COLORS = {
    "LOW_RISK": "#22C55E",         # Green
    "MEDIUM_RISK": "#EAB308",      # Yellow
    "HIGH_RISK": "#F97316",        # Orange
    "CRITICAL_RISK": "#EF4444",    # Red
    "NOT_SCANNED": "#6B7280",      # Gray
}

VERDICT_LABELS = {
    "LOW_RISK": "LOW RISK",
    "MEDIUM_RISK": "MEDIUM RISK",
    "HIGH_RISK": "HIGH RISK",
    "CRITICAL_RISK": "CRITICAL RISK",
    "NOT_SCANNED": "NOT SCANNED",
}


def _generate_badge_svg(
    label: str,
    message: str,
    color: str,
    score: float | None = None,
) -> str:
    """Generate a shields.io-compatible SVG badge.

    Uses the flat style for maximum compatibility with GitHub READMEs.
    """
    # Approximate text widths (character width ~6.5px for 11px Verdana)
    label_width = len(label) * 6.5 + 10
    message_width = len(message) * 6.5 + 10
    total_width = label_width + message_width

    score_text = f" ({score:.0f})" if score is not None else ""
    full_message = message + score_text
    message_width = len(full_message) * 6.5 + 10
    total_width = label_width + message_width

    label_x = label_width / 2
    message_x = label_width + message_width / 2

    # Escape XML entities to prevent XSS in SVG output
    safe_label = xml_escape(label)
    safe_message = xml_escape(full_message)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width:.0f}" height="20" role="img" aria-label="Sigil automated scan result: {safe_message} — not a security certification">
  <title>Automated scan by Sigil. This is not a security certification. Click for full report.</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width:.0f}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width:.0f}" height="20" fill="#555"/>
    <rect x="{label_width:.0f}" width="{message_width:.0f}" height="20" fill="{color}"/>
    <rect width="{total_width:.0f}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_x * 10:.0f}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{safe_label}</text>
    <text x="{label_x * 10:.0f}" y="140" transform="scale(.1)" fill="#fff">{safe_label}</text>
    <text aria-hidden="true" x="{message_x * 10:.0f}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{safe_message}</text>
    <text x="{message_x * 10:.0f}" y="140" transform="scale(.1)" fill="#fff">{safe_message}</text>
  </g>
</svg>"""


def _svg_response(svg: str) -> Response:
    """Return an SVG response with appropriate caching headers."""
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=3600, s-maxage=3600",
            "X-Powered-By": "Sigil Security",
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/shield/{verdict}",
    summary="Generic verdict badge",
    response_class=Response,
)
async def shield_badge(verdict: str) -> Response:
    """Generate a static badge for a given verdict. Useful for documentation."""
    verdict_upper = verdict.upper().replace("-", "_")
    color = VERDICT_COLORS.get(verdict_upper, "#9f9f9f")
    label_text = VERDICT_LABELS.get(verdict_upper, verdict.lower())
    svg = _generate_badge_svg("sigil", label_text, color)
    return _svg_response(svg)


@router.get(
    "/scan/{scan_id}",
    summary="Badge for a specific scan",
    response_class=Response,
)
async def scan_badge(scan_id: str) -> Response:
    """Generate a badge for a specific scan ID. Links to the public report."""
    # Try public_scans first, fall back to scans
    row = await db.select_one("public_scans", {"id": scan_id})
    if not row:
        row = await db.select_one("scans", {"id": scan_id})
    if not row:
        svg = _generate_badge_svg("sigil", "not found", "#9f9f9f")
        return _svg_response(svg)

    verdict = row.get("verdict", "LOW_RISK")
    score = row.get("risk_score", 0.0)
    color = VERDICT_COLORS.get(verdict, "#9f9f9f")
    label_text = VERDICT_LABELS.get(verdict, "unknown")
    svg = _generate_badge_svg("sigil", label_text, color, score=score)
    return _svg_response(svg)


@router.get(
    "/{ecosystem}/{package_name}",
    summary="Badge for the latest scan of a package",
    response_class=Response,
)
async def package_badge(ecosystem: str, package_name: str) -> Response:
    """Generate a badge for the latest scan of a package in a given ecosystem.

    Embed in your README:
        ![Scanned by Sigil](https://sigilsec.ai/badge/{ecosystem}/{package_name}.svg)

    Example:
        [![Scanned by Sigil](https://sigilsec.ai/badge/clawhub/my-skill.svg)](https://sigilsec.ai/scans/clawhub/my-skill)
    """
    rows = await db.select(
        "public_scans",
        {"ecosystem": ecosystem, "package_name": package_name},
        limit=100,
    )
    if not rows:
        svg = _generate_badge_svg("sigil", "not scanned", "#9f9f9f")
        return _svg_response(svg)

    rows.sort(
        key=lambda r: r.get("scanned_at", r.get("created_at", "")), reverse=True
    )
    row = rows[0]
    verdict = row.get("verdict", "LOW_RISK")
    score = row.get("risk_score", 0.0)
    color = VERDICT_COLORS.get(verdict, "#9f9f9f")
    label_text = VERDICT_LABELS.get(verdict, "unknown")
    svg = _generate_badge_svg("sigil", label_text, color, score=score)
    return _svg_response(svg)
