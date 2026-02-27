"""
Sigil API — Public Scan Registry Router

Public, unauthenticated endpoints for the Sigil scan database.
Every scanned package gets a permanent, crawlable page that AI models
and search engines can index.

GET  /registry/search           — Search the public scan database
GET  /registry/{ecosystem}      — List scanned packages in an ecosystem
GET  /registry/{ecosystem}/{name}          — Latest scan for a package
GET  /registry/{ecosystem}/{name}/{version} — Scan for a specific version
GET  /registry/scan/{scan_id}   — Public scan detail by ID
POST /registry/submit           — Submit a public scan (API key required)
GET  /registry/stats            — Public registry statistics
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Header, Query, status
from pydantic import BaseModel, Field

from api.config import settings
from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/registry", tags=["registry"])

TABLE = "public_scans"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PublicScanSummary(BaseModel):
    """Summary of a public scan for list/search views."""

    id: str
    ecosystem: str = "unknown"
    package_name: str = ""
    package_version: str = ""
    risk_score: float = 0.0
    verdict: str = "CLEAN"
    findings_count: int = 0
    files_scanned: int = 0
    badge_url: str = ""
    report_url: str = ""
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PublicScanDetail(BaseModel):
    """Full public scan record."""

    id: str
    ecosystem: str = "unknown"
    package_name: str = ""
    package_version: str = ""
    risk_score: float = 0.0
    verdict: str = "CLEAN"
    findings_count: int = 0
    files_scanned: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    badge_url: str = ""
    report_url: str = ""
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RegistrySearchResponse(BaseModel):
    """Paginated search results."""

    items: list[PublicScanSummary] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    query: str = ""


class RegistryStats(BaseModel):
    """Public registry statistics."""

    total_packages: int = 0
    total_scans: int = 0
    threats_found: int = 0
    ecosystems: dict[str, int] = Field(default_factory=dict)
    verdicts: dict[str, int] = Field(default_factory=dict)


class PublicScanSubmit(BaseModel):
    """Request to submit a scan to the public registry."""

    ecosystem: str = Field(..., description="Ecosystem: clawhub, npm, pip, cargo, mcp")
    package_name: str = Field(..., description="Package or skill name")
    package_version: str = Field("", description="Package version")
    risk_score: float = Field(0.0)
    verdict: str = Field("CLEAN")
    findings_count: int = Field(0)
    files_scanned: int = Field(0)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_summary(row: dict[str, Any]) -> PublicScanSummary:
    scan_id = row.get("id", "")
    ecosystem = row.get("ecosystem", "unknown")
    name = row.get("package_name", "")
    return PublicScanSummary(
        id=scan_id,
        ecosystem=ecosystem,
        package_name=name,
        package_version=row.get("package_version", ""),
        risk_score=row.get("risk_score", 0.0),
        verdict=row.get("verdict", "CLEAN"),
        findings_count=row.get("findings_count", 0),
        files_scanned=row.get("files_scanned", 0),
        badge_url=f"https://api.sigilsec.ai/badge/{ecosystem}/{name}",
        report_url=f"https://sigilsec.ai/registry/{ecosystem}/{name}",
        scanned_at=row.get("scanned_at", row.get("created_at", datetime.now(timezone.utc))),
    )


def _row_to_detail(row: dict[str, Any]) -> PublicScanDetail:
    scan_id = row.get("id", "")
    ecosystem = row.get("ecosystem", "unknown")
    name = row.get("package_name", "")
    findings = row.get("findings_json", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []
    metadata = row.get("metadata_json", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}
    return PublicScanDetail(
        id=scan_id,
        ecosystem=ecosystem,
        package_name=name,
        package_version=row.get("package_version", ""),
        risk_score=row.get("risk_score", 0.0),
        verdict=row.get("verdict", "CLEAN"),
        findings_count=row.get("findings_count", 0),
        files_scanned=row.get("files_scanned", 0),
        findings=findings,
        metadata=metadata,
        badge_url=f"https://api.sigilsec.ai/badge/{ecosystem}/{name}",
        report_url=f"https://sigilsec.ai/registry/{ecosystem}/{name}",
        scanned_at=row.get("scanned_at", row.get("created_at", datetime.now(timezone.utc))),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/search",
    response_model=RegistrySearchResponse,
    summary="Search the public scan database",
)
async def search_registry(
    q: str = Query("", description="Search query (package name)"),
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    verdict: str | None = Query(None, description="Filter by verdict"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> RegistrySearchResponse:
    """Search the public scan database. Results are ordered by scan date."""
    filters: dict[str, Any] = {}
    if ecosystem:
        filters["ecosystem"] = ecosystem
    if verdict:
        filters["verdict"] = verdict

    rows = await db.select(TABLE, filters if filters else None, limit=1000)

    if q:
        q_lower = q.lower()
        rows = [r for r in rows if q_lower in r.get("package_name", "").lower()]

    rows.sort(key=lambda r: r.get("scanned_at", r.get("created_at", "")), reverse=True)
    total = len(rows)
    start = (page - 1) * per_page
    page_rows = rows[start : start + per_page]

    return RegistrySearchResponse(
        items=[_row_to_summary(r) for r in page_rows],
        total=total,
        page=page,
        per_page=per_page,
        query=q,
    )


@router.get(
    "/stats",
    response_model=RegistryStats,
    summary="Public registry statistics",
)
async def registry_stats() -> RegistryStats:
    """Aggregate statistics for the public scan registry."""
    rows = await db.select(TABLE, None, limit=100_000)
    ecosystems: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    threats = 0
    for r in rows:
        eco = r.get("ecosystem", "unknown")
        ecosystems[eco] = ecosystems.get(eco, 0) + 1
        v = r.get("verdict", "CLEAN")
        verdicts[v] = verdicts.get(v, 0) + 1
        if v in ("HIGH_RISK", "CRITICAL"):
            threats += 1

    # Count unique packages
    seen = set()
    for r in rows:
        seen.add(f"{r.get('ecosystem', '')}:{r.get('package_name', '')}")

    return RegistryStats(
        total_packages=len(seen),
        total_scans=len(rows),
        threats_found=threats,
        ecosystems=ecosystems,
        verdicts=verdicts,
    )


@router.get(
    "/scan/{scan_id}",
    response_model=PublicScanDetail,
    summary="Get a public scan by ID",
)
async def get_public_scan(scan_id: str) -> PublicScanDetail:
    """Return full details of a public scan by its ID."""
    row = await db.select_one(TABLE, {"id": scan_id})
    if not row:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return _row_to_detail(row)


@router.get(
    "/{ecosystem}",
    response_model=RegistrySearchResponse,
    summary="List packages in an ecosystem",
)
async def list_ecosystem(
    ecosystem: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort: str = Query("recent", description="Sort: recent, risk, name"),
) -> RegistrySearchResponse:
    """List all scanned packages in a given ecosystem (clawhub, npm, pip, etc.)."""
    rows = await db.select(TABLE, {"ecosystem": ecosystem}, limit=10_000)

    if sort == "risk":
        rows.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
    elif sort == "name":
        rows.sort(key=lambda r: r.get("package_name", ""))
    else:
        rows.sort(key=lambda r: r.get("scanned_at", r.get("created_at", "")), reverse=True)

    # Deduplicate: keep latest scan per package
    seen: dict[str, dict[str, Any]] = {}
    for r in rows:
        key = f"{r.get('package_name', '')}@{r.get('package_version', '')}"
        if key not in seen:
            seen[key] = r

    deduped = list(seen.values())
    total = len(deduped)
    start = (page - 1) * per_page
    page_rows = deduped[start : start + per_page]

    return RegistrySearchResponse(
        items=[_row_to_summary(r) for r in page_rows],
        total=total,
        page=page,
        per_page=per_page,
        query=ecosystem,
    )


@router.get(
    "/{ecosystem}/{package_name}",
    response_model=PublicScanDetail,
    summary="Latest scan for a package",
)
async def get_package_scan(ecosystem: str, package_name: str) -> PublicScanDetail:
    """Return the most recent scan for a package in the given ecosystem."""
    rows = await db.select(
        TABLE, {"ecosystem": ecosystem, "package_name": package_name}, limit=100
    )
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"No scans found for {ecosystem}/{package_name}",
        )
    rows.sort(key=lambda r: r.get("scanned_at", r.get("created_at", "")), reverse=True)
    return _row_to_detail(rows[0])


@router.get(
    "/{ecosystem}/{package_name}/{version}",
    response_model=PublicScanDetail,
    summary="Scan for a specific package version",
)
async def get_package_version_scan(
    ecosystem: str, package_name: str, version: str
) -> PublicScanDetail:
    """Return the scan for a specific package version."""
    rows = await db.select(
        TABLE,
        {
            "ecosystem": ecosystem,
            "package_name": package_name,
            "package_version": version,
        },
        limit=1,
    )
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"No scan found for {ecosystem}/{package_name}@{version}",
        )
    return _row_to_detail(rows[0])


@router.post(
    "/submit",
    response_model=PublicScanSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a scan to the public registry",
)
async def submit_public_scan(
    request: PublicScanSubmit,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> PublicScanSummary:
    """Submit a scan result to the public registry.

    Requires a valid API key via the X-API-Key header.
    Called by the crawler pipeline and by the MCP server when
    users opt to share their scan results publicly.
    """
    # Reject unauthenticated submissions — the JWT secret doubles as the
    # internal API key for crawler-to-API communication.
    expected_key = settings.jwt_secret
    if settings.jwt_secret_is_insecure or not x_api_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid X-API-Key header required",
        )
    scan_id = str(uuid4())
    now = datetime.now(timezone.utc)

    row_data: dict[str, Any] = {
        "id": scan_id,
        "ecosystem": request.ecosystem,
        "package_name": request.package_name,
        "package_version": request.package_version,
        "risk_score": request.risk_score,
        "verdict": request.verdict,
        "findings_count": request.findings_count,
        "files_scanned": request.files_scanned,
        "findings_json": request.findings,
        "metadata_json": request.metadata,
        "scanned_at": now.isoformat(),
        "created_at": now.isoformat(),
    }

    try:
        await db.insert(TABLE, row_data)
    except Exception:
        logger.exception("Failed to persist public scan %s", scan_id)

    logger.info(
        "Public scan %s: %s/%s@%s verdict=%s score=%.1f",
        scan_id,
        request.ecosystem,
        request.package_name,
        request.package_version,
        request.verdict,
        request.risk_score,
    )

    return _row_to_summary(row_data)
