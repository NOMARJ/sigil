"""
Scanner v2 migration monitoring endpoints for admin dashboard
"""

from fastapi import APIRouter, Depends
from typing import List, Optional
from datetime import datetime, timedelta
import asyncpg
from pydantic import BaseModel
from ...database import get_db_connection
from ...auth import require_admin

router = APIRouter(prefix="/admin/migration", tags=["admin"])


class MigrationStats(BaseModel):
    total_scans: int
    v1_scans: int
    v2_scans: int
    migration_percentage: float
    avg_score_reduction: float
    estimated_completion_date: Optional[str]


class FalsePositiveComparison(BaseModel):
    scanner_version: str
    total_findings: int
    false_positives: int
    false_positive_rate: float
    avg_confidence: Optional[float]


class PendingRescan(BaseModel):
    package_name: str
    package_version: str
    current_score: int
    scan_date: str
    priority: str


class DailyProgress(BaseModel):
    date: str
    v2_scans: int
    cumulative_percentage: float


@router.get("/status", response_model=MigrationStats)
async def get_migration_status(
    conn: asyncpg.Connection = Depends(get_db_connection),
    _: dict = Depends(require_admin),
):
    """Get overall migration status and progress"""

    # Get scan counts by version
    stats = await conn.fetchrow("""
        SELECT 
            COUNT(*) as total_scans,
            COUNT(*) FILTER (WHERE scanner_version = '1.0.0' OR scanner_version IS NULL) as v1_scans,
            COUNT(*) FILTER (WHERE scanner_version = '2.0.0') as v2_scans,
            AVG(CASE 
                WHEN original_score IS NOT NULL AND risk_score < original_score 
                THEN ((original_score - risk_score)::FLOAT / original_score) * 100 
                ELSE 0 
            END) as avg_score_reduction
        FROM scans
        WHERE created_at >= NOW() - INTERVAL '90 days'
    """)

    total = stats["total_scans"]
    v2_count = stats["v2_scans"]
    migration_pct = (v2_count / total * 100) if total > 0 else 0

    # Estimate completion based on migration rate
    completion_date = None
    if v2_count > 0:
        daily_rate = await conn.fetchval("""
            SELECT COUNT(*)::FLOAT / GREATEST(1, DATE_PART('day', NOW() - MIN(rescanned_at)))
            FROM scans
            WHERE scanner_version = '2.0.0' AND rescanned_at IS NOT NULL
        """)

        if daily_rate and daily_rate > 0:
            remaining = stats["v1_scans"]
            days_remaining = int(remaining / daily_rate)
            completion_date = (
                datetime.now() + timedelta(days=days_remaining)
            ).strftime("%Y-%m-%d")

    return MigrationStats(
        total_scans=total,
        v1_scans=stats["v1_scans"],
        v2_scans=v2_count,
        migration_percentage=round(migration_pct, 2),
        avg_score_reduction=round(stats["avg_score_reduction"] or 0, 2),
        estimated_completion_date=completion_date,
    )


@router.get("/false-positives", response_model=List[FalsePositiveComparison])
async def compare_false_positive_rates(
    conn: asyncpg.Connection = Depends(get_db_connection),
    _: dict = Depends(require_admin),
):
    """Compare false positive rates between v1 and v2"""

    results = []

    for version in ["1.0.0", "2.0.0"]:
        stats = await conn.fetchrow(
            """
            SELECT 
                COUNT(DISTINCT f.id) as total_findings,
                COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'info' OR f.confidence = 'LOW') as false_positives,
                AVG(CASE 
                    WHEN f.confidence = 'HIGH' THEN 0.9
                    WHEN f.confidence = 'MEDIUM' THEN 0.6
                    WHEN f.confidence = 'LOW' THEN 0.3
                    ELSE 0.5
                END) as avg_confidence
            FROM scans s
            JOIN findings f ON s.id = f.scan_id
            WHERE (s.scanner_version = $1) OR ($1 = '1.0.0' AND s.scanner_version IS NULL)
            AND s.created_at >= NOW() - INTERVAL '30 days'
        """,
            version,
        )

        total = stats["total_findings"]
        fps = stats["false_positives"] or 0

        results.append(
            FalsePositiveComparison(
                scanner_version=version,
                total_findings=total,
                false_positives=fps,
                false_positive_rate=round((fps / total * 100) if total > 0 else 0, 2),
                avg_confidence=round(stats["avg_confidence"] or 0.5, 2),
            )
        )

    return results


@router.get("/pending-rescans", response_model=List[PendingRescan])
async def get_pending_rescans(
    limit: int = 20,
    conn: asyncpg.Connection = Depends(get_db_connection),
    _: dict = Depends(require_admin),
):
    """Get list of high-priority packages pending rescan"""

    rows = await conn.fetch(
        """
        SELECT 
            package_name,
            package_version,
            risk_score as current_score,
            created_at::date as scan_date,
            CASE 
                WHEN risk_score >= 70 THEN 'CRITICAL'
                WHEN risk_score >= 50 THEN 'HIGH'
                WHEN risk_score >= 30 THEN 'MEDIUM'
                ELSE 'LOW'
            END as priority
        FROM scans
        WHERE (scanner_version = '1.0.0' OR scanner_version IS NULL)
        AND risk_score >= 30
        ORDER BY risk_score DESC, created_at ASC
        LIMIT $1
    """,
        limit,
    )

    return [
        PendingRescan(
            package_name=row["package_name"],
            package_version=row["package_version"],
            current_score=row["current_score"],
            scan_date=row["scan_date"].strftime("%Y-%m-%d"),
            priority=row["priority"],
        )
        for row in rows
    ]


@router.get("/daily-progress", response_model=List[DailyProgress])
async def get_daily_migration_progress(
    days: int = 30,
    conn: asyncpg.Connection = Depends(get_db_connection),
    _: dict = Depends(require_admin),
):
    """Get daily migration progress for chart visualization"""

    rows = await conn.fetch(
        """
        WITH daily_counts AS (
            SELECT 
                DATE(rescanned_at) as migration_date,
                COUNT(*) as daily_v2_scans
            FROM scans
            WHERE scanner_version = '2.0.0' 
            AND rescanned_at IS NOT NULL
            AND rescanned_at >= NOW() - INTERVAL '%s days'
            GROUP BY DATE(rescanned_at)
        ),
        running_total AS (
            SELECT 
                migration_date,
                daily_v2_scans,
                SUM(daily_v2_scans) OVER (ORDER BY migration_date) as cumulative_v2
            FROM daily_counts
        ),
        total_scans AS (
            SELECT COUNT(*) as total FROM scans
        )
        SELECT 
            rt.migration_date::text as date,
            rt.daily_v2_scans as v2_scans,
            ROUND((rt.cumulative_v2::FLOAT / ts.total) * 100, 2) as cumulative_percentage
        FROM running_total rt, total_scans ts
        ORDER BY rt.migration_date
    """
        % days
    )

    return [
        DailyProgress(
            date=row["date"],
            v2_scans=row["v2_scans"],
            cumulative_percentage=row["cumulative_percentage"],
        )
        for row in rows
    ]


@router.post("/record-progress")
async def record_migration_progress(
    conn: asyncpg.Connection = Depends(get_db_connection),
    _: dict = Depends(require_admin),
):
    """Record daily migration progress snapshot"""

    await conn.execute("""
        INSERT INTO scanner_migration_progress (
            total_scans, v1_scans, v2_scans, avg_score_reduction, false_positive_rate
        )
        SELECT 
            COUNT(*) as total_scans,
            COUNT(*) FILTER (WHERE scanner_version = '1.0.0' OR scanner_version IS NULL) as v1_scans,
            COUNT(*) FILTER (WHERE scanner_version = '2.0.0') as v2_scans,
            AVG(CASE 
                WHEN original_score IS NOT NULL AND risk_score < original_score 
                THEN ((original_score - risk_score)::FLOAT / original_score) * 100 
                ELSE 0 
            END) as avg_score_reduction,
            (COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'info' OR f.confidence = 'LOW')::FLOAT / 
             NULLIF(COUNT(DISTINCT f.id), 0)) * 100 as false_positive_rate
        FROM scans s
        LEFT JOIN findings f ON s.id = f.scan_id
        WHERE s.created_at >= NOW() - INTERVAL '30 days'
    """)

    return {"message": "Migration progress recorded successfully"}
