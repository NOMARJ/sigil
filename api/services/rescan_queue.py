"""
Rescan Queue Service for Scanner v2 Migration

Manages progressive migration by identifying and rescanning high-priority
packages with enhanced Scanner v2 to reduce false positives.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from dataclasses import dataclass

from api.database import db

logger = logging.getLogger(__name__)


@dataclass
class RescanCandidate:
    """A package candidate for rescanning with v2."""
    
    ecosystem: str
    package_name: str
    package_version: str
    current_score: float
    current_verdict: str
    findings_count: int
    last_scanned: datetime
    priority_score: float
    reason: str  # Why this package was selected for rescanning


class RescanQueue:
    """
    Queue manager for progressive v1->v2 migration.
    
    Identifies high-priority packages for rescanning and manages
    the migration process to avoid overwhelming the system.
    """
    
    def __init__(self, max_per_hour: int = 10):
        self.max_per_hour = max_per_hour
        self.rescan_cooldown_hours = 24  # Don't rescan same package within 24h
        
    async def identify_rescan_candidates(self, limit: int = 100) -> List[RescanCandidate]:
        """
        Identify top packages that should be rescanned with v2.
        
        Priority criteria:
        1. HIGH_RISK or CRITICAL_RISK verdicts (likely false positives)
        2. High findings count with old scanner version
        3. Popular packages (high download counts)
        4. Recently scanned v1 packages
        """
        candidates = []
        
        try:
            # Query high-risk packages scanned with v1 that haven't been rescanned recently
            high_risk_query = """
                SELECT TOP (?) 
                    ecosystem, package_name, package_version, risk_score, verdict,
                    findings_count, scanned_at, metadata_json,
                    COALESCE(scanner_version, '1.0.0') as scanner_version
                FROM public_scans 
                WHERE verdict IN ('HIGH_RISK', 'CRITICAL_RISK')
                    AND COALESCE(scanner_version, '1.0.0') LIKE '1.%'
                    AND scanned_at > DATEADD(day, -30, GETUTCDATE())
                    AND (rescanned_at IS NULL OR rescanned_at < DATEADD(hour, -?, GETUTCDATE()))
                ORDER BY 
                    CASE verdict
                        WHEN 'CRITICAL_RISK' THEN 4
                        WHEN 'HIGH_RISK' THEN 3
                        WHEN 'MEDIUM_RISK' THEN 2
                        ELSE 1
                    END DESC,
                    findings_count DESC,
                    scanned_at DESC
            """
            
            high_risk_rows = await db.execute_raw_sql(
                high_risk_query, 
                (limit // 2, self.rescan_cooldown_hours)
            )
            
            for row in high_risk_rows:
                priority_score = self._calculate_priority_score(row)
                candidate = RescanCandidate(
                    ecosystem=row["ecosystem"],
                    package_name=row["package_name"],
                    package_version=row["package_version"],
                    current_score=row["risk_score"],
                    current_verdict=row["verdict"],
                    findings_count=row["findings_count"],
                    last_scanned=row["scanned_at"],
                    priority_score=priority_score,
                    reason=f"High-risk {row['verdict']} with {row['findings_count']} findings"
                )
                candidates.append(candidate)
            
            # Query popular packages with moderate findings that might benefit from v2
            popular_query = """
                SELECT TOP (?) 
                    ecosystem, package_name, package_version, risk_score, verdict,
                    findings_count, scanned_at, metadata_json,
                    COALESCE(scanner_version, '1.0.0') as scanner_version
                FROM public_scans 
                WHERE verdict IN ('MEDIUM_RISK')
                    AND findings_count >= 5
                    AND COALESCE(scanner_version, '1.0.0') LIKE '1.%'
                    AND scanned_at > DATEADD(day, -14, GETUTCDATE())
                    AND (rescanned_at IS NULL OR rescanned_at < DATEADD(hour, -?, GETUTCDATE()))
                    AND JSON_VALUE(metadata_json, '$.download_count') > 1000
                ORDER BY 
                    findings_count DESC,
                    CAST(JSON_VALUE(metadata_json, '$.download_count') AS INT) DESC,
                    scanned_at DESC
            """
            
            popular_rows = await db.execute_raw_sql(
                popular_query, 
                (limit // 2, self.rescan_cooldown_hours)
            )
            
            for row in popular_rows:
                priority_score = self._calculate_priority_score(row)
                candidate = RescanCandidate(
                    ecosystem=row["ecosystem"],
                    package_name=row["package_name"],
                    package_version=row["package_version"],
                    current_score=row["risk_score"],
                    current_verdict=row["verdict"],
                    findings_count=row["findings_count"],
                    last_scanned=row["scanned_at"],
                    priority_score=priority_score,
                    reason=f"Popular package with {row['findings_count']} findings"
                )
                candidates.append(candidate)
            
        except Exception as e:
            logger.exception("Failed to identify rescan candidates: %s", e)
            
        # Sort by priority score and return top candidates
        candidates.sort(key=lambda c: c.priority_score, reverse=True)
        return candidates[:limit]
    
    def _calculate_priority_score(self, row: Dict[str, Any]) -> float:
        """Calculate priority score for rescanning (higher = more urgent)."""
        score = 0.0
        
        # Base score from current verdict
        verdict_scores = {
            "CRITICAL_RISK": 100.0,
            "HIGH_RISK": 75.0,
            "MEDIUM_RISK": 50.0,
            "LOW_RISK": 25.0,
        }
        score += verdict_scores.get(row.get("verdict", "LOW_RISK"), 25.0)
        
        # Bonus for high findings count (likely false positives)
        findings_count = row.get("findings_count", 0)
        if findings_count >= 20:
            score += 25.0
        elif findings_count >= 10:
            score += 15.0
        elif findings_count >= 5:
            score += 10.0
            
        # Bonus for popular packages
        try:
            metadata = row.get("metadata_json", {})
            if isinstance(metadata, str):
                import json
                metadata = json.loads(metadata)
            
            download_count = metadata.get("download_count", 0)
            if download_count > 100000:
                score += 15.0
            elif download_count > 10000:
                score += 10.0
            elif download_count > 1000:
                score += 5.0
        except Exception:
            pass
            
        # Penalty for very old scans (less relevant)
        last_scanned = row.get("scanned_at")
        if isinstance(last_scanned, datetime):
            days_old = (datetime.now(timezone.utc) - last_scanned).days
            if days_old > 7:
                score -= min(days_old - 7, 20)  # Max penalty of 20 points
                
        return max(score, 0.0)
    
    async def get_queue_status(self) -> Dict[str, Any]:
        """Get current rescan queue status and progress."""
        try:
            # Count packages by scanner version
            version_query = """
                SELECT 
                    COALESCE(scanner_version, '1.0.0') as version,
                    COUNT(*) as count,
                    COUNT(CASE WHEN verdict IN ('HIGH_RISK', 'CRITICAL_RISK') THEN 1 END) as high_risk_count
                FROM public_scans
                GROUP BY COALESCE(scanner_version, '1.0.0')
                ORDER BY version
            """
            
            version_stats = await db.execute_raw_sql(version_query, ())
            
            # Count recent rescans
            recent_rescans_query = """
                SELECT COUNT(*) as recent_rescans
                FROM public_scans
                WHERE rescanned_at > DATEADD(hour, -24, GETUTCDATE())
            """
            
            recent_rescans = await db.execute_raw_sql(recent_rescans_query, ())
            recent_count = recent_rescans[0]["recent_rescans"] if recent_rescans else 0
            
            # Calculate migration progress
            total_v1 = sum(row["count"] for row in version_stats if row["version"].startswith("1."))
            total_v2 = sum(row["count"] for row in version_stats if row["version"].startswith("2."))
            total_packages = total_v1 + total_v2
            
            migration_percentage = (total_v2 / total_packages * 100) if total_packages > 0 else 0.0
            
            return {
                "migration_progress": {
                    "v1_packages": total_v1,
                    "v2_packages": total_v2,
                    "total_packages": total_packages,
                    "percentage_migrated": round(migration_percentage, 2),
                },
                "recent_activity": {
                    "rescans_last_24h": recent_count,
                    "hourly_rate": round(recent_count / 24, 2),
                    "max_hourly_rate": self.max_per_hour,
                },
                "version_breakdown": [
                    {
                        "version": row["version"],
                        "count": row["count"],
                        "high_risk_count": row["high_risk_count"],
                    }
                    for row in version_stats
                ],
            }
            
        except Exception as e:
            logger.exception("Failed to get queue status: %s", e)
            return {
                "error": str(e),
                "migration_progress": {"v1_packages": 0, "v2_packages": 0, "total_packages": 0, "percentage_migrated": 0.0},
                "recent_activity": {"rescans_last_24h": 0, "hourly_rate": 0.0, "max_hourly_rate": self.max_per_hour},
                "version_breakdown": [],
            }
    
    async def can_process_more_rescans(self) -> bool:
        """Check if we can process more rescans this hour."""
        try:
            recent_query = """
                SELECT COUNT(*) as recent_count
                FROM public_scans
                WHERE rescanned_at > DATEADD(hour, -1, GETUTCDATE())
            """
            
            recent_rescans = await db.execute_raw_sql(recent_query, ())
            recent_count = recent_rescans[0]["recent_count"] if recent_rescans else 0
            
            return recent_count < self.max_per_hour
            
        except Exception as e:
            logger.warning("Failed to check rescan rate limit: %s", e)
            return False


async def main():
    """CLI entry point for rescan queue operations."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Scanner v2 Migration Rescan Queue")
    parser.add_argument("--dry-run", action="store_true", help="Show candidates without processing")
    parser.add_argument("--status", action="store_true", help="Show migration status")
    parser.add_argument("--limit", type=int, default=20, help="Number of candidates to show")
    
    args = parser.parse_args()
    
    queue = RescanQueue()
    
    if args.status:
        status = await queue.get_queue_status()
        print("=== Scanner v2 Migration Status ===")
        print(f"Migration Progress: {status['migration_progress']['percentage_migrated']:.1f}%")
        print(f"  v1 packages: {status['migration_progress']['v1_packages']}")
        print(f"  v2 packages: {status['migration_progress']['v2_packages']}")
        print(f"  total packages: {status['migration_progress']['total_packages']}")
        print()
        print("Recent Activity:")
        print(f"  Rescans in last 24h: {status['recent_activity']['rescans_last_24h']}")
        print(f"  Current hourly rate: {status['recent_activity']['hourly_rate']:.1f}/hour")
        print(f"  Max hourly rate: {status['recent_activity']['max_hourly_rate']}/hour")
        print()
        print("Version Breakdown:")
        for version_info in status['version_breakdown']:
            print(f"  {version_info['version']}: {version_info['count']} packages "
                  f"({version_info['high_risk_count']} high-risk)")
        return
    
    candidates = await queue.identify_rescan_candidates(limit=args.limit)
    
    print(f"=== Top {len(candidates)} Rescan Candidates ===")
    for i, candidate in enumerate(candidates, 1):
        print(f"{i:2d}. {candidate.ecosystem}/{candidate.package_name}@{candidate.package_version}")
        print(f"     Current: {candidate.current_verdict} (score: {candidate.current_score:.1f}, "
              f"findings: {candidate.findings_count})")
        print(f"     Priority: {candidate.priority_score:.1f} - {candidate.reason}")
        print(f"     Last scanned: {candidate.last_scanned.strftime('%Y-%m-%d %H:%M UTC')}")
        print()
    
    if args.dry_run:
        print("DRY RUN: No packages were actually rescanned.")
    else:
        print("To implement actual rescanning, use the rescan API endpoints or worker.")


if __name__ == "__main__":
    asyncio.run(main())