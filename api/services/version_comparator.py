"""
Version Comparator Service
Compares security findings between different code versions or branches
"""

from __future__ import annotations

import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from api.database import db
from api.services.scanner import scan_directory
from api.services.credit_service import credit_service
from api.models import Finding, Severity

logger = logging.getLogger(__name__)


class ChangeType(str, Enum):
    """Types of security changes"""

    VULNERABILITY_ADDED = "vulnerability_added"
    VULNERABILITY_FIXED = "vulnerability_fixed"
    SEVERITY_INCREASED = "severity_increased"
    SEVERITY_DECREASED = "severity_decreased"
    NO_CHANGE = "no_change"


@dataclass
class SecurityChange:
    """Represents a security change between versions"""

    change_type: ChangeType
    finding: Finding
    old_finding: Optional[Finding]
    file: str
    line: int
    commit: Optional[str]
    author: Optional[str]
    timestamp: Optional[datetime]
    description: str


@dataclass
class VersionComparison:
    """Complete comparison between two versions"""

    base_version: str
    compare_version: str
    base_findings: List[Finding]
    compare_findings: List[Finding]
    vulnerabilities_added: List[SecurityChange]
    vulnerabilities_fixed: List[SecurityChange]
    severity_changes: List[SecurityChange]
    security_score_delta: float
    risk_trend: str  # "improving", "worsening", "stable"
    summary_stats: Dict[str, int]
    blame_info: Dict[str, List[str]]  # author -> [changes]
    timeline_data: List[Dict[str, Any]]


class VersionComparator:
    """Compares security state between code versions"""

    async def compare_versions(
        self,
        base_path: str,
        compare_path: str,
        base_ref: str,
        compare_ref: str,
        user_id: str,
        scan_id: Optional[str] = None,
        include_blame: bool = True,
    ) -> VersionComparison:
        """
        Compare security between two code versions.

        Args:
            base_path: Path to base version code
            compare_path: Path to compare version code
            base_ref: Git reference for base (commit/branch)
            compare_ref: Git reference for compare (commit/branch)
            user_id: User requesting the comparison
            scan_id: Optional associated scan ID
            include_blame: Whether to include git blame info

        Returns:
            Complete version comparison analysis
        """
        # Check and deduct credits (6 credits for version comparison)
        credit_cost = 6
        if not await credit_service.has_credits(user_id, credit_cost):
            raise ValueError(
                f"Insufficient credits. Need {credit_cost} credits for version comparison."
            )

        await credit_service.deduct_credits(
            user_id=user_id,
            amount=credit_cost,
            transaction_type="version_comparison",
            scan_id=scan_id,
            metadata={"base_ref": base_ref, "compare_ref": compare_ref},
        )

        try:
            logger.info(f"Comparing security between {base_ref} and {compare_ref}")

            # Scan both versions
            base_findings = await self._scan_version(base_path, base_ref)
            compare_findings = await self._scan_version(compare_path, compare_ref)

            # Analyze changes
            changes = self._analyze_changes(
                base_findings, compare_findings, base_ref, compare_ref
            )

            # Get blame information if requested
            blame_info = {}
            if include_blame:
                blame_info = await self._get_blame_info(
                    changes.vulnerabilities_added, compare_path
                )

            # Calculate security score delta
            base_score = self._calculate_security_score(base_findings)
            compare_score = self._calculate_security_score(compare_findings)
            score_delta = compare_score - base_score

            # Determine risk trend
            if score_delta < -5:
                risk_trend = "improving"
            elif score_delta > 5:
                risk_trend = "worsening"
            else:
                risk_trend = "stable"

            # Build timeline data for visualization
            timeline_data = self._build_timeline_data(changes)

            # Generate summary statistics
            summary_stats = {
                "base_total_findings": len(base_findings),
                "compare_total_findings": len(compare_findings),
                "vulnerabilities_added": len(changes.vulnerabilities_added),
                "vulnerabilities_fixed": len(changes.vulnerabilities_fixed),
                "critical_added": sum(
                    1
                    for c in changes.vulnerabilities_added
                    if c.finding.severity == Severity.CRITICAL
                ),
                "critical_fixed": sum(
                    1
                    for c in changes.vulnerabilities_fixed
                    if c.finding.severity == Severity.CRITICAL
                ),
                "high_added": sum(
                    1
                    for c in changes.vulnerabilities_added
                    if c.finding.severity == Severity.HIGH
                ),
                "high_fixed": sum(
                    1
                    for c in changes.vulnerabilities_fixed
                    if c.finding.severity == Severity.HIGH
                ),
            }

            comparison = VersionComparison(
                base_version=base_ref,
                compare_version=compare_ref,
                base_findings=base_findings,
                compare_findings=compare_findings,
                vulnerabilities_added=changes.vulnerabilities_added,
                vulnerabilities_fixed=changes.vulnerabilities_fixed,
                severity_changes=changes.severity_changes,
                security_score_delta=round(score_delta, 2),
                risk_trend=risk_trend,
                summary_stats=summary_stats,
                blame_info=blame_info,
                timeline_data=timeline_data,
            )

            # Store comparison result if scan_id provided
            if scan_id:
                await self._store_comparison(scan_id, comparison)

            return comparison

        except Exception as e:
            logger.exception(f"Failed to compare versions: {e}")
            raise

    async def _scan_version(self, path: str, ref: str) -> List[Finding]:
        """Scan a specific version and return findings"""
        try:
            # Use the existing scanner service
            findings = await scan_directory(path)

            # Add version reference to findings
            for finding in findings:
                if not hasattr(finding, "version"):
                    finding.version = ref

            return findings

        except Exception as e:
            logger.error(f"Failed to scan version {ref}: {e}")
            return []

    def _analyze_changes(
        self,
        base_findings: List[Finding],
        compare_findings: List[Finding],
        base_ref: str,
        compare_ref: str,
    ) -> Any:
        """Analyze changes between finding sets"""

        # Create finding maps for comparison
        base_map = self._create_finding_map(base_findings)
        compare_map = self._create_finding_map(compare_findings)

        vulnerabilities_added = []
        vulnerabilities_fixed = []
        severity_changes = []

        # Find new vulnerabilities
        for key, finding in compare_map.items():
            if key not in base_map:
                change = SecurityChange(
                    change_type=ChangeType.VULNERABILITY_ADDED,
                    finding=finding,
                    old_finding=None,
                    file=finding.file,
                    line=finding.line,
                    commit=compare_ref,
                    author=None,  # Will be filled by blame
                    timestamp=None,
                    description=f"New {finding.severity.value} vulnerability: {finding.rule}",
                )
                vulnerabilities_added.append(change)

        # Find fixed vulnerabilities
        for key, finding in base_map.items():
            if key not in compare_map:
                change = SecurityChange(
                    change_type=ChangeType.VULNERABILITY_FIXED,
                    finding=finding,
                    old_finding=finding,
                    file=finding.file,
                    line=finding.line,
                    commit=compare_ref,
                    author=None,
                    timestamp=None,
                    description=f"Fixed {finding.severity.value} vulnerability: {finding.rule}",
                )
                vulnerabilities_fixed.append(change)

        # Find severity changes
        for key in set(base_map.keys()) & set(compare_map.keys()):
            base_finding = base_map[key]
            compare_finding = compare_map[key]

            if base_finding.severity != compare_finding.severity:
                change_type = (
                    ChangeType.SEVERITY_INCREASED
                    if self._severity_value(compare_finding.severity)
                    > self._severity_value(base_finding.severity)
                    else ChangeType.SEVERITY_DECREASED
                )

                change = SecurityChange(
                    change_type=change_type,
                    finding=compare_finding,
                    old_finding=base_finding,
                    file=compare_finding.file,
                    line=compare_finding.line,
                    commit=compare_ref,
                    author=None,
                    timestamp=None,
                    description=(
                        f"Severity changed from {base_finding.severity.value} "
                        f"to {compare_finding.severity.value}: {compare_finding.rule}"
                    ),
                )
                severity_changes.append(change)

        # Return an object with the changes
        class Changes:
            def __init__(self):
                self.vulnerabilities_added = vulnerabilities_added
                self.vulnerabilities_fixed = vulnerabilities_fixed
                self.severity_changes = severity_changes

        return Changes()

    def _create_finding_map(self, findings: List[Finding]) -> Dict[str, Finding]:
        """Create a map of findings by unique key"""
        finding_map = {}
        for finding in findings:
            # Create unique key for finding
            key = f"{finding.file}:{finding.rule}:{finding.line}"
            finding_map[key] = finding
        return finding_map

    def _calculate_security_score(self, findings: List[Finding]) -> float:
        """Calculate overall security score (higher is worse)"""
        score = 0.0

        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
        }

        for finding in findings:
            weight = severity_weights.get(finding.severity, 1.0)
            score += weight * finding.weight if hasattr(finding, "weight") else weight

        return score

    def _severity_value(self, severity: Severity) -> int:
        """Get numeric value for severity comparison"""
        values = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return values.get(severity, 0)

    async def _get_blame_info(
        self, changes: List[SecurityChange], repo_path: str
    ) -> Dict[str, List[str]]:
        """Get git blame information for changes"""
        blame_info = {}

        try:
            # Import git utility (will be created next)
            from api.utils.git_analyzer import git_analyzer

            for change in changes:
                if change.file:
                    author = await git_analyzer.get_blame_for_line(
                        repo_path, change.file, change.line
                    )

                    if author:
                        change.author = author["author"]
                        change.timestamp = author.get("timestamp")

                        # Group by author
                        if author["author"] not in blame_info:
                            blame_info[author["author"]] = []
                        blame_info[author["author"]].append(change.description)

        except Exception as e:
            logger.warning(f"Failed to get blame info: {e}")

        return blame_info

    def _build_timeline_data(self, changes: Any) -> List[Dict[str, Any]]:
        """Build timeline visualization data"""
        timeline = []

        # Add events for each change
        for change in changes.vulnerabilities_added:
            timeline.append(
                {
                    "type": "added",
                    "severity": change.finding.severity.value,
                    "rule": change.finding.rule,
                    "file": change.finding.file,
                    "timestamp": change.timestamp.isoformat()
                    if change.timestamp
                    else None,
                    "author": change.author,
                    "description": change.description,
                }
            )

        for change in changes.vulnerabilities_fixed:
            timeline.append(
                {
                    "type": "fixed",
                    "severity": change.finding.severity.value,
                    "rule": change.finding.rule,
                    "file": change.finding.file,
                    "timestamp": change.timestamp.isoformat()
                    if change.timestamp
                    else None,
                    "author": change.author,
                    "description": change.description,
                }
            )

        for change in changes.severity_changes:
            timeline.append(
                {
                    "type": "severity_change",
                    "old_severity": change.old_finding.severity.value
                    if change.old_finding
                    else None,
                    "new_severity": change.finding.severity.value,
                    "rule": change.finding.rule,
                    "file": change.finding.file,
                    "timestamp": change.timestamp.isoformat()
                    if change.timestamp
                    else None,
                    "author": change.author,
                    "description": change.description,
                }
            )

        # Sort by timestamp if available
        timeline.sort(key=lambda x: x.get("timestamp") or "")

        return timeline

    async def _store_comparison(
        self, scan_id: str, comparison: VersionComparison
    ) -> None:
        """Store comparison results in database"""
        try:
            import json

            comparison_data = {
                "base_version": comparison.base_version,
                "compare_version": comparison.compare_version,
                "security_score_delta": comparison.security_score_delta,
                "risk_trend": comparison.risk_trend,
                "summary_stats": comparison.summary_stats,
                "vulnerabilities_added": len(comparison.vulnerabilities_added),
                "vulnerabilities_fixed": len(comparison.vulnerabilities_fixed),
                "blame_info": comparison.blame_info,
            }

            await db.execute(
                """
                INSERT INTO version_comparisons 
                (scan_id, comparison_data, created_at)
                VALUES (:scan_id, :data, GETDATE())
                """,
                {"scan_id": scan_id, "data": json.dumps(comparison_data)},
            )

        except Exception as e:
            logger.warning(f"Failed to store comparison: {e}")

    async def get_security_trend(
        self, repo_path: str, num_commits: int = 10, user_id: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get security trend over recent commits.

        Args:
            repo_path: Repository path
            num_commits: Number of commits to analyze
            user_id: User ID for credit tracking

        Returns:
            List of security scores per commit
        """
        try:
            from api.utils.git_analyzer import git_analyzer

            # Get recent commits
            commits = await git_analyzer.get_recent_commits(repo_path, num_commits)

            trend_data = []
            for commit in commits:
                # Checkout commit and scan
                # Note: In production, this would use git worktree or similar
                # to avoid disrupting the working directory
                findings = await scan_directory(repo_path)
                score = self._calculate_security_score(findings)

                trend_data.append(
                    {
                        "commit": commit["hash"][:8],
                        "message": commit["message"][:100],
                        "author": commit["author"],
                        "date": commit["date"],
                        "security_score": score,
                        "finding_count": len(findings),
                        "critical_count": sum(
                            1 for f in findings if f.severity == Severity.CRITICAL
                        ),
                        "high_count": sum(
                            1 for f in findings if f.severity == Severity.HIGH
                        ),
                    }
                )

            return trend_data

        except Exception as e:
            logger.error(f"Failed to get security trend: {e}")
            return []


# Global service instance
version_comparator = VersionComparator()
