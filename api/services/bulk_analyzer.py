"""
Bulk Analyzer Service
Performs batch analysis on groups of similar security findings
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime

from ..models import Finding
from ..services.pattern_grouper import pattern_grouper
from ..services.credit_service import credit_service
from ..services.model_router import model_router
from ..services.claude_service import claude_service
from ..prompts.bulk_analysis_prompts import BulkAnalysisPromptBuilder
from ..exceptions import InsufficientCreditsError

logger = logging.getLogger(__name__)


class BulkAnalyzer:
    """Analyzes groups of similar findings in batch"""

    async def analyze_bulk(
        self,
        user_id: str,
        findings: List[Finding],
        investigation_depth: str = "thorough",
        group_by_pattern: bool = True
    ) -> Dict[str, Any]:
        """
        Perform bulk analysis on multiple findings.
        
        Args:
            user_id: User ID for credit tracking
            findings: List of findings to analyze
            investigation_depth: Analysis depth (quick/thorough/exhaustive)
            group_by_pattern: Whether to group by pattern type first
            
        Returns:
            Bulk analysis results with pattern groups and recommendations
        """
        try:
            # Group findings by pattern
            if group_by_pattern:
                pattern_groups = pattern_grouper.group_findings(findings)
            else:
                # Treat all as single group
                pattern_groups = {
                    "UNGROUPED": {
                        "findings": findings,
                        "pattern_type": "MIXED",
                        "group_name": "All Findings",
                        "count": len(findings),
                        "files": list(set(f.file_path for f in findings)),
                        "severity_distribution": self._get_severity_distribution(findings),
                        "common_characteristics": {},
                        "root_cause_similarity": 0.0,
                        "likely_same_root_cause": False
                    }
                }
            
            # Calculate total credits needed
            total_credits = self._estimate_credits(pattern_groups, investigation_depth)
            
            # Check credits
            has_credits = await credit_service.check_balance(user_id, total_credits)
            if not has_credits:
                raise InsufficientCreditsError(
                    f"Need {total_credits} credits for bulk analysis"
                )
            
            # Analyze each group
            results = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_findings": len(findings),
                "pattern_groups": {},
                "summary": {},
                "recommendations": [],
                "credits_used": 0
            }
            
            for pattern_type, group in pattern_groups.items():
                if group["count"] > 0:
                    # Analyze group
                    group_result = await self._analyze_pattern_group(
                        user_id=user_id,
                        pattern_type=pattern_type,
                        group=group,
                        depth=investigation_depth
                    )
                    
                    results["pattern_groups"][pattern_type] = group_result
                    results["credits_used"] += group_result.get("credits_used", 0)
            
            # Generate overall summary
            results["summary"] = self._generate_summary(results["pattern_groups"])
            
            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(
                pattern_groups, results["pattern_groups"]
            )
            
            logger.info(
                f"Bulk analysis completed for user {user_id}: "
                f"{len(findings)} findings in {len(pattern_groups)} groups"
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Bulk analysis failed: {e}")
            raise

    async def _analyze_pattern_group(
        self,
        user_id: str,
        pattern_type: str,
        group: Dict[str, Any],
        depth: str
    ) -> Dict[str, Any]:
        """Analyze a single pattern group"""
        findings = group["findings"]
        
        # Determine model based on complexity
        model, credits = await model_router.get_model_for_request(
            user_id=user_id,
            task_type="bulk_investigation",
            context={
                "findings_count": len(findings),
                "depth": depth,
                "pattern_type": pattern_type
            }
        )
        
        # Build prompt
        prompt_builder = BulkAnalysisPromptBuilder()
        prompt = prompt_builder.build_bulk_analysis_prompt(
            pattern_type=pattern_type,
            findings=findings,
            common_characteristics=group.get("common_characteristics", {}),
            depth=depth
        )
        
        # Call Claude
        analysis = await claude_service.analyze_with_claude(
            prompt=prompt,
            model=model,
            max_tokens=2000
        )
        
        # Deduct credits
        await credit_service.deduct_credits(
            user_id=user_id,
            amount=credits,
            description=f"Bulk analysis: {pattern_type} ({len(findings)} findings)"
        )
        
        # Parse analysis
        result = {
            "pattern_type": pattern_type,
            "group_name": group["group_name"],
            "findings_count": len(findings),
            "files_affected": group["files"],
            "severity_distribution": group["severity_distribution"],
            "likely_same_root_cause": group.get("likely_same_root_cause", False),
            "root_cause_similarity": group.get("root_cause_similarity", 0.0),
            "analysis": analysis,
            "credits_used": credits,
            "model_used": model,
            "single_fix_possible": False,
            "fix_suggestion": None
        }
        
        # Get single fix suggestion if applicable
        if group.get("likely_same_root_cause"):
            fix = pattern_grouper.suggest_single_fix(group)
            if fix:
                result["single_fix_possible"] = True
                result["fix_suggestion"] = fix
        
        # Extract key insights from analysis
        result["key_insights"] = self._extract_insights(analysis)
        
        return result

    def _estimate_credits(
        self,
        pattern_groups: Dict[str, Dict],
        depth: str
    ) -> int:
        """Estimate total credits needed for analysis"""
        base_costs = {
            "quick": 3,
            "thorough": 5,
            "exhaustive": 10
        }
        
        base_cost = base_costs.get(depth, 5)
        total_credits = 0
        
        for group in pattern_groups.values():
            if group["count"] > 0:
                # More findings = slightly more credits
                multiplier = 1 + (min(group["count"], 10) * 0.1)
                total_credits += int(base_cost * multiplier)
        
        return total_credits

    def _generate_summary(
        self,
        analyzed_groups: Dict[str, Dict]
    ) -> Dict[str, Any]:
        """Generate overall summary of bulk analysis"""
        summary = {
            "total_groups": len(analyzed_groups),
            "patterns_found": [],
            "critical_issues": 0,
            "high_priority_fixes": [],
            "estimated_total_effort": "Unknown",
            "root_causes_identified": 0
        }
        
        total_effort_hours = 0
        
        for pattern_type, group in analyzed_groups.items():
            summary["patterns_found"].append({
                "type": pattern_type,
                "count": group["findings_count"],
                "severity": self._get_highest_severity(group["severity_distribution"])
            })
            
            # Count critical issues
            if "CRITICAL" in group["severity_distribution"]:
                summary["critical_issues"] += group["severity_distribution"]["CRITICAL"]
            
            # Track root causes
            if group.get("likely_same_root_cause"):
                summary["root_causes_identified"] += 1
            
            # Collect high priority fixes
            if group.get("single_fix_possible") and group.get("fix_suggestion"):
                fix = group["fix_suggestion"]
                summary["high_priority_fixes"].append({
                    "pattern": pattern_type,
                    "title": fix["title"],
                    "impact": f"{group['findings_count']} issues",
                    "effort": fix.get("estimated_effort", "Unknown")
                })
                
                # Estimate effort
                effort = fix.get("estimated_effort", "")
                if "hour" in effort:
                    hours = re.findall(r'(\d+)', effort)
                    if hours:
                        total_effort_hours += int(hours[0])
        
        # Estimate total effort
        if total_effort_hours > 0:
            if total_effort_hours <= 8:
                summary["estimated_total_effort"] = f"{total_effort_hours} hours"
            else:
                days = total_effort_hours / 8
                summary["estimated_total_effort"] = f"{days:.1f} days"
        
        return summary

    def _generate_recommendations(
        self,
        pattern_groups: Dict[str, Dict],
        analyzed_groups: Dict[str, Dict]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Priority 1: Critical issues with single fix
        for pattern_type, group in analyzed_groups.items():
            if (group.get("single_fix_possible") and 
                "CRITICAL" in group.get("severity_distribution", {})):
                
                recommendations.append({
                    "priority": 1,
                    "type": "CRITICAL_BATCH_FIX",
                    "pattern": pattern_type,
                    "title": f"Fix {group['findings_count']} {pattern_type} vulnerabilities",
                    "description": group.get("fix_suggestion", {}).get("description", ""),
                    "impact": "Critical security vulnerabilities",
                    "effort": group.get("fix_suggestion", {}).get("estimated_effort", "Unknown"),
                    "affected_files": len(group["files_affected"])
                })
        
        # Priority 2: High severity with common root cause
        for pattern_type, group in analyzed_groups.items():
            if (group.get("likely_same_root_cause") and 
                "HIGH" in group.get("severity_distribution", {}) and
                pattern_type not in [r["pattern"] for r in recommendations]):
                
                recommendations.append({
                    "priority": 2,
                    "type": "ROOT_CAUSE_FIX",
                    "pattern": pattern_type,
                    "title": f"Address root cause of {pattern_type}",
                    "description": f"Common root cause identified across {group['findings_count']} findings",
                    "impact": "High severity vulnerabilities",
                    "effort": self._estimate_effort_from_count(group['findings_count']),
                    "affected_files": len(group["files_affected"])
                })
        
        # Priority 3: Quick wins (low effort, multiple fixes)
        for pattern_type, group in analyzed_groups.items():
            fix = group.get("fix_suggestion", {})
            if (fix and "Low" in fix.get("estimated_effort", "") and
                group['findings_count'] >= 3 and
                pattern_type not in [r["pattern"] for r in recommendations]):
                
                recommendations.append({
                    "priority": 3,
                    "type": "QUICK_WIN",
                    "pattern": pattern_type,
                    "title": f"Quick fix for {group['findings_count']} {pattern_type} issues",
                    "description": fix.get("description", ""),
                    "impact": "Multiple vulnerabilities fixed quickly",
                    "effort": fix.get("estimated_effort", "Low"),
                    "affected_files": len(group["files_affected"])
                })
        
        # Sort by priority
        recommendations.sort(key=lambda r: (r["priority"], -r.get("affected_files", 0)))
        
        return recommendations[:10]  # Top 10 recommendations

    def _extract_insights(self, analysis: str) -> List[str]:
        """Extract key insights from analysis text"""
        insights = []
        
        # Look for key phrases
        key_phrases = [
            "root cause",
            "common pattern",
            "vulnerability chain",
            "exploit scenario",
            "false positive",
            "recommended fix",
            "security impact"
        ]
        
        lines = analysis.split('\n')
        for line in lines:
            line_lower = line.lower()
            if any(phrase in line_lower for phrase in key_phrases):
                # Clean and add insight
                insight = line.strip().strip('- •*')
                if len(insight) > 20 and len(insight) < 200:
                    insights.append(insight)
        
        return insights[:5]  # Top 5 insights

    def _get_severity_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        """Get severity distribution from findings"""
        distribution = {}
        for finding in findings:
            severity = finding.severity
            distribution[severity] = distribution.get(severity, 0) + 1
        return distribution

    def _get_highest_severity(self, distribution: Dict[str, int]) -> str:
        """Get highest severity from distribution"""
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for severity in severity_order:
            if severity in distribution and distribution[severity] > 0:
                return severity
        return "UNKNOWN"

    def _estimate_effort_from_count(self, count: int) -> str:
        """Estimate effort based on finding count"""
        if count <= 3:
            return "Low (< 2 hours)"
        elif count <= 10:
            return "Medium (2-4 hours)"
        elif count <= 20:
            return "High (4-8 hours)"
        else:
            return "Very High (1+ days)"


# Global analyzer instance
bulk_analyzer = BulkAnalyzer()