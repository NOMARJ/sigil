"""
Compliance Mapper Service
Maps security findings to compliance frameworks and regulations
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime

from ..models import Finding, SubscriptionTier
from ..services.credit_service import CreditService

logger = logging.getLogger(__name__)

class ComplianceMapper:
    """Maps security findings to compliance frameworks"""

    def __init__(self):
        self.credit_service = CreditService()
        self.frameworks_data = self._load_frameworks()

    def _load_frameworks(self) -> Dict[str, Any]:
        """Load compliance frameworks data"""
        try:
            data_path = Path(__file__).parent.parent / "data" / "compliance_frameworks.json"
            with open(data_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load compliance frameworks: {e}")
            return {"frameworks": {}, "pattern_mappings": {}}

    async def map_findings_to_compliance(
        self,
        findings: List[Finding],
        user_id: str,
        frameworks: Optional[List[str]] = None,
        compliance_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Map security findings to compliance frameworks.
        
        Args:
            findings: List of security findings
            user_id: User ID for credit tracking
            frameworks: Optional list of frameworks to check (default: all)
            compliance_context: Optional context (e.g., "healthcare", "financial")
            
        Returns:
            Compliance mapping with framework violations and priorities
        """
        # Check credits (3 credits for compliance mapping)
        credits_needed = 3
        has_credits = await self.credit_service.check_balance(
            user_id, credits_needed
        )
        
        if not has_credits:
            return {
                "error": "Insufficient credits",
                "credits_needed": credits_needed
            }
        
        # Deduct credits
        success = await self.credit_service.deduct_credits(
            user_id=user_id,
            amount=credits_needed,
            description="Compliance mapping analysis"
        )
        
        if not success:
            return {"error": "Failed to deduct credits"}
        
        try:
            # If no frameworks specified, use all
            if not frameworks:
                frameworks = list(self.frameworks_data["frameworks"].keys())
            
            # Build compliance report
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "findings_count": len(findings),
                "frameworks_checked": frameworks,
                "compliance_context": compliance_context,
                "violations": {},
                "summary": {},
                "remediation_priorities": [],
                "export_format": None
            }
            
            # Track violations by framework
            for framework in frameworks:
                report["violations"][framework] = []
            
            # Map each finding to compliance frameworks
            for finding in findings:
                pattern = self._extract_pattern_from_finding(finding)
                
                if pattern in self.frameworks_data["pattern_mappings"]:
                    mapping = self.frameworks_data["pattern_mappings"][pattern]
                    
                    # Add to violations for each framework
                    for framework_ref in mapping.get("frameworks", []):
                        framework_name, category = framework_ref.split(":", 1)
                        
                        if framework_name in report["violations"]:
                            violation = {
                                "finding_id": finding.id,
                                "finding_description": finding.description,
                                "pattern": pattern,
                                "category": category,
                                "severity": self._adjust_severity(
                                    mapping["severity_base"],
                                    framework_name,
                                    compliance_context
                                ),
                                "file": finding.file_path,
                                "line": finding.line_number,
                                "remediation_priority": mapping.get("remediation_priority", 3)
                            }
                            
                            # Add framework-specific details
                            if framework_name in self.frameworks_data["frameworks"]:
                                fw_data = self.frameworks_data["frameworks"][framework_name]
                                
                                # Get category details
                                if framework_name == "OWASP" and category in fw_data["categories"]:
                                    violation["category_name"] = fw_data["categories"][category]["name"]
                                    violation["category_description"] = fw_data["categories"][category].get("description", "")
                                elif framework_name == "CWE" and category in fw_data["categories"]:
                                    violation["category_name"] = fw_data["categories"][category]["name"]
                                elif framework_name == "PCI_DSS" and category in fw_data.get("requirements", {}):
                                    violation["category_name"] = fw_data["requirements"][category]["name"]
                                elif framework_name == "HIPAA" and category in fw_data.get("safeguards", {}):
                                    violation["category_name"] = fw_data["safeguards"][category]["name"]
                                elif framework_name == "GDPR" and category in fw_data.get("articles", {}):
                                    violation["category_name"] = fw_data["articles"][category]["name"]
                                    violation["category_description"] = fw_data["articles"][category].get("description", "")
                            
                            report["violations"][framework_name].append(violation)
            
            # Generate summary statistics
            for framework in frameworks:
                violations = report["violations"][framework]
                if violations:
                    report["summary"][framework] = {
                        "total_violations": len(violations),
                        "critical": len([v for v in violations if v["severity"] == "CRITICAL"]),
                        "high": len([v for v in violations if v["severity"] == "HIGH"]),
                        "medium": len([v for v in violations if v["severity"] == "MEDIUM"]),
                        "low": len([v for v in violations if v["severity"] == "LOW"]),
                        "categories_affected": len(set(v["category"] for v in violations)),
                        "compliance_score": self._calculate_compliance_score(violations)
                    }
                else:
                    report["summary"][framework] = {
                        "total_violations": 0,
                        "compliance_score": 100.0
                    }
            
            # Build remediation priority list
            all_violations = []
            for framework_violations in report["violations"].values():
                all_violations.extend(framework_violations)
            
            # Sort by remediation priority and severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            all_violations.sort(
                key=lambda v: (v["remediation_priority"], severity_order.get(v["severity"], 4))
            )
            
            # Get unique violations for remediation list
            seen = set()
            for violation in all_violations:
                key = (violation["pattern"], violation["file"])
                if key not in seen:
                    seen.add(key)
                    report["remediation_priorities"].append({
                        "pattern": violation["pattern"],
                        "file": violation["file"],
                        "line": violation["line"],
                        "severity": violation["severity"],
                        "priority": violation["remediation_priority"],
                        "frameworks_violated": self._get_frameworks_for_pattern(violation["pattern"]),
                        "description": violation["finding_description"]
                    })
            
            # Limit to top 20 priorities
            report["remediation_priorities"] = report["remediation_priorities"][:20]
            
            # Generate export format
            report["export_format"] = self._generate_export_format(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to map compliance: {e}")
            return {"error": str(e)}

    def _extract_pattern_from_finding(self, finding: Finding) -> str:
        """Extract the pattern type from a finding"""
        # Map finding rules to pattern types
        rule_to_pattern = {
            "INSTALL_HOOK_NPM": "npm_install_hook",
            "INSTALL_HOOK_PIP": "pypi_setup_hook",
            "SQL_INJECTION": "sql_injection",
            "COMMAND_INJECTION": "command_injection",
            "XSS_REFLECTED": "xss_reflected",
            "XSS_STORED": "xss_stored",
            "PATH_TRAVERSAL": "path_traversal",
            "HARDCODED_SECRET": "hardcoded_secret",
            "EVAL_USAGE": "eval_usage",
            "DESERIALIZATION": "deserialization",
            "WEAK_CRYPTO": "weak_crypto",
            "MISSING_AUTH": "missing_auth",
            "CREDENTIAL_ACCESS": "credential_theft",
            "NETWORK_EXFIL": "network_exfiltration",
            "BACKDOOR": "backdoor",
            "OBFUSCATION": "obfuscation"
        }
        
        # Try to match the rule
        for rule_key, pattern in rule_to_pattern.items():
            if rule_key.lower() in finding.rule.lower():
                return pattern
        
        # Default pattern based on phase
        phase_defaults = {
            "install_hooks": "npm_install_hook",
            "code_patterns": "eval_usage",
            "network": "network_exfiltration",
            "credentials": "credential_theft",
            "obfuscation": "obfuscation"
        }
        
        return phase_defaults.get(finding.phase, "unknown")

    def _adjust_severity(
        self,
        base_severity: str,
        framework: str,
        compliance_context: Optional[str]
    ) -> str:
        """Adjust severity based on compliance context"""
        # Apply framework-specific multipliers
        if compliance_context:
            adjustments = self.frameworks_data.get("severity_adjustments", {})
            
            # Check if context matches a framework needing adjustment
            if compliance_context == "healthcare" and "HIPAA" in adjustments:
                # Increase severity for healthcare context
                if base_severity == "MEDIUM":
                    return "HIGH"
                elif base_severity == "LOW":
                    return "MEDIUM"
            elif compliance_context == "financial" and "PCI_DSS" in adjustments:
                # Increase severity for financial context
                if base_severity == "MEDIUM":
                    return "HIGH"
                elif base_severity == "LOW":
                    return "MEDIUM"
            elif compliance_context == "privacy" and "GDPR" in adjustments:
                # Increase severity for privacy context
                if base_severity == "LOW":
                    return "MEDIUM"
        
        return base_severity

    def _calculate_compliance_score(self, violations: List[Dict]) -> float:
        """Calculate compliance score (0-100)"""
        if not violations:
            return 100.0
        
        # Weight violations by severity
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1
        }
        
        total_weight = sum(weights.get(v["severity"], 1) for v in violations)
        
        # Score decreases with more/severe violations
        # Max penalty of 100 at 50+ weighted violations
        score = max(0, 100 - (total_weight * 2))
        
        return round(score, 1)

    def _get_frameworks_for_pattern(self, pattern: str) -> List[str]:
        """Get all frameworks that flag this pattern"""
        if pattern in self.frameworks_data["pattern_mappings"]:
            frameworks = self.frameworks_data["pattern_mappings"][pattern].get("frameworks", [])
            return [fw.split(":")[0] for fw in frameworks]
        return []

    def _generate_export_format(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an export-friendly format for auditors"""
        export = {
            "report_date": report["timestamp"],
            "executive_summary": {
                "total_findings": report["findings_count"],
                "frameworks_evaluated": report["frameworks_checked"],
                "compliance_context": report["compliance_context"],
                "overall_compliance": {}
            },
            "detailed_violations": {},
            "remediation_roadmap": []
        }
        
        # Add compliance scores
        for framework, summary in report["summary"].items():
            export["executive_summary"]["overall_compliance"][framework] = {
                "score": summary["compliance_score"],
                "violations": summary["total_violations"],
                "status": "COMPLIANT" if summary["compliance_score"] >= 80 else "NON_COMPLIANT"
            }
        
        # Add detailed violations grouped by framework
        for framework, violations in report["violations"].items():
            if violations:
                export["detailed_violations"][framework] = {}
                
                # Group by category
                for violation in violations:
                    category = violation["category"]
                    if category not in export["detailed_violations"][framework]:
                        export["detailed_violations"][framework][category] = {
                            "name": violation.get("category_name", category),
                            "description": violation.get("category_description", ""),
                            "findings": []
                        }
                    
                    export["detailed_violations"][framework][category]["findings"].append({
                        "file": violation["file"],
                        "line": violation["line"],
                        "severity": violation["severity"],
                        "description": violation["finding_description"]
                    })
        
        # Add remediation roadmap
        for priority in report["remediation_priorities"]:
            export["remediation_roadmap"].append({
                "priority_level": priority["priority"],
                "severity": priority["severity"],
                "issue": priority["description"],
                "location": f"{priority['file']}:{priority['line']}",
                "frameworks_impacted": priority["frameworks_violated"],
                "remediation_effort": self._estimate_effort(priority["pattern"])
            })
        
        return export

    def _estimate_effort(self, pattern: str) -> str:
        """Estimate remediation effort"""
        high_effort = ["sql_injection", "command_injection", "missing_auth", "weak_crypto"]
        medium_effort = ["xss_reflected", "xss_stored", "path_traversal", "deserialization"]
        low_effort = ["hardcoded_secret", "weak_password", "verbose_errors"]
        
        if pattern in high_effort:
            return "HIGH (1-2 weeks)"
        elif pattern in medium_effort:
            return "MEDIUM (2-5 days)"
        elif pattern in low_effort:
            return "LOW (< 1 day)"
        else:
            return "UNKNOWN"

    async def generate_compliance_report_markdown(
        self,
        report: Dict[str, Any]
    ) -> str:
        """Generate a markdown compliance report"""
        lines = [
            "# Compliance Assessment Report",
            f"**Generated**: {report['timestamp']}",
            f"**Total Findings**: {report['findings_count']}",
            f"**Compliance Context**: {report.get('compliance_context', 'General')}",
            "",
            "## Executive Summary",
            ""
        ]
        
        # Add compliance scores
        for framework, summary in report["summary"].items():
            status = "✅" if summary["compliance_score"] >= 80 else "❌"
            lines.extend([
                f"### {framework} {status}",
                f"- **Compliance Score**: {summary['compliance_score']}%",
                f"- **Total Violations**: {summary['total_violations']}",
            ])
            
            if summary["total_violations"] > 0:
                lines.extend([
                    f"- **Critical**: {summary.get('critical', 0)}",
                    f"- **High**: {summary.get('high', 0)}",
                    f"- **Medium**: {summary.get('medium', 0)}",
                    f"- **Low**: {summary.get('low', 0)}",
                ])
            lines.append("")
        
        # Add top remediation priorities
        if report["remediation_priorities"]:
            lines.extend([
                "## Top Remediation Priorities",
                "",
                "| Priority | Severity | Issue | Location | Frameworks |",
                "|----------|----------|-------|----------|------------|"
            ])
            
            for priority in report["remediation_priorities"][:10]:
                frameworks = ", ".join(priority["frameworks_violated"])
                location = f"{priority['file']}:{priority['line']}"
                lines.append(
                    f"| {priority['priority']} | {priority['severity']} | "
                    f"{priority['description'][:50]}... | {location} | {frameworks} |"
                )
            lines.append("")
        
        # Add detailed violations by framework
        lines.extend([
            "## Detailed Violations by Framework",
            ""
        ])
        
        for framework, violations in report["violations"].items():
            if violations:
                lines.append(f"### {framework}")
                
                # Group by category
                categories = {}
                for violation in violations:
                    cat = violation.get("category_name", violation["category"])
                    if cat not in categories:
                        categories[cat] = []
                    categories[cat].append(violation)
                
                for category, cat_violations in categories.items():
                    lines.extend([
                        f"#### {category} ({len(cat_violations)} violations)",
                        ""
                    ])
                    
                    for v in cat_violations[:5]:  # Show first 5 per category
                        lines.append(
                            f"- **{v['severity']}**: {v['finding_description'][:80]}... "
                            f"(`{v['file']}:{v['line']}`)"
                        )
                    
                    if len(cat_violations) > 5:
                        lines.append(f"- _{len(cat_violations) - 5} more violations..._")
                    lines.append("")
        
        return "\n".join(lines)


# Global mapper instance
compliance_mapper = ComplianceMapper()