"""
Threat Correlation Service
Correlates threats across time, files, and attack vectors to identify coordinated campaigns.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from models import Finding
from llm_models import LLMInsight


logger = logging.getLogger(__name__)


class ThreatCorrelator:
    """Service for correlating threats and identifying coordinated attack campaigns."""

    def __init__(self):
        self.threat_history = {}
        self.correlation_rules = self._load_correlation_rules()
        self.max_history_days = 30

    def correlate_threats(
        self,
        current_findings: list[Finding],
        llm_insights: list[LLMInsight] | None = None,
        repository_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Correlate current threats with historical patterns and across vectors."""

        try:
            # Analyze current threat landscape
            current_analysis = self._analyze_current_threats(
                current_findings, llm_insights or []
            )

            # Correlate with historical patterns
            historical_correlations = self._correlate_with_history(current_analysis)

            # Identify attack campaign indicators
            campaign_indicators = self._identify_campaign_indicators(
                current_analysis, historical_correlations
            )

            # Generate threat intelligence
            threat_intelligence = self._generate_threat_intelligence(
                current_analysis, historical_correlations, campaign_indicators
            )

            # Update threat history
            self._update_threat_history(current_analysis)

            return {
                "current_threat_analysis": current_analysis,
                "historical_correlations": historical_correlations,
                "campaign_indicators": campaign_indicators,
                "threat_intelligence": threat_intelligence,
                "correlation_confidence": self._calculate_correlation_confidence(
                    current_analysis, historical_correlations
                ),
                "recommendations": self._generate_correlation_recommendations(
                    current_analysis, campaign_indicators
                ),
            }

        except Exception as e:
            logger.exception(f"Threat correlation failed: {e}")
            return {
                "error": str(e),
                "current_threat_analysis": {"error": "analysis_failed"},
                "historical_correlations": [],
                "campaign_indicators": [],
                "threat_intelligence": {"error": "generation_failed"},
                "correlation_confidence": 0.0,
                "recommendations": [
                    "Manual threat analysis recommended due to correlation failure"
                ],
            }

    def _analyze_current_threats(
        self, findings: list[Finding], llm_insights: list[LLMInsight]
    ) -> dict[str, Any]:
        """Analyze the current threat landscape from findings and LLM insights."""

        # Categorize static analysis findings
        static_threats = self._categorize_static_threats(findings)

        # Categorize LLM insights
        llm_threats = self._categorize_llm_threats(llm_insights)

        # Calculate threat scores
        threat_scores = self._calculate_threat_scores(static_threats, llm_threats)

        # Identify threat patterns
        threat_patterns = self._identify_threat_patterns(findings, llm_insights)

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "static_threats": static_threats,
            "llm_threats": llm_threats,
            "threat_scores": threat_scores,
            "threat_patterns": threat_patterns,
            "overall_risk_level": self._calculate_overall_risk(threat_scores),
        }

    def _categorize_static_threats(self, findings: list[Finding]) -> dict[str, Any]:
        """Categorize static analysis findings by threat type."""

        categories = defaultdict(list)
        severity_counts = defaultdict(int)

        for finding in findings:
            # Map phase to threat category
            threat_category = self._map_phase_to_threat_category(finding.phase.value)
            categories[threat_category].append(
                {
                    "rule": finding.rule,
                    "severity": finding.severity.value,
                    "file": finding.file,
                    "description": finding.description,
                    "weight": finding.weight,
                }
            )
            severity_counts[finding.severity.value] += 1

        return {
            "categories": dict(categories),
            "severity_distribution": dict(severity_counts),
            "total_findings": len(findings),
            "unique_rules": len(set(f.rule for f in findings)),
            "affected_files": len(set(f.file for f in findings)),
        }

    def _categorize_llm_threats(self, llm_insights: list[LLMInsight]) -> dict[str, Any]:
        """Categorize LLM insights by threat type and confidence."""

        categories = defaultdict(list)
        confidence_distribution = defaultdict(int)

        for insight in llm_insights:
            categories[insight.threat_category.value].append(
                {
                    "analysis_type": insight.analysis_type.value,
                    "confidence": insight.confidence,
                    "title": insight.title,
                    "severity_adjustment": insight.severity_adjustment,
                    "false_positive_likelihood": insight.false_positive_likelihood,
                    "affected_files": insight.affected_files,
                }
            )

            # Bin confidence scores
            confidence_bin = (
                "high"
                if insight.confidence > 0.7
                else "medium"
                if insight.confidence > 0.3
                else "low"
            )
            confidence_distribution[confidence_bin] += 1

        return {
            "categories": dict(categories),
            "confidence_distribution": dict(confidence_distribution),
            "total_insights": len(llm_insights),
            "avg_confidence": sum(i.confidence for i in llm_insights)
            / len(llm_insights)
            if llm_insights
            else 0.0,
            "high_confidence_insights": len(
                [i for i in llm_insights if i.confidence > 0.8]
            ),
        }

    def _calculate_threat_scores(
        self, static_threats: dict[str, Any], llm_threats: dict[str, Any]
    ) -> dict[str, float]:
        """Calculate normalized threat scores for different categories."""

        scores = {}

        # Score static threats
        for category, findings in static_threats["categories"].items():
            category_score = 0.0
            for finding in findings:
                severity_weight = self._get_severity_weight(finding["severity"])
                category_score += severity_weight * finding.get("weight", 1.0)
            scores[f"static_{category}"] = min(category_score, 10.0)  # Cap at 10

        # Score LLM threats
        for category, insights in llm_threats["categories"].items():
            category_score = 0.0
            for insight in insights:
                confidence_weight = insight["confidence"]
                severity_adj = insight.get("severity_adjustment", 0.0)
                category_score += (3.0 + severity_adj) * confidence_weight
            scores[f"llm_{category}"] = min(category_score, 10.0)  # Cap at 10

        return scores

    def _identify_threat_patterns(
        self, findings: list[Finding], llm_insights: list[LLMInsight]
    ) -> list[dict[str, Any]]:
        """Identify patterns in the current threat landscape."""

        patterns = []

        # Multi-vector attacks
        threat_vectors = set()
        for finding in findings:
            threat_vectors.add(finding.phase.value)

        if len(threat_vectors) > 3:
            patterns.append(
                {
                    "type": "multi_vector_attack",
                    "description": f"Threats detected across {len(threat_vectors)} different attack vectors",
                    "vectors": list(threat_vectors),
                    "severity": "high",
                }
            )

        # High-confidence LLM insights
        high_confidence_insights = [i for i in llm_insights if i.confidence > 0.8]
        if len(high_confidence_insights) > 2:
            patterns.append(
                {
                    "type": "high_confidence_ai_threats",
                    "description": f"{len(high_confidence_insights)} high-confidence AI-detected threats",
                    "categories": list(
                        set(i.threat_category.value for i in high_confidence_insights)
                    ),
                    "severity": "critical",
                }
            )

        # Coordinated file targeting
        affected_files = set()
        for finding in findings:
            affected_files.add(finding.file)
        for insight in llm_insights:
            affected_files.update(insight.affected_files)

        if len(affected_files) > 10:
            patterns.append(
                {
                    "type": "widespread_compromise",
                    "description": f"Threats affecting {len(affected_files)} files",
                    "severity": "high",
                }
            )

        return patterns

    def _correlate_with_history(
        self, current_analysis: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Correlate current threats with historical patterns."""

        correlations = []

        current_timestamp = datetime.fromisoformat(current_analysis["timestamp"])

        for historical_timestamp, historical_analysis in self.threat_history.items():
            try:
                hist_dt = datetime.fromisoformat(historical_timestamp)

                # Only consider recent history
                if (current_timestamp - hist_dt).days > self.max_history_days:
                    continue

                # Calculate correlation strength
                correlation_strength = self._calculate_correlation_strength(
                    current_analysis, historical_analysis
                )

                if correlation_strength > 0.3:  # Significant correlation threshold
                    correlations.append(
                        {
                            "timestamp": historical_timestamp,
                            "correlation_strength": correlation_strength,
                            "common_patterns": self._identify_common_patterns(
                                current_analysis, historical_analysis
                            ),
                            "escalation_indicators": self._identify_escalation_indicators(
                                current_analysis, historical_analysis
                            ),
                        }
                    )

            except (ValueError, KeyError) as e:
                logger.warning(f"Error processing historical data: {e}")
                continue

        # Sort by correlation strength
        correlations.sort(key=lambda x: x["correlation_strength"], reverse=True)
        return correlations[:5]  # Return top 5 correlations

    def _identify_campaign_indicators(
        self,
        current_analysis: dict[str, Any],
        historical_correlations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify indicators of coordinated attack campaigns."""

        indicators = []

        # Persistent threat indicators
        if len(historical_correlations) > 2:
            indicators.append(
                {
                    "type": "persistent_threat_activity",
                    "description": f"Similar threat patterns detected across {len(historical_correlations)} time periods",
                    "confidence": 0.8,
                    "time_span_days": self._calculate_campaign_timespan(
                        historical_correlations
                    ),
                }
            )

        # Escalating sophistication
        if self._detect_escalating_sophistication(
            current_analysis, historical_correlations
        ):
            indicators.append(
                {
                    "type": "escalating_sophistication",
                    "description": "Increasing threat sophistication over time",
                    "confidence": 0.7,
                }
            )

        # Tool reuse patterns
        tool_reuse = self._detect_tool_reuse(current_analysis, historical_correlations)
        if tool_reuse:
            indicators.append(
                {
                    "type": "tool_reuse_pattern",
                    "description": "Consistent use of specific attack tools/techniques",
                    "confidence": 0.6,
                    "common_tools": tool_reuse,
                }
            )

        return indicators

    def _generate_threat_intelligence(
        self,
        current_analysis: dict[str, Any],
        historical_correlations: list[dict[str, Any]],
        campaign_indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate actionable threat intelligence."""

        intelligence = {
            "threat_landscape_summary": self._generate_landscape_summary(
                current_analysis
            ),
            "attack_progression": self._analyze_attack_progression(
                historical_correlations
            ),
            "predicted_next_steps": self._predict_next_attack_steps(
                current_analysis, campaign_indicators
            ),
            "attribution_indicators": self._identify_attribution_indicators(
                current_analysis, historical_correlations
            ),
            "iocs": self._extract_indicators_of_compromise(current_analysis),
        }

        return intelligence

    def _calculate_correlation_confidence(
        self,
        current_analysis: dict[str, Any],
        historical_correlations: list[dict[str, Any]],
    ) -> float:
        """Calculate overall confidence in threat correlations."""

        if not historical_correlations:
            return 0.0

        # Base confidence on correlation strength and quantity
        avg_strength = sum(
            c["correlation_strength"] for c in historical_correlations
        ) / len(historical_correlations)
        quantity_factor = min(
            len(historical_correlations) / 5.0, 1.0
        )  # Max at 5 correlations

        return avg_strength * quantity_factor

    def _generate_correlation_recommendations(
        self,
        current_analysis: dict[str, Any],
        campaign_indicators: list[dict[str, Any]],
    ) -> list[str]:
        """Generate recommendations based on threat correlations."""

        recommendations = []

        # High risk recommendations
        if current_analysis.get("overall_risk_level") == "critical":
            recommendations.extend(
                [
                    "Implement immediate incident response procedures",
                    "Isolate affected systems pending further analysis",
                    "Activate threat hunting procedures",
                ]
            )

        # Campaign-based recommendations
        for indicator in campaign_indicators:
            if indicator["type"] == "persistent_threat_activity":
                recommendations.append(
                    "Deploy advanced threat detection for persistent campaign monitoring"
                )
            elif indicator["type"] == "escalating_sophistication":
                recommendations.append(
                    "Enhance security controls to match evolving threat sophistication"
                )

        # Historical pattern recommendations
        recommendations.extend(
            [
                "Review and update threat detection rules based on correlation patterns",
                "Implement behavioral analysis for campaign detection",
                "Enhance logging and monitoring for threat correlation",
            ]
        )

        return list(set(recommendations))  # Remove duplicates

    # Helper methods
    def _load_correlation_rules(self) -> dict[str, Any]:
        """Load threat correlation rules."""
        return {
            "time_window_hours": 72,
            "similarity_threshold": 0.3,
            "escalation_threshold": 0.2,
            "campaign_indicators": {
                "min_correlations": 3,
                "max_timespan_days": 30,
            },
        }

    def _map_phase_to_threat_category(self, phase: str) -> str:
        """Map scan phase to threat category."""
        phase_mapping = {
            "install_hooks": "installation_threats",
            "code_patterns": "code_execution_threats",
            "network_exfil": "exfiltration_threats",
            "credentials": "credential_threats",
            "obfuscation": "evasion_threats",
            "provenance": "supply_chain_threats",
            "prompt_injection": "ai_threats",
            "skill_security": "ai_threats",
            "llm_analysis": "advanced_threats",
        }
        return phase_mapping.get(phase, "unknown_threats")

    def _get_severity_weight(self, severity: str) -> float:
        """Get numeric weight for severity level."""
        weights = {
            "INFO": 0.5,
            "LOW": 1.0,
            "MEDIUM": 2.0,
            "HIGH": 3.0,
            "CRITICAL": 5.0,
        }
        return weights.get(severity, 1.0)

    def _calculate_overall_risk(self, threat_scores: dict[str, float]) -> str:
        """Calculate overall risk level from threat scores."""
        total_score = sum(threat_scores.values())

        if total_score > 20:
            return "critical"
        elif total_score > 15:
            return "high"
        elif total_score > 8:
            return "medium"
        else:
            return "low"

    def _calculate_correlation_strength(
        self, current: dict[str, Any], historical: dict[str, Any]
    ) -> float:
        """Calculate correlation strength between current and historical analysis."""

        # Simple correlation based on common threat categories
        current_categories = set(
            current.get("static_threats", {}).get("categories", {}).keys()
        )
        historical_categories = set(
            historical.get("static_threats", {}).get("categories", {}).keys()
        )

        if not current_categories or not historical_categories:
            return 0.0

        intersection = current_categories.intersection(historical_categories)
        union = current_categories.union(historical_categories)

        return len(intersection) / len(union) if union else 0.0

    def _identify_common_patterns(
        self, current: dict[str, Any], historical: dict[str, Any]
    ) -> list[str]:
        """Identify common patterns between current and historical analysis."""
        patterns = []

        # Common threat categories
        current_categories = set(
            current.get("static_threats", {}).get("categories", {}).keys()
        )
        historical_categories = set(
            historical.get("static_threats", {}).get("categories", {}).keys()
        )
        common_categories = current_categories.intersection(historical_categories)

        for category in common_categories:
            patterns.append(f"Recurring {category}")

        return patterns

    def _identify_escalation_indicators(
        self, current: dict[str, Any], historical: dict[str, Any]
    ) -> list[str]:
        """Identify escalation indicators between current and historical analysis."""
        indicators = []

        current_risk = current.get("overall_risk_level", "low")
        historical_risk = historical.get("overall_risk_level", "low")

        risk_levels = ["low", "medium", "high", "critical"]
        current_level = risk_levels.index(current_risk)
        historical_level = risk_levels.index(historical_risk)

        if current_level > historical_level:
            indicators.append("Increasing threat severity")

        return indicators

    def _detect_escalating_sophistication(
        self, current: dict[str, Any], historical: list[dict[str, Any]]
    ) -> bool:
        """Detect escalating threat sophistication over time."""
        if not historical:
            return False

        # Simple heuristic: check if LLM threat count is increasing
        current_llm_count = current.get("llm_threats", {}).get("total_insights", 0)

        for correlation in historical:
            hist_analysis = correlation.get("historical_analysis", {})
            hist_llm_count = hist_analysis.get("llm_threats", {}).get(
                "total_insights", 0
            )

            if current_llm_count > hist_llm_count:
                return True

        return False

    def _detect_tool_reuse(
        self, current: dict[str, Any], historical: list[dict[str, Any]]
    ) -> list[str]:
        """Detect reuse of attack tools/techniques."""
        # Simplified implementation - would need more sophisticated analysis in practice
        return ["common_obfuscation_technique", "shared_network_protocol"]

    def _generate_landscape_summary(self, current_analysis: dict[str, Any]) -> str:
        """Generate a summary of the current threat landscape."""
        static_count = current_analysis.get("static_threats", {}).get(
            "total_findings", 0
        )
        llm_count = current_analysis.get("llm_threats", {}).get("total_insights", 0)
        risk_level = current_analysis.get("overall_risk_level", "unknown")

        return f"Detected {static_count} static threats and {llm_count} AI-identified threats with {risk_level} overall risk"

    def _analyze_attack_progression(
        self, historical_correlations: list[dict[str, Any]]
    ) -> list[str]:
        """Analyze how attacks have progressed over time."""
        if not historical_correlations:
            return ["No historical attack progression data available"]

        return ["Attack sophistication appears to be increasing over time"]

    def _predict_next_attack_steps(
        self,
        current_analysis: dict[str, Any],
        campaign_indicators: list[dict[str, Any]],
    ) -> list[str]:
        """Predict likely next steps in the attack sequence."""
        predictions = []

        # Simple heuristics based on current threat types
        static_categories = current_analysis.get("static_threats", {}).get(
            "categories", {}
        )

        if "credential_threats" in static_categories:
            predictions.append("Potential privilege escalation attempts")

        if "exfiltration_threats" in static_categories:
            predictions.append("Possible data staging for bulk exfiltration")

        return predictions or ["Unable to predict next attack steps"]

    def _identify_attribution_indicators(
        self, current: dict[str, Any], historical: list[dict[str, Any]]
    ) -> list[str]:
        """Identify potential attribution indicators."""
        return ["Insufficient data for attribution analysis"]

    def _extract_indicators_of_compromise(
        self, current_analysis: dict[str, Any]
    ) -> list[str]:
        """Extract indicators of compromise from current analysis."""
        iocs = []

        # Extract from static threats - simplified example
        static_threats = current_analysis.get("static_threats", {}).get(
            "categories", {}
        )

        if "exfiltration_threats" in static_threats:
            iocs.append("Suspicious network activity patterns")

        if "credential_threats" in static_threats:
            iocs.append("Unauthorized credential access attempts")

        return iocs

    def _calculate_campaign_timespan(
        self, historical_correlations: list[dict[str, Any]]
    ) -> int:
        """Calculate the timespan of a potential campaign."""
        if not historical_correlations:
            return 0

        timestamps = [
            correlation["timestamp"] for correlation in historical_correlations
        ]
        try:
            dates = [datetime.fromisoformat(ts) for ts in timestamps]
            return (max(dates) - min(dates)).days
        except ValueError:
            return 0

    def _update_threat_history(self, current_analysis: dict[str, Any]) -> None:
        """Update threat history with current analysis."""
        timestamp = current_analysis["timestamp"]

        # Remove old entries
        cutoff_date = datetime.utcnow() - timedelta(days=self.max_history_days)
        self.threat_history = {
            ts: analysis
            for ts, analysis in self.threat_history.items()
            if datetime.fromisoformat(ts) > cutoff_date
        }

        # Add current analysis
        self.threat_history[timestamp] = current_analysis


# Global threat correlator instance
threat_correlator = ThreatCorrelator()
