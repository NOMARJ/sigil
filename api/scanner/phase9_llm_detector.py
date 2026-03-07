"""
Phase 9: LLM-Powered Threat Detection
Pro tier feature that uses AI to detect sophisticated threats beyond static analysis.
"""

from __future__ import annotations

import logging
from typing import Any

from models import Finding, ScanPhase, Severity
from models.llm_models import (
    LLMAnalysisRequest,
    LLMAnalysisType,
    LLMThreatCategory,
)
from services.llm_service import llm_service


logger = logging.getLogger(__name__)


class Phase9LLMDetector:
    """AI-powered threat detector for sophisticated attacks."""

    def __init__(self):
        self.phase = ScanPhase.LLM_ANALYSIS

    async def scan_with_llm(
        self,
        file_contents: dict[str, str],
        static_findings: list[Finding],
        repository_context: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Perform LLM-powered analysis and return additional findings."""

        if not file_contents:
            logger.info("No file contents provided for LLM analysis")
            return []

        try:
            # Prepare static findings data for LLM context
            static_findings_data = [
                {
                    "phase": f.phase.value,
                    "rule": f.rule,
                    "severity": f.severity.value,
                    "file": f.file,
                    "line": f.line,
                    "snippet": f.snippet,
                    "description": f.description,
                    "weight": f.weight,
                }
                for f in static_findings
            ]

            # Build analysis request
            analysis_request = LLMAnalysisRequest(
                file_contents=file_contents,
                static_findings=static_findings_data,
                repository_context=repository_context or {},
                target_type="directory",
                analysis_types=[
                    LLMAnalysisType.ZERO_DAY_DETECTION,
                    LLMAnalysisType.OBFUSCATION_ANALYSIS,
                    LLMAnalysisType.BEHAVIORAL_PATTERN,
                    LLMAnalysisType.SUPPLY_CHAIN_RISK,
                    LLMAnalysisType.AI_ATTACK_VECTOR,
                    LLMAnalysisType.CONTEXTUAL_CORRELATION,
                ],
                max_insights=20,  # Pro tier can get more insights
                include_context_analysis=True,
            )

            # Perform LLM analysis
            logger.info(f"Starting LLM analysis on {len(file_contents)} files")
            analysis_response = await llm_service.analyze_threat(analysis_request)

            if not analysis_response.success:
                logger.warning(
                    f"LLM analysis failed: {analysis_response.error_message}"
                )
                if analysis_response.fallback_used:
                    return []  # Return empty list for fallback
                else:
                    raise Exception(analysis_response.error_message)

            # Convert LLM insights to Finding objects
            llm_findings = self._convert_insights_to_findings(analysis_response)

            logger.info(
                f"LLM analysis completed: {len(llm_findings)} insights, "
                f"{analysis_response.tokens_used} tokens, "
                f"{analysis_response.processing_time_ms}ms"
            )

            return llm_findings

        except Exception as e:
            logger.exception(f"Phase 9 LLM detection failed: {e}")
            # Don't fail the entire scan if LLM fails
            return []

    def _convert_insights_to_findings(self, analysis_response) -> list[Finding]:
        """Convert LLM insights to Sigil Finding objects."""
        findings = []

        for insight in analysis_response.insights:
            # Map LLM threat category to severity
            severity = self._map_threat_to_severity(
                insight.threat_category, insight.confidence
            )

            # Calculate weight based on confidence and severity
            base_weight = 3.0  # LLM findings get higher base weight than static
            confidence_multiplier = max(0.5, insight.confidence)  # 0.5-1.0 range
            weight = base_weight * confidence_multiplier

            # Apply severity adjustment from LLM
            weight += insight.severity_adjustment

            # Reduce weight if high false positive likelihood
            if insight.false_positive_likelihood > 0.5:
                weight *= 1.0 - insight.false_positive_likelihood

            # Build evidence snippet from multiple sources
            evidence_parts = []
            if insight.evidence_snippets:
                evidence_parts.extend(insight.evidence_snippets[:3])  # Max 3 snippets

            evidence = (
                "\n---\n".join(evidence_parts) if evidence_parts else insight.title
            )

            # Determine primary affected file
            primary_file = (
                insight.affected_files[0] if insight.affected_files else "<multiple>"
            )

            # Build comprehensive description
            description_parts = [insight.description]
            if insight.reasoning:
                description_parts.append(f"AI Reasoning: {insight.reasoning}")
            if insight.remediation_suggestions:
                suggestions = "; ".join(insight.remediation_suggestions[:2])
                description_parts.append(f"Suggested fixes: {suggestions}")

            full_description = " | ".join(description_parts)

            finding = Finding(
                phase=ScanPhase.LLM_ANALYSIS,
                rule=f"llm-{insight.analysis_type.value}-{insight.threat_category.value}",
                severity=severity,
                file=primary_file,
                line=0,  # LLM doesn't always provide line numbers
                snippet=evidence[:500],  # Truncate for storage
                weight=round(weight, 2),
                description=full_description[:500],  # Truncate for storage
                explanation=self._build_llm_explanation(insight),
            )

            findings.append(finding)

        return findings

    def _map_threat_to_severity(
        self, threat_category: LLMThreatCategory, confidence: float
    ) -> Severity:
        """Map LLM threat category and confidence to Sigil severity."""

        # Critical threats
        critical_threats = {
            LLMThreatCategory.SUPPLY_CHAIN_ATTACK,
            LLMThreatCategory.BACKDOOR,
            LLMThreatCategory.PRIVILEGE_ESCALATION,
        }

        # High severity threats
        high_threats = {
            LLMThreatCategory.CODE_INJECTION,
            LLMThreatCategory.DATA_EXFILTRATION,
            LLMThreatCategory.CREDENTIAL_THEFT,
            LLMThreatCategory.OBFUSCATED_MALWARE,
            LLMThreatCategory.TIME_BOMB,
        }

        # Medium severity threats
        medium_threats = {
            LLMThreatCategory.PROMPT_INJECTION,
            LLMThreatCategory.UNKNOWN_PATTERN,
        }

        # Base severity from threat type
        if threat_category in critical_threats:
            base_severity = Severity.CRITICAL
        elif threat_category in high_threats:
            base_severity = Severity.HIGH
        elif threat_category in medium_threats:
            base_severity = Severity.MEDIUM
        else:
            base_severity = Severity.LOW

        # Adjust based on confidence
        if confidence < 0.3:
            # Low confidence downgrades severity
            if base_severity == Severity.CRITICAL:
                return Severity.HIGH
            elif base_severity == Severity.HIGH:
                return Severity.MEDIUM
            elif base_severity == Severity.MEDIUM:
                return Severity.LOW
            else:
                return Severity.LOW
        elif confidence > 0.8 and base_severity != Severity.CRITICAL:
            # High confidence upgrades non-critical findings
            if base_severity == Severity.HIGH:
                return Severity.CRITICAL
            elif base_severity == Severity.MEDIUM:
                return Severity.HIGH
            elif base_severity == Severity.LOW:
                return Severity.MEDIUM

        return base_severity

    def _build_llm_explanation(self, insight) -> str:
        """Build detailed explanation for LLM finding."""
        parts = [
            f"AI-Powered Analysis ({insight.analysis_type.value})",
            f"Confidence: {insight.confidence:.1%} ({insight.confidence_level.value})",
            f"Threat Type: {insight.threat_category.value.replace('_', ' ').title()}",
        ]

        if insight.reasoning:
            parts.append(f"Detection Logic: {insight.reasoning}")

        if insight.mitigation_steps:
            steps = "; ".join(insight.mitigation_steps[:3])
            parts.append(f"Immediate Actions: {steps}")

        if insight.false_positive_likelihood > 0.3:
            parts.append(
                f"⚠️ False Positive Risk: {insight.false_positive_likelihood:.1%}"
            )

        return " | ".join(parts)


# Global detector instance
phase9_detector = Phase9LLMDetector()
