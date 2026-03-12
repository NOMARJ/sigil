"""
Attack Chain Tracer Service
Analyzes how vulnerabilities can be exploited end-to-end through code flow analysis
"""

from __future__ import annotations

import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum

from api.database import db
from api.services.credit_service import credit_service
from api.services.llm_service import llm_service
from api.llm_models import LLMAnalysisRequest, LLMAnalysisType
from api.models import Finding, Severity

logger = logging.getLogger(__name__)


class ExploitStage(str, Enum):
    """Stages of an attack chain"""
    ENTRY_POINT = "entry_point"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackStep:
    """A single step in an attack chain"""
    stage: ExploitStage
    description: str
    code_location: Optional[str]
    technique: str
    mitre_att_ck: Optional[str]
    risk_level: str
    mitigation: Optional[str]


@dataclass
class AttackChain:
    """Complete attack chain analysis"""
    finding_id: str
    vulnerability_type: str
    entry_points: List[str]
    attack_steps: List[AttackStep]
    total_risk_score: float
    blast_radius: Dict[str, Any]
    affected_systems: List[str]
    data_at_risk: List[str]
    mitigation_points: List[Dict[str, str]]
    kill_chain_disruption: Dict[str, str]
    visualization_data: Dict[str, Any]


class AttackChainTracer:
    """Traces complete attack chains from vulnerabilities"""

    async def trace_attack_chain(
        self,
        finding: Finding,
        scan_id: str,
        user_id: str,
        context_files: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,
    ) -> AttackChain:
        """
        Trace the complete attack chain for a vulnerability.
        
        Args:
            finding: The vulnerability finding to analyze
            scan_id: Associated scan ID
            user_id: User requesting the analysis
            context_files: Additional code files for context
            session_id: Optional interactive session ID
            
        Returns:
            Complete attack chain analysis
        """
        # Check and deduct credits (8 credits for attack chain analysis)
        credit_cost = 8
        if not await credit_service.has_credits(user_id, credit_cost):
            raise ValueError(f"Insufficient credits. Need {credit_cost} credits for attack chain analysis.")
            
        await credit_service.deduct_credits(
            user_id=user_id,
            amount=credit_cost,
            transaction_type="attack_chain",
            scan_id=scan_id,
            session_id=session_id,
            model_used="claude-3-sonnet-20240229",
            metadata={"finding_id": finding.id if hasattr(finding, 'id') else None}
        )
        
        try:
            # Build attack chain prompt
            prompt = self._build_attack_chain_prompt(finding, context_files)
            
            # Get LLM analysis using Sonnet for complex reasoning
            analysis_request = LLMAnalysisRequest(
                file_contents=context_files or {},
                static_findings=[self._finding_to_dict(finding)],
                repository_context={"scan_id": scan_id},
                analysis_types=[LLMAnalysisType.BEHAVIORAL_PATTERN],
                max_insights=10,
                include_context_analysis=True
            )
            
            # Custom prompt for attack chain analysis
            analysis_request.custom_prompt = prompt
            
            response = await llm_service.analyze_threat(analysis_request)
            
            # Parse response into attack chain structure
            attack_chain = self._parse_attack_chain_response(
                finding=finding,
                llm_response=response
            )
            
            # Store in database if session exists
            if session_id:
                await self._store_attack_chain_analysis(
                    session_id=session_id,
                    attack_chain=attack_chain
                )
            
            logger.info(
                f"Attack chain traced for finding {finding.rule}: "
                f"{len(attack_chain.attack_steps)} steps identified"
            )
            
            return attack_chain
            
        except Exception as e:
            logger.exception(f"Failed to trace attack chain: {e}")
            # Return minimal chain on error
            return self._create_fallback_chain(finding)

    def _build_attack_chain_prompt(
        self,
        finding: Finding,
        context_files: Optional[Dict[str, str]] = None
    ) -> str:
        """Build prompt for attack chain analysis"""
        
        context = ""
        if context_files:
            context = "\n\nAdditional Context Files:\n"
            for filename, content in list(context_files.items())[:5]:  # Limit to 5 files
                context += f"\n--- {filename} ---\n{content[:2000]}\n"  # Limit content
        
        return f"""Analyze the complete attack chain for this vulnerability:

Vulnerability: {finding.rule}
Severity: {finding.severity.value}
File: {finding.file}
Line: {finding.line}
Code: {finding.snippet}
Description: {finding.description}
{context}

Provide a detailed attack chain analysis including:

1. **Entry Points**: How can an attacker reach this vulnerability?
2. **Attack Steps**: Step-by-step exploitation process following MITRE ATT&CK framework
3. **Execution Flow**: How the attack progresses through the code
4. **Persistence**: Can the attacker maintain access?
5. **Privilege Escalation**: Can privileges be elevated?
6. **Data Access**: What data can be accessed or exfiltrated?
7. **Lateral Movement**: Can the attack spread to other systems?
8. **Impact Assessment**: What's the worst-case scenario?
9. **Blast Radius**: Which systems and data are affected?
10. **Kill Chain Disruption**: Where can we break the attack chain?

Format the response as a structured attack chain with clear stages and mitigations.
Include MITRE ATT&CK technique IDs where applicable."""

    def _parse_attack_chain_response(
        self,
        finding: Finding,
        llm_response: Any
    ) -> AttackChain:
        """Parse LLM response into AttackChain structure"""
        
        # Extract insights from LLM response
        attack_steps = []
        entry_points = []
        mitigations = []
        affected_systems = []
        data_at_risk = []
        
        if llm_response.insights:
            for insight in llm_response.insights:
                # Map insights to attack steps
                step = AttackStep(
                    stage=self._determine_stage(insight.title),
                    description=insight.description,
                    code_location=insight.affected_files[0] if insight.affected_files else None,
                    technique=insight.title,
                    mitre_att_ck=self._extract_mitre_id(insight.description),
                    risk_level=self._map_confidence_to_risk(insight.confidence),
                    mitigation=insight.remediation_suggestions[0] if insight.remediation_suggestions else None
                )
                attack_steps.append(step)
                
                # Extract entry points
                if "entry" in insight.title.lower() or "input" in insight.description.lower():
                    entry_points.extend(insight.affected_files)
                
                # Extract mitigations
                for remediation in insight.remediation_suggestions:
                    mitigations.append({
                        "stage": step.stage.value,
                        "mitigation": remediation
                    })
                
                # Extract affected systems from context
                if insight.evidence_snippets:
                    for evidence in insight.evidence_snippets:
                        if "database" in evidence.lower():
                            data_at_risk.append("Database records")
                        if "api" in evidence.lower():
                            affected_systems.append("API endpoints")
                        if "file" in evidence.lower():
                            data_at_risk.append("File system")
        
        # Calculate total risk score
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5
        }
        base_score = severity_scores.get(finding.severity, 5.0)
        chain_multiplier = min(len(attack_steps) * 0.5, 3.0)  # More steps = higher risk
        total_risk_score = base_score * chain_multiplier
        
        # Build visualization data for frontend
        visualization_data = self._build_visualization_data(attack_steps, entry_points)
        
        # Determine kill chain disruption points
        kill_chain_disruption = {}
        for i, step in enumerate(attack_steps):
            if step.mitigation:
                kill_chain_disruption[f"Step {i+1}: {step.stage.value}"] = step.mitigation
        
        return AttackChain(
            finding_id=finding.id if hasattr(finding, 'id') else finding.rule,
            vulnerability_type=finding.rule,
            entry_points=entry_points or [finding.file],
            attack_steps=attack_steps,
            total_risk_score=round(total_risk_score, 2),
            blast_radius={
                "files_affected": len(set(s.code_location for s in attack_steps if s.code_location)),
                "systems_affected": len(affected_systems),
                "data_categories": len(data_at_risk),
                "maximum_impact": self._determine_maximum_impact(attack_steps)
            },
            affected_systems=affected_systems or ["Application"],
            data_at_risk=data_at_risk or ["Application data"],
            mitigation_points=mitigations,
            kill_chain_disruption=kill_chain_disruption,
            visualization_data=visualization_data
        )

    def _determine_stage(self, title: str) -> ExploitStage:
        """Map insight title to exploit stage"""
        title_lower = title.lower()
        
        if "entry" in title_lower or "input" in title_lower:
            return ExploitStage.ENTRY_POINT
        elif "initial" in title_lower or "access" in title_lower:
            return ExploitStage.INITIAL_ACCESS
        elif "exec" in title_lower or "run" in title_lower:
            return ExploitStage.EXECUTION
        elif "persist" in title_lower:
            return ExploitStage.PERSISTENCE
        elif "privilege" in title_lower or "escalat" in title_lower:
            return ExploitStage.PRIVILEGE_ESCALATION
        elif "evad" in title_lower or "bypass" in title_lower:
            return ExploitStage.DEFENSE_EVASION
        elif "credential" in title_lower or "password" in title_lower:
            return ExploitStage.CREDENTIAL_ACCESS
        elif "discover" in title_lower or "recon" in title_lower:
            return ExploitStage.DISCOVERY
        elif "lateral" in title_lower or "spread" in title_lower:
            return ExploitStage.LATERAL_MOVEMENT
        elif "collect" in title_lower or "gather" in title_lower:
            return ExploitStage.COLLECTION
        elif "exfil" in title_lower or "leak" in title_lower:
            return ExploitStage.EXFILTRATION
        else:
            return ExploitStage.IMPACT

    def _extract_mitre_id(self, description: str) -> Optional[str]:
        """Extract MITRE ATT&CK technique ID from description"""
        import re
        
        # Look for patterns like T1234 or T1234.001
        pattern = r'T\d{4}(?:\.\d{3})?'
        match = re.search(pattern, description)
        return match.group(0) if match else None

    def _map_confidence_to_risk(self, confidence: float) -> str:
        """Map confidence score to risk level"""
        if confidence >= 0.8:
            return "CRITICAL"
        elif confidence >= 0.6:
            return "HIGH"
        elif confidence >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def _determine_maximum_impact(self, attack_steps: List[AttackStep]) -> str:
        """Determine the maximum potential impact"""
        critical_stages = {
            ExploitStage.EXFILTRATION,
            ExploitStage.IMPACT,
            ExploitStage.CREDENTIAL_ACCESS,
            ExploitStage.PRIVILEGE_ESCALATION
        }
        
        for step in attack_steps:
            if step.stage in critical_stages:
                if step.stage == ExploitStage.EXFILTRATION:
                    return "Complete data breach"
                elif step.stage == ExploitStage.IMPACT:
                    return "System compromise"
                elif step.stage == ExploitStage.CREDENTIAL_ACCESS:
                    return "Account takeover"
                elif step.stage == ExploitStage.PRIVILEGE_ESCALATION:
                    return "Admin access"
        
        return "Limited impact"

    def _build_visualization_data(
        self,
        attack_steps: List[AttackStep],
        entry_points: List[str]
    ) -> Dict[str, Any]:
        """Build data structure for frontend visualization"""
        
        # Create nodes for each stage
        nodes = []
        for i, step in enumerate(attack_steps):
            nodes.append({
                "id": f"step_{i}",
                "label": step.stage.value.replace("_", " ").title(),
                "description": step.description,
                "risk": step.risk_level,
                "mitre": step.mitre_att_ck,
                "type": "attack_step"
            })
        
        # Add entry point nodes
        for i, entry in enumerate(entry_points):
            nodes.insert(0, {
                "id": f"entry_{i}",
                "label": f"Entry: {entry}",
                "type": "entry_point"
            })
        
        # Create edges between nodes
        edges = []
        for i in range(len(nodes) - 1):
            edges.append({
                "source": nodes[i]["id"],
                "target": nodes[i + 1]["id"],
                "label": f"Step {i + 1}"
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "layout": "hierarchical"  # Suggested layout for visualization
        }

    def _finding_to_dict(self, finding: Finding) -> Dict:
        """Convert Finding to dict for LLM context"""
        return {
            "phase": finding.phase.value if finding.phase else "unknown",
            "rule": finding.rule,
            "severity": finding.severity.value,
            "file": finding.file,
            "line": finding.line,
            "snippet": finding.snippet,
            "description": finding.description,
            "weight": finding.weight
        }

    def _create_fallback_chain(self, finding: Finding) -> AttackChain:
        """Create a minimal attack chain when analysis fails"""
        return AttackChain(
            finding_id=finding.id if hasattr(finding, 'id') else finding.rule,
            vulnerability_type=finding.rule,
            entry_points=[finding.file],
            attack_steps=[
                AttackStep(
                    stage=ExploitStage.ENTRY_POINT,
                    description=f"Potential entry via {finding.file}",
                    code_location=finding.file,
                    technique=finding.rule,
                    mitre_att_ck=None,
                    risk_level="UNKNOWN",
                    mitigation="Unable to analyze - manual review required"
                )
            ],
            total_risk_score=5.0,
            blast_radius={"files_affected": 1, "systems_affected": 1, "data_categories": 0, "maximum_impact": "Unknown"},
            affected_systems=["Unknown"],
            data_at_risk=["Unknown"],
            mitigation_points=[],
            kill_chain_disruption={},
            visualization_data={"nodes": [], "edges": [], "layout": "hierarchical"}
        )

    async def _store_attack_chain_analysis(
        self,
        session_id: str,
        attack_chain: AttackChain
    ) -> None:
        """Store attack chain analysis in session"""
        try:
            # Convert attack chain to JSON for storage
            import json
            
            analysis_data = {
                "type": "attack_chain",
                "finding_id": attack_chain.finding_id,
                "vulnerability_type": attack_chain.vulnerability_type,
                "entry_points": attack_chain.entry_points,
                "attack_steps": [
                    {
                        "stage": step.stage.value,
                        "description": step.description,
                        "code_location": step.code_location,
                        "technique": step.technique,
                        "mitre": step.mitre_att_ck,
                        "risk": step.risk_level,
                        "mitigation": step.mitigation
                    }
                    for step in attack_chain.attack_steps
                ],
                "total_risk_score": attack_chain.total_risk_score,
                "blast_radius": attack_chain.blast_radius,
                "affected_systems": attack_chain.affected_systems,
                "data_at_risk": attack_chain.data_at_risk,
                "mitigation_points": attack_chain.mitigation_points,
                "kill_chain_disruption": attack_chain.kill_chain_disruption,
                "visualization_data": attack_chain.visualization_data
            }
            
            # Update session with attack chain analysis
            await db.execute(
                """
                UPDATE interactive_sessions
                SET conversation_history = JSON_MODIFY(
                    ISNULL(conversation_history, '[]'),
                    'append $',
                    :analysis
                ),
                last_activity = GETDATE()
                WHERE session_id = :session_id
                """,
                {
                    "session_id": session_id,
                    "analysis": json.dumps(analysis_data)
                }
            )
            
        except Exception as e:
            logger.warning(f"Failed to store attack chain analysis: {e}")


# Global service instance
attack_chain_tracer = AttackChainTracer()