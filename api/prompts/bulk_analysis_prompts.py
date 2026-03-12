"""
Bulk Analysis Prompt Builder
Constructs prompts for batch security finding analysis
"""

from typing import List, Dict, Any
from ..models import Finding


class BulkAnalysisPromptBuilder:
    """Builds prompts for bulk finding analysis"""

    def build_bulk_analysis_prompt(
        self,
        pattern_type: str,
        findings: List[Finding],
        common_characteristics: Dict[str, Any],
        depth: str = "thorough",
    ) -> str:
        """Build prompt for bulk analysis of similar findings"""

        prompt = f"""Analyze this group of {len(findings)} similar {pattern_type} security findings.

PATTERN TYPE: {pattern_type}
ANALYSIS DEPTH: {depth}
TOTAL FINDINGS: {len(findings)}

COMMON CHARACTERISTICS:
- Common Functions: {", ".join(common_characteristics.get("common_functions", ["None identified"]))}
- Common Variables: {", ".join(common_characteristics.get("common_variables", ["None identified"]))}
- Code Similarity: {common_characteristics.get("code_similarity", 0):.0%}
- File Proximity: {"Yes" if common_characteristics.get("file_proximity") else "No"}

FINDINGS DETAIL:
"""

        # Add findings (limit to prevent token overflow)
        max_findings = 10 if depth == "exhaustive" else 5
        for i, finding in enumerate(findings[:max_findings], 1):
            prompt += f"""
Finding {i}:
- File: {finding.file_path}:{finding.line_number}
- Severity: {finding.severity}
- Rule: {finding.rule}
- Description: {finding.description}
- Evidence: {finding.evidence[:200] if finding.evidence else "N/A"}
"""

        if len(findings) > max_findings:
            prompt += (
                f"\n... and {len(findings) - max_findings} more similar findings\n"
            )

        # Add analysis instructions based on depth
        if depth == "quick":
            prompt += """
QUICK ANALYSIS REQUIRED:
1. Are these likely the same root cause? (Yes/No with confidence %)
2. What is the common vulnerability pattern?
3. Can a single fix address all instances?
4. Estimated severity if exploited together?
"""
        elif depth == "thorough":
            prompt += """
THOROUGH ANALYSIS REQUIRED:
1. Root Cause Analysis:
   - Are these the same vulnerability? (confidence %)
   - What is the underlying security flaw?
   - Why does this pattern appear multiple times?

2. Exploit Scenario:
   - Can these be chained together?
   - What is the combined attack surface?
   - What is the worst-case impact?

3. Remediation Strategy:
   - Can a single fix address all instances?
   - What is the recommended fix approach?
   - What is the priority for fixing these?

4. False Positive Assessment:
   - Any likely false positives in this group?
   - Confidence in the findings?
"""
        else:  # exhaustive
            prompt += """
EXHAUSTIVE ANALYSIS REQUIRED:
1. Detailed Root Cause Analysis:
   - Exact vulnerability pattern and why it exists
   - Code flow analysis showing how it manifests
   - Development practices that led to this pattern

2. Complete Exploit Chain:
   - Step-by-step exploitation path
   - Required attacker capabilities
   - Potential for automated exploitation
   - Impact on confidentiality, integrity, availability

3. Comprehensive Remediation Plan:
   - Specific code changes required
   - Testing approach to verify fixes
   - Prevention of future occurrences
   - Architectural improvements needed

4. Risk Assessment:
   - CVSS score estimation
   - Compliance implications
   - Business impact analysis
   - Timeline criticality

5. Pattern Recognition:
   - Similar vulnerabilities that might exist
   - Related security weaknesses to investigate
   - Systemic issues indicated by this pattern
"""

        prompt += """
Provide a structured analysis focusing on actionable insights for fixing these security issues efficiently.
"""

        return prompt

    def build_root_cause_prompt(
        self, findings: List[Finding], pattern_type: str
    ) -> str:
        """Build prompt specifically for root cause analysis"""

        return f"""Perform root cause analysis on {len(findings)} {pattern_type} findings.

Focus on identifying:
1. The single underlying cause (if any)
2. Why this vulnerability pattern repeats
3. The most efficient fix strategy
4. Whether these can be exploited together

Provide specific, actionable recommendations.
"""

    def build_remediation_prompt(
        self, findings: List[Finding], pattern_type: str, single_fix_possible: bool
    ) -> str:
        """Build prompt for generating bulk remediation"""

        if single_fix_possible:
            return f"""Generate a single remediation that fixes all {len(findings)} {pattern_type} vulnerabilities.

Requirements:
1. One solution that addresses all instances
2. Step-by-step implementation guide
3. Code examples in the appropriate language
4. Testing approach to verify the fix
5. Estimated implementation effort

Be specific and practical.
"""
        else:
            return f"""Generate an efficient remediation plan for {len(findings)} {pattern_type} vulnerabilities.

Since these require individual fixes:
1. Group similar fixes together
2. Provide templates or patterns to speed up fixing
3. Suggest automation approaches if possible
4. Priority order for fixing
5. Total estimated effort

Focus on efficiency and completeness.
"""
