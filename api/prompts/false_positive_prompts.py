"""
Prompt templates for false positive analysis.
These prompts help the LLM determine if a security finding is likely a false positive.
"""

from typing import Dict, List, Optional


class FalsePositivePrompts:
    """Collection of prompts for false positive analysis."""

    @staticmethod
    def build_false_positive_analysis_prompt(
        finding_data: Dict,
        code_context: str,
        data_flow_info: Optional[str] = None,
        surrounding_functions: Optional[List[str]] = None,
    ) -> str:
        """
        Build a comprehensive prompt for false positive analysis.

        Args:
            finding_data: Details of the security finding
            code_context: Surrounding code context
            data_flow_info: Information about data flow and inputs
            surrounding_functions: List of surrounding function definitions

        Returns:
            Formatted prompt for LLM analysis
        """

        prompt = f"""
You are an expert security analyst specializing in false positive detection. Your task is to analyze a security finding and determine if it's likely a false positive based on the specific context and usage patterns.

SECURITY FINDING TO ANALYZE:
- Pattern: {finding_data.get("pattern_id", "Unknown")}
- Phase: {finding_data.get("phase", "Unknown")}
- Severity: {finding_data.get("severity", "Unknown")}
- Message: {finding_data.get("message", "No message")}
- File: {finding_data.get("file_path", "Unknown")}
- Line: {finding_data.get("line_number", "Unknown")}

FLAGGED CODE:
```{finding_data.get("file_extension", "")}
{code_context}
```
"""

        if data_flow_info:
            prompt += f"""
DATA FLOW ANALYSIS:
{data_flow_info}
"""

        if surrounding_functions:
            prompt += f"""
SURROUNDING FUNCTIONS:
{chr(10).join(surrounding_functions)}
"""

        prompt += """
ANALYSIS REQUIREMENTS:

1. CONTEXT EVALUATION:
   - Is this code in a test file, configuration parser, or development utility?
   - Is the potentially dangerous operation safely contained or sandboxed?
   - Are there appropriate input validation and sanitization measures?
   - Is the code only processing trusted/internal data?

2. USAGE PATTERN ANALYSIS:
   - Is this a legitimate use case (e.g., eval() in a config parser)?
   - Are there defensive measures in place?
   - Is the scope of the operation limited and controlled?
   - Are there clear security boundaries?

3. DEFENSE-IN-DEPTH ASSESSMENT:
   - Even if this specific finding is safe, are there additional security measures that could improve defense?
   - What would make this code more secure without breaking functionality?

Provide your analysis as JSON:

{{
    "is_false_positive": boolean,
    "confidence_percentage": integer (0-100),
    "reasoning": "detailed explanation of your assessment",
    "context_factors": [
        "factor 1: why this supports/refutes false positive",
        "factor 2: additional contextual evidence"
    ],
    "risk_factors": [
        "any remaining risk factors even if false positive",
        "potential edge cases or attack vectors"
    ],
    "defense_recommendations": [
        "improvement 1: how to make this more secure",
        "improvement 2: additional defensive measures"
    ],
    "true_positive_scenarios": [
        "scenario where this could be exploited",
        "edge case that might make this dangerous"
    ],
    "verdict_summary": "one sentence summary of your conclusion"
}}

IMPORTANT GUIDELINES:
- Be extremely thorough in your analysis
- Consider both obvious and subtle security implications  
- Even for false positives, suggest defense-in-depth improvements
- Err on the side of caution - prefer false positives over missing real threats
- Consider the full application context, not just the isolated code snippet
- Look for patterns that indicate intentional security measures vs oversight
"""

        return prompt

    @staticmethod
    def build_data_flow_analysis_prompt(
        finding_data: Dict,
        code_context: str,
        input_sources: Optional[List[str]] = None,
    ) -> str:
        """
        Build a prompt specifically for analyzing data flow to the flagged code.

        Args:
            finding_data: Details of the security finding
            code_context: Code context around the finding
            input_sources: Known input sources to the vulnerable function

        Returns:
            Formatted prompt for data flow analysis
        """

        prompt = f"""
Analyze the data flow leading to this potentially vulnerable code to determine if user-controlled input can reach it.

FINDING DETAILS:
- Type: {finding_data.get("pattern_id", "Unknown")}
- File: {finding_data.get("file_path", "Unknown")}
- Function/Context: {finding_data.get("message", "Unknown")}

CODE CONTEXT:
```{finding_data.get("file_extension", "")}
{code_context}
```
"""

        if input_sources:
            prompt += f"""
IDENTIFIED INPUT SOURCES:
{chr(10).join(f"- {source}" for source in input_sources)}
"""

        prompt += """
TRACE THE DATA FLOW:

1. IDENTIFY INPUTS:
   - Where does data come from? (user input, files, network, environment variables)
   - Is it from trusted sources only?
   - Are there any user-controllable parameters?

2. TRACE TRANSFORMATIONS:
   - How is the data processed before reaching the vulnerable code?
   - Are there validation, sanitization, or encoding steps?
   - Is the data filtered or restricted in any way?

3. ASSESS CONTROL:
   - Can an attacker influence what reaches the vulnerable function?
   - Are there any bypass opportunities in the validation?
   - Is the input scope limited (e.g., only predefined values)?

Respond with JSON:

{
    "user_controlled_input_possible": boolean,
    "input_sources": [
        {"source": "description", "controllable": boolean, "path": "how it reaches target"}
    ],
    "validation_present": boolean,
    "validation_methods": ["method 1", "method 2"],
    "bypass_opportunities": ["potential bypass 1", "potential bypass 2"],
    "data_flow_summary": "concise description of the complete data flow",
    "exploitability_assessment": "none|low|medium|high - based on data flow analysis"
}
"""

        return prompt

    @staticmethod
    def build_context_classification_prompt(
        file_path: str,
        code_sample: str,
        file_purpose: Optional[str] = None,
    ) -> str:
        """
        Build a prompt to classify the context and purpose of code.

        Args:
            file_path: Path to the file containing the code
            code_sample: Sample of code from the file
            file_purpose: Optional description of file purpose

        Returns:
            Formatted prompt for context classification
        """

        prompt = f"""
Classify the context and intended purpose of this code to help assess security finding severity.

FILE PATH: {file_path}
"""

        if file_purpose:
            prompt += f"STATED PURPOSE: {file_purpose}\n"

        prompt += f"""
CODE SAMPLE:
```
{code_sample}
```

CLASSIFICATION CRITERIA:

1. FILE TYPE ANALYSIS:
   - Is this a test file? (look for test patterns, fixtures, mocks)
   - Is this a configuration parser or setup script?
   - Is this production code vs development utilities?
   - Is this part of a security-sensitive module?

2. EXECUTION CONTEXT:
   - When/how is this code executed?
   - Is it run during build time, runtime, or testing?
   - Who or what triggers this code execution?
   - Is it user-facing or internal-only?

3. SECURITY CONTEXT:
   - Is this code handling sensitive data?
   - Is it part of the attack surface?
   - Are there existing security controls around it?
   - What are the blast radius implications?

Respond with JSON:

{{
    "file_classification": "test|config|production|utility|build_script|other",
    "security_sensitivity": "none|low|medium|high|critical",
    "execution_context": "build_time|test_time|runtime|admin_only|user_facing",
    "likely_purpose": "detailed description of what this code does",
    "security_implications": "how this classification affects security assessment",
    "false_positive_indicators": ["indicator 1", "indicator 2"],
    "legitimate_use_case": boolean,
    "recommended_treatment": "suppress|review|investigate|prioritize"
}}
"""

        return prompt

    @staticmethod
    def build_comparative_analysis_prompt(
        finding_data: Dict,
        similar_findings: List[Dict],
        known_false_positives: Optional[List[Dict]] = None,
    ) -> str:
        """
        Build a prompt for comparative analysis against similar findings.

        Args:
            finding_data: The current finding to analyze
            similar_findings: List of similar findings for comparison
            known_false_positives: Known false positives for pattern learning

        Returns:
            Formatted prompt for comparative analysis
        """

        prompt = f"""
Compare this security finding against similar findings to assess false positive likelihood using pattern analysis.

CURRENT FINDING:
- Pattern: {finding_data.get("pattern_id", "Unknown")}
- File: {finding_data.get("file_path", "Unknown")}
- Context: {finding_data.get("message", "Unknown")}
- Code: {finding_data.get("code_snippet", "No code available")}

SIMILAR FINDINGS FOR COMPARISON:
"""

        for i, similar in enumerate(similar_findings[:5], 1):
            prompt += f"""
Finding #{i}:
- Pattern: {similar.get("pattern_id", "Unknown")}
- File: {similar.get("file_path", "Unknown")}
- Code: {similar.get("code_snippet", "Unknown")}
- Status: {similar.get("status", "Unknown")}
"""

        if known_false_positives:
            prompt += "\nKNOWN FALSE POSITIVES:\n"
            for i, fp in enumerate(known_false_positives[:3], 1):
                prompt += f"""
False Positive #{i}:
- Reason: {fp.get("false_positive_reason", "Unknown")}
- Pattern: {fp.get("pattern_id", "Unknown")}
- Code: {fp.get("code_snippet", "Unknown")}
"""

        prompt += """
COMPARATIVE ANALYSIS:

1. PATTERN MATCHING:
   - Does the current finding match patterns of known false positives?
   - Are there common characteristics with legitimate use cases?
   - How does it differ from confirmed true positives?

2. CONTEXTUAL SIMILARITY:
   - Are similar findings in similar file types or contexts?
   - Do similar findings share common frameworks or libraries?
   - Are there patterns in how this code pattern is typically used?

3. HISTORICAL TRENDS:
   - What has been the false positive rate for this pattern type?
   - Are there evolutionary changes in how this pattern appears?
   - What factors distinguish true vs false positives historically?

Respond with JSON:

{
    "similarity_score": float (0.0-1.0),
    "false_positive_likelihood": float (0.0-1.0),
    "pattern_confidence": "low|medium|high",
    "similar_finding_analysis": [
        {
            "finding_index": int,
            "similarity_factors": ["factor 1", "factor 2"],
            "key_differences": ["difference 1", "difference 2"]
        }
    ],
    "historical_pattern_match": boolean,
    "risk_differentiation": "what makes this different from confirmed true positives",
    "recommendation": "suppress|review|investigate|escalate",
    "confidence_factors": ["factor that increases confidence", "factor that decreases confidence"]
}
"""

        return prompt
