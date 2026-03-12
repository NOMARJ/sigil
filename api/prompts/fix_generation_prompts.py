"""
Prompt templates for secure code fix generation.
These prompts help the LLM generate working code fixes for security vulnerabilities.
"""

from typing import Dict, List, Optional


class FixGenerationPrompts:
    """Collection of prompts for remediation code generation."""

    @staticmethod
    def build_remediation_prompt(
        finding_data: Dict,
        code_context: str,
        language: str,
        framework_info: Optional[Dict] = None,
        fix_preference: str = "secure",
    ) -> str:
        """
        Build a comprehensive prompt for generating secure code fixes.

        Args:
            finding_data: Details of the security finding
            code_context: Code context around the vulnerability
            language: Programming language (python, javascript, etc.)
            framework_info: Information about frameworks in use
            fix_preference: Type of fix to prioritize (secure, minimal, performance)

        Returns:
            Formatted prompt for LLM code generation
        """

        prompt = f"""
You are an expert security engineer tasked with generating a secure fix for a vulnerability. Generate working code that eliminates the security issue while maintaining functionality.

VULNERABILITY DETAILS:
- Type: {finding_data.get("pattern_id", "Unknown")}
- Phase: {finding_data.get("phase", "Unknown")}
- Severity: {finding_data.get("severity", "Unknown")}
- Message: {finding_data.get("message", "No message")}
- File: {finding_data.get("file_path", "Unknown")}
- Line: {finding_data.get("line_number", "Unknown")}

LANGUAGE: {language.upper()}
FIX PREFERENCE: {fix_preference}

VULNERABLE CODE:
```{language}
{code_context}
```
"""

        if framework_info:
            prompt += f"""
FRAMEWORK INFORMATION:
- Framework: {framework_info.get("name", "Unknown")}
- Version: {framework_info.get("version", "Unknown")}
- Security Libraries Available: {", ".join(framework_info.get("security_libs", []))}
"""

        prompt += f"""
REMEDIATION REQUIREMENTS:

1. SECURITY COMPLIANCE:
   - Eliminate the identified vulnerability completely
   - Follow OWASP secure coding practices
   - Use principle of least privilege
   - Implement defense in depth where applicable

2. CODE QUALITY:
   - Maintain existing functionality
   - Use idiomatic {language} patterns
   - Include proper error handling
   - Add appropriate comments explaining security measures

3. TESTING:
   - Provide unit test that verifies the fix
   - Include test case that demonstrates the vulnerability is patched
   - Test both positive and negative scenarios

Provide your response as JSON:

{{
    "primary_fix": {{
        "description": "Main recommended fix approach",
        "code": "complete fixed code with security measures",
        "explanation": "detailed explanation of how this fix works",
        "security_benefits": ["benefit 1", "benefit 2"],
        "potential_issues": ["any caveats or side effects"]
    }},
    "alternative_fixes": [
        {{
            "name": "alternative approach name",
            "description": "brief description of alternative",
            "code": "alternative implementation",
            "pros": ["advantage 1", "advantage 2"],
            "cons": ["disadvantage 1", "disadvantage 2"]
        }}
    ],
    "unit_test": {{
        "description": "test that verifies the fix",
        "code": "complete unit test code",
        "test_explanation": "what the test validates"
    }},
    "security_validation": {{
        "attack_prevention": "how this prevents the original attack",
        "additional_protections": ["extra security measures included"],
        "security_checklist": ["verification item 1", "verification item 2"]
    }},
    "implementation_notes": {{
        "breaking_changes": ["any breaking changes"],
        "dependencies_needed": ["new dependencies required"],
        "configuration_changes": ["config updates needed"],
        "migration_steps": ["steps to safely deploy this fix"]
    }},
    "before_after_comparison": {{
        "vulnerability_demo": "code that would exploit the original vulnerability",
        "fix_demonstration": "how the fix prevents the exploitation"
    }}
}}

IMPORTANT GUIDELINES:
- Generate WORKING, PRODUCTION-READY code
- Include all necessary imports and dependencies
- Use established security libraries and patterns for {language}
- Test the logical flow to ensure no syntax or logic errors
- Prefer well-established security solutions over custom implementations
- Include meaningful variable names and clear comments
- Consider edge cases and error conditions
- Ensure backward compatibility unless security requires breaking changes
"""

        # Add language-specific security guidance
        security_guidance = FixGenerationPrompts._get_language_security_guidance(
            language
        )
        if security_guidance:
            prompt += f"\n\nLANGUAGE-SPECIFIC SECURITY GUIDANCE:\n{security_guidance}"

        return prompt

    @staticmethod
    def build_validation_prompt(
        original_code: str,
        fixed_code: str,
        finding_type: str,
        language: str,
    ) -> str:
        """
        Build a prompt to validate that a fix properly addresses the vulnerability.

        Args:
            original_code: The vulnerable code
            fixed_code: The proposed fix
            finding_type: Type of vulnerability being fixed
            language: Programming language

        Returns:
            Formatted prompt for fix validation
        """

        prompt = f"""
Validate that this security fix properly addresses the vulnerability and doesn't introduce new issues.

VULNERABILITY TYPE: {finding_type}
LANGUAGE: {language}

ORIGINAL VULNERABLE CODE:
```{language}
{original_code}
```

PROPOSED FIX:
```{language}
{fixed_code}
```

VALIDATION REQUIREMENTS:

1. VULNERABILITY REMEDIATION:
   - Does the fix completely eliminate the original vulnerability?
   - Are there any ways the original attack vector could still work?
   - Has the root cause been addressed, not just the symptoms?

2. FUNCTIONALITY PRESERVATION:
   - Does the code maintain its original intended functionality?
   - Are all input/output behaviors preserved?
   - Are performance characteristics similar?

3. NEW VULNERABILITY ASSESSMENT:
   - Does the fix introduce any new security vulnerabilities?
   - Are there any injection points or unsafe operations?
   - Is error handling secure and doesn't leak sensitive information?

4. CODE QUALITY:
   - Is the code syntactically correct and runnable?
   - Are best practices followed for {language}?
   - Is the security approach appropriate for the context?

Respond with JSON:

{{
    "vulnerability_fixed": boolean,
    "functionality_preserved": boolean,
    "introduces_new_vulnerabilities": boolean,
    "syntax_correct": boolean,
    "security_score": integer (1-10),
    "validation_details": {{
        "original_attack_blocked": "how the original attack is now prevented",
        "remaining_vulnerabilities": ["any vulnerabilities that remain"],
        "new_vulnerabilities": ["any new vulnerabilities introduced"],
        "functionality_changes": ["any changes to expected behavior"]
    }},
    "improvement_suggestions": [
        "suggestion 1 for making the fix even better",
        "suggestion 2 for additional security"
    ],
    "approval_recommendation": "approve|approve_with_changes|reject",
    "rejection_reasons": ["reason 1", "reason 2"] // if rejected
}}
"""

        return prompt

    @staticmethod
    def build_test_generation_prompt(
        fixed_code: str,
        vulnerability_type: str,
        language: str,
        test_framework: Optional[str] = None,
    ) -> str:
        """
        Build a prompt to generate comprehensive tests for the security fix.

        Args:
            fixed_code: The secure code implementation
            vulnerability_type: Type of vulnerability that was fixed
            language: Programming language
            test_framework: Testing framework to use (pytest, jest, etc.)

        Returns:
            Formatted prompt for test generation
        """

        framework_guidance = FixGenerationPrompts._get_test_framework_guidance(
            language, test_framework
        )

        prompt = f"""
Generate comprehensive security tests for this fixed code to ensure the vulnerability is properly remediated.

VULNERABILITY TYPE: {vulnerability_type}
LANGUAGE: {language}
{f"TEST FRAMEWORK: {test_framework}" if test_framework else ""}

FIXED CODE TO TEST:
```{language}
{fixed_code}
```

{framework_guidance}

TEST REQUIREMENTS:

1. SECURITY TESTS:
   - Test that confirms the original vulnerability is fixed
   - Test malicious inputs that should be rejected/sanitized
   - Test edge cases that might bypass security measures
   - Test that security boundaries are enforced

2. FUNCTIONAL TESTS:
   - Test normal operation with valid inputs
   - Test error handling with invalid inputs
   - Test all code paths and branches
   - Test integration with surrounding code

3. REGRESSION TESTS:
   - Test that existing functionality still works
   - Test performance hasn't degraded significantly
   - Test that no new bugs were introduced

Respond with JSON:

{{
    "security_tests": [
        {{
            "test_name": "descriptive test name",
            "purpose": "what this test validates",
            "code": "complete test code",
            "expected_outcome": "what should happen when test runs"
        }}
    ],
    "functional_tests": [
        {{
            "test_name": "test name",
            "purpose": "test purpose",
            "code": "test code",
            "expected_outcome": "expected result"
        }}
    ],
    "test_data": {{
        "malicious_inputs": ["malicious input 1", "malicious input 2"],
        "valid_inputs": ["valid input 1", "valid input 2"],
        "edge_cases": ["edge case 1", "edge case 2"]
    }},
    "test_setup": {{
        "dependencies": ["test dependency 1", "test dependency 2"],
        "mock_requirements": ["what needs to be mocked"],
        "setup_code": "any setup code needed before tests"
    }},
    "security_assertions": [
        "assertion 1: what security property is verified",
        "assertion 2: what attack vector is blocked"
    ]
}}
"""

        return prompt

    @staticmethod
    def _get_language_security_guidance(language: str) -> str:
        """Get language-specific security guidance."""
        guidance = {
            "python": """
- Use parameterized queries for SQL operations (SQLAlchemy, psycopg2)
- Use html.escape() for HTML output escaping
- Use secrets module for cryptographic randomness
- Validate input with marshmallow or pydantic
- Use subprocess with shell=False and validate commands
- For pickle/eval vulnerabilities, use ast.literal_eval() or json instead
            """,
            "javascript": """
- Use parameterized queries for database operations
- Use prepared statements with mysql2/pg libraries
- Escape HTML output with libraries like DOMPurify or validator
- Use crypto.randomBytes() for secure random generation
- Validate input with joi, yup, or class-validator
- For eval vulnerabilities, use JSON.parse() or Function constructor alternatives
- Use Content Security Policy headers
            """,
            "java": """
- Use PreparedStatement for SQL queries
- Use OWASP Java HTML Sanitizer for HTML output
- Use SecureRandom for cryptographic operations
- Validate input with Bean Validation (JSR 303/380)
- Use ProcessBuilder instead of Runtime.exec()
- For reflection vulnerabilities, use allow-lists for class names
            """,
            "csharp": """
- Use parameterized queries with SqlCommand
- Use AntiXSS library or HttpUtility.HtmlEncode for output encoding
- Use RNGCryptoServiceProvider for secure randomness
- Validate input with Data Annotations or FluentValidation
- Use Process.Start with careful argument handling
- For reflection, validate type names against allow-lists
            """,
            "go": """
- Use prepared statements with database/sql
- Use html/template for HTML output
- Use crypto/rand for secure randomness
- Use validator library for input validation
- Use os/exec.Command with careful argument handling
- For reflection vulnerabilities, use type switches and interface assertions
            """,
        }

        return guidance.get(language.lower(), "")

    @staticmethod
    def _get_test_framework_guidance(language: str, framework: Optional[str]) -> str:
        """Get test framework specific guidance."""
        if not framework:
            return ""

        guidance = {
            "pytest": "Use pytest fixtures and parametrization. Include security-specific assertions.",
            "jest": "Use Jest test suites with describe/it blocks. Mock external dependencies.",
            "junit": "Use JUnit 5 with @Test annotations. Use Mockito for mocking.",
            "nunit": "Use NUnit with [Test] attributes. Use Moq for mocking dependencies.",
            "testing": "Use Go's built-in testing package with TestXxx functions.",
        }

        return guidance.get(
            framework.lower(), f"Use {framework} testing patterns and best practices."
        )

    @staticmethod
    def build_fix_comparison_prompt(
        finding_data: Dict,
        fix_options: List[Dict],
        context_requirements: Optional[Dict] = None,
    ) -> str:
        """
        Build a prompt to compare multiple fix options and recommend the best approach.

        Args:
            finding_data: Details of the security finding
            fix_options: List of different fix approaches
            context_requirements: Specific requirements or constraints

        Returns:
            Formatted prompt for fix comparison
        """

        prompt = f"""
Compare these security fix options and recommend the best approach based on security effectiveness, maintainability, and implementation cost.

VULNERABILITY DETAILS:
- Type: {finding_data.get("pattern_id", "Unknown")}
- Severity: {finding_data.get("severity", "Unknown")}
- Context: {finding_data.get("message", "Unknown")}

FIX OPTIONS TO COMPARE:
"""

        for i, option in enumerate(fix_options, 1):
            prompt += f"""
Option {i}: {option.get("name", f"Fix {i}")}
Description: {option.get("description", "No description")}
Implementation effort: {option.get("effort", "Unknown")}
Security effectiveness: {option.get("security_score", "Unknown")}
"""

        if context_requirements:
            prompt += f"""
CONTEXT REQUIREMENTS:
- Performance constraints: {context_requirements.get("performance", "None specified")}
- Compatibility requirements: {context_requirements.get("compatibility", "None specified")}
- Maintenance considerations: {context_requirements.get("maintenance", "None specified")}
- Timeline constraints: {context_requirements.get("timeline", "None specified")}
"""

        prompt += """
COMPARISON CRITERIA:

1. SECURITY EFFECTIVENESS:
   - How completely does each fix eliminate the vulnerability?
   - Which provides the strongest defense against attacks?
   - Which offers the best defense-in-depth?

2. IMPLEMENTATION COST:
   - Development time and complexity
   - Risk of introducing bugs
   - Impact on existing code

3. MAINTAINABILITY:
   - Long-term maintenance burden
   - Clarity and readability
   - Future modification flexibility

4. PERFORMANCE IMPACT:
   - Runtime performance implications
   - Memory usage changes
   - Scalability considerations

Respond with JSON:

{
    "recommended_fix": {
        "option_number": integer,
        "name": "name of recommended fix",
        "justification": "detailed reasoning for recommendation"
    },
    "comparison_matrix": [
        {
            "option_number": integer,
            "security_score": integer (1-10),
            "implementation_score": integer (1-10),
            "maintainability_score": integer (1-10),
            "performance_score": integer (1-10),
            "total_score": integer,
            "strengths": ["strength 1", "strength 2"],
            "weaknesses": ["weakness 1", "weakness 2"]
        }
    ],
    "implementation_roadmap": {
        "immediate_actions": ["action 1", "action 2"],
        "follow_up_tasks": ["task 1", "task 2"],
        "validation_steps": ["validation 1", "validation 2"]
    },
    "risk_assessment": {
        "implementation_risks": ["risk 1", "risk 2"],
        "mitigation_strategies": ["strategy 1", "strategy 2"]
    }
}
"""

        return prompt
