"""
Remediation Generation Service for Interactive LLM Analysis
Generates secure code fixes for security vulnerabilities with testing and validation.
"""

from __future__ import annotations

import logging
import json
import re
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from api.database import db
from api.services.llm_service import llm_service
from api.services.credit_service import credit_service, SCAN_COSTS
from api.prompts.fix_generation_prompts import FixGenerationPrompts
from api.exceptions import InsufficientCreditsError

logger = logging.getLogger(__name__)


class RemediationRequest(BaseModel):
    """Request for code remediation generation."""

    user_id: str = Field(..., description="User requesting the remediation")
    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Finding to generate remediation for")
    fix_preference: str = Field(
        default="secure", description="Fix preference: secure, minimal, performance"
    )
    include_tests: bool = Field(
        default=True, description="Include unit tests for the fix"
    )
    include_alternatives: bool = Field(
        default=True, description="Include alternative fix approaches"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class CodeFix(BaseModel):
    """A code fix implementation."""

    description: str = Field(..., description="Description of the fix approach")
    code: str = Field(..., description="Complete fixed code")
    explanation: str = Field(
        ..., description="Detailed explanation of how the fix works"
    )
    security_benefits: List[str] = Field(..., description="Security benefits provided")
    potential_issues: List[str] = Field(
        ..., description="Potential caveats or side effects"
    )


class AlternativeFix(BaseModel):
    """An alternative fix approach."""

    name: str = Field(..., description="Name of the alternative approach")
    description: str = Field(..., description="Brief description")
    code: str = Field(..., description="Alternative implementation code")
    pros: List[str] = Field(..., description="Advantages of this approach")
    cons: List[str] = Field(..., description="Disadvantages of this approach")


class UnitTest(BaseModel):
    """Unit test for validating the fix."""

    description: str = Field(..., description="Description of what the test validates")
    code: str = Field(..., description="Complete unit test code")
    test_explanation: str = Field(..., description="Explanation of test validation")


class SecurityValidation(BaseModel):
    """Security validation information."""

    attack_prevention: str = Field(
        ..., description="How this prevents the original attack"
    )
    additional_protections: List[str] = Field(
        ..., description="Extra security measures"
    )
    security_checklist: List[str] = Field(
        ..., description="Security verification items"
    )


class ImplementationNotes(BaseModel):
    """Implementation and deployment notes."""

    breaking_changes: List[str] = Field(..., description="Any breaking changes")
    dependencies_needed: List[str] = Field(..., description="New dependencies required")
    configuration_changes: List[str] = Field(
        ..., description="Configuration updates needed"
    )
    migration_steps: List[str] = Field(..., description="Safe deployment steps")


class BeforeAfterComparison(BaseModel):
    """Before/after comparison demonstrating the fix."""

    vulnerability_demo: str = Field(
        ..., description="Code demonstrating the original vulnerability"
    )
    fix_demonstration: str = Field(..., description="How the fix prevents exploitation")


class RemediationResponse(BaseModel):
    """Response from remediation generation."""

    remediation_id: str = Field(..., description="Unique remediation ID")
    finding_id: str = Field(..., description="Finding that was remediated")
    language: str = Field(..., description="Programming language of the fix")
    primary_fix: CodeFix = Field(..., description="Main recommended fix")
    alternative_fixes: List[AlternativeFix] = Field(
        ..., description="Alternative approaches"
    )
    unit_test: Optional[UnitTest] = Field(
        default=None, description="Unit test for the fix"
    )
    security_validation: SecurityValidation = Field(
        ..., description="Security validation info"
    )
    implementation_notes: ImplementationNotes = Field(
        ..., description="Implementation guidance"
    )
    before_after_comparison: BeforeAfterComparison = Field(
        ..., description="Vulnerability demonstration"
    )
    model_used: str = Field(..., description="LLM model used for generation")
    credits_used: int = Field(..., description="Credits consumed for generation")
    processing_time_ms: Optional[int] = Field(
        default=None, description="Processing time"
    )


class RemediationGeneratorService:
    """Service for generating secure code remediations."""

    async def generate_remediation(
        self, request: RemediationRequest
    ) -> RemediationResponse:
        """
        Generate secure code remediation for a security finding.

        Args:
            request: Remediation request with finding details and preferences

        Returns:
            Complete remediation with code fixes, tests, and guidance

        Raises:
            InsufficientCreditsError: If user lacks credits for remediation
        """
        remediation_id = str(uuid4())[:16]
        start_time = datetime.utcnow()

        try:
            # Use Sonnet model for code generation (balance of quality and cost)
            model = "claude-3-sonnet-20240229"
            credits_cost = SCAN_COSTS["remediation_suggest"]

            # Check credit availability
            if not await credit_service.has_credits(request.user_id, credits_cost):
                balance = await credit_service.get_balance(request.user_id)
                raise InsufficientCreditsError(
                    f"Insufficient credits for remediation generation. "
                    f"Required: {credits_cost}, Available: {balance}"
                )

            # Get finding details from database
            finding_data = await self._get_finding_details(
                request.scan_id, request.finding_id
            )
            if not finding_data:
                raise ValueError(
                    f"Finding {request.finding_id} not found in scan {request.scan_id}"
                )

            # Get extended code context
            code_context = await self._get_extended_code_context(
                request.scan_id, finding_data["file_path"], finding_data["line_number"]
            )

            # Determine programming language
            language = self._detect_language(finding_data["file_path"])

            # Get framework information if available
            framework_info = await self._detect_framework(
                request.scan_id, finding_data["file_path"]
            )

            # Generate remediation
            remediation_data = await self._generate_main_remediation(
                finding_data,
                code_context,
                language,
                framework_info,
                request.fix_preference,
                model,
            )

            # Parse and structure the response
            remediation_response = self._parse_remediation_response(
                remediation_data, finding_data, language, model, remediation_id
            )

            # Calculate processing time
            processing_time = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            remediation_response.processing_time_ms = processing_time
            remediation_response.credits_used = credits_cost

            # Deduct credits
            await credit_service.deduct_credits(
                user_id=request.user_id,
                amount=credits_cost,
                transaction_type="remediation",
                scan_id=request.scan_id,
                session_id=request.session_id,
                model_used=model,
                tokens_used=self._estimate_tokens(code_context, str(remediation_data)),
                metadata={
                    "remediation_id": remediation_id,
                    "finding_id": request.finding_id,
                    "language": language,
                    "fix_preference": request.fix_preference,
                    "include_tests": request.include_tests,
                },
            )

            # Store in session if provided
            if request.session_id:
                await self._store_remediation_in_session(
                    request.session_id, remediation_response
                )

            logger.info(
                f"Generated remediation {remediation_id} for finding {request.finding_id} "
                f"in {processing_time}ms using {model}"
            )

            return remediation_response

        except InsufficientCreditsError:
            raise
        except Exception as e:
            logger.exception(
                f"Remediation generation failed for finding {request.finding_id}: {e}"
            )
            raise

    async def _get_finding_details(
        self, scan_id: str, finding_id: str
    ) -> Optional[Dict]:
        """Retrieve finding details from database."""
        try:
            result = await db.fetch_one(
                """
                SELECT 
                    finding_id,
                    phase,
                    pattern_id,
                    severity,
                    message,
                    file_path,
                    line_number,
                    code_snippet,
                    context_before,
                    context_after,
                    metadata
                FROM scan_findings 
                WHERE scan_id = :scan_id AND finding_id = :finding_id
                """,
                {"scan_id": scan_id, "finding_id": finding_id},
            )

            if result:
                return {
                    "finding_id": result["finding_id"],
                    "phase": result["phase"],
                    "pattern_id": result["pattern_id"],
                    "severity": result["severity"],
                    "message": result["message"],
                    "file_path": result["file_path"],
                    "line_number": result["line_number"],
                    "code_snippet": result["code_snippet"],
                    "context_before": result["context_before"],
                    "context_after": result["context_after"],
                    "metadata": json.loads(result["metadata"])
                    if result["metadata"]
                    else {},
                }

            return None

        except Exception as e:
            logger.exception(f"Failed to get finding details: {e}")
            return None

    async def _get_extended_code_context(
        self, scan_id: str, file_path: str, line_number: int
    ) -> str:
        """Get extended code context for remediation generation."""
        try:
            result = await db.fetch_one(
                """
                SELECT file_content 
                FROM scan_files 
                WHERE scan_id = :scan_id AND file_path = :file_path
                """,
                {"scan_id": scan_id, "file_path": file_path},
            )

            if result and result["file_content"]:
                lines = result["file_content"].split("\n")
                start_line = max(0, line_number - 30)  # 30 lines before
                end_line = min(len(lines), line_number + 30)  # 30 lines after

                context_lines = []
                for i in range(start_line, end_line):
                    prefix = ">>> " if i == line_number else "    "
                    context_lines.append(f"{i + 1:4d}:{prefix}{lines[i]}")

                return "\n".join(context_lines)

            return "Code context not available"

        except Exception as e:
            logger.exception(f"Failed to get extended code context: {e}")
            return "Error retrieving code context"

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        if "." not in file_path:
            return "unknown"

        extension = file_path.split(".")[-1].lower()

        language_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "java": "java",
            "cs": "csharp",
            "go": "go",
            "php": "php",
            "rb": "ruby",
            "cpp": "cpp",
            "c": "c",
            "rs": "rust",
            "swift": "swift",
            "kt": "kotlin",
            "scala": "scala",
        }

        return language_map.get(extension, extension)

    async def _detect_framework(self, scan_id: str, file_path: str) -> Optional[Dict]:
        """Detect framework information from project context."""
        try:
            # Look for common framework indicators in project files
            framework_files = [
                "package.json",
                "requirements.txt",
                "pom.xml",
                "Gemfile",
                "composer.json",
                "go.mod",
                "Cargo.toml",
            ]

            for framework_file in framework_files:
                result = await db.fetch_one(
                    """
                    SELECT file_content 
                    FROM scan_files 
                    WHERE scan_id = :scan_id AND file_path LIKE :pattern
                    """,
                    {"scan_id": scan_id, "pattern": f"%{framework_file}"},
                )

                if result:
                    # Simple framework detection based on file content
                    content = result["file_content"].lower()
                    frameworks = self._extract_frameworks_from_content(
                        content, framework_file
                    )
                    if frameworks:
                        return frameworks

            return None

        except Exception as e:
            logger.warning(f"Framework detection failed: {e}")
            return None

    def _extract_frameworks_from_content(
        self, content: str, filename: str
    ) -> Optional[Dict]:
        """Extract framework information from dependency file content."""
        frameworks = {
            "package.json": {
                "react": "React",
                "express": "Express.js",
                "nestjs": "NestJS",
                "angular": "Angular",
                "vue": "Vue.js",
            },
            "requirements.txt": {
                "django": "Django",
                "flask": "Flask",
                "fastapi": "FastAPI",
                "sqlalchemy": "SQLAlchemy",
            },
            "pom.xml": {"spring": "Spring Framework", "hibernate": "Hibernate"},
        }

        for framework_key, framework_name in frameworks.get(filename, {}).items():
            if framework_key in content:
                return {
                    "name": framework_name,
                    "version": "unknown",
                    "security_libs": self._get_security_libs_for_framework(
                        framework_name
                    ),
                }

        return None

    def _get_security_libs_for_framework(self, framework: str) -> List[str]:
        """Get security libraries commonly used with a framework."""
        security_libs_map = {
            "Django": ["django-ratelimit", "django-csp", "django-security"],
            "Flask": ["flask-security", "flask-limiter", "flask-talisman"],
            "Express.js": ["helmet", "express-rate-limit", "express-validator"],
            "Spring Framework": ["spring-security", "owasp-java-encoder"],
            "React": ["dompurify", "validator"],
        }

        return security_libs_map.get(framework, [])

    async def _generate_main_remediation(
        self,
        finding_data: Dict,
        code_context: str,
        language: str,
        framework_info: Optional[Dict],
        fix_preference: str,
        model: str,
    ) -> Dict:
        """Generate the main remediation using LLM."""
        try:
            # Build remediation prompt
            prompt = FixGenerationPrompts.build_remediation_prompt(
                finding_data=finding_data,
                code_context=code_context,
                language=language,
                framework_info=framework_info,
                fix_preference=fix_preference,
            )

            # Call LLM service
            response = await self._call_llm_service(prompt, model)

            # Parse JSON response
            return self._parse_json_response(response)

        except Exception as e:
            logger.exception(f"Remediation generation failed: {e}")
            raise

    async def _call_llm_service(self, prompt: str, model: str) -> str:
        """Call LLM service for remediation generation."""
        from api.llm_models import LLMAnalysisRequest, LLMAnalysisType

        # Create analysis request
        analysis_request = LLMAnalysisRequest(
            file_contents={"remediation_context": prompt},
            analysis_types=[LLMAnalysisType.VULNERABILITY_ANALYSIS],
            max_tokens=4000,  # Larger token limit for code generation
            include_context_analysis=False,
        )

        # Call LLM service
        response = await llm_service.analyze_threat(analysis_request)

        # Extract response content
        if response.insights:
            return response.insights[0].description
        else:
            raise Exception("No insights returned from LLM analysis")

    def _parse_json_response(self, response: str) -> Dict:
        """Parse JSON response from LLM with error handling."""
        try:
            # Try to extract JSON block
            json_match = re.search(r"```json\n(.*?)\n```", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON object
                json_match = re.search(r"\{.*\}", response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    json_str = response

            return json.loads(json_str)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            logger.debug(f"Raw response: {response[:500]}...")

            # Return fallback structure
            return {
                "primary_fix": {
                    "description": "Fix generation failed - JSON parsing error",
                    "code": "// Fix generation failed",
                    "explanation": f"Error parsing LLM response: {str(e)}",
                    "security_benefits": [],
                    "potential_issues": ["Fix generation failed"],
                },
                "alternative_fixes": [],
                "unit_test": {
                    "description": "Test generation failed",
                    "code": "// Test generation failed",
                    "test_explanation": "Unable to generate tests due to parsing error",
                },
                "security_validation": {
                    "attack_prevention": "Unknown due to parsing error",
                    "additional_protections": [],
                    "security_checklist": [],
                },
                "implementation_notes": {
                    "breaking_changes": [],
                    "dependencies_needed": [],
                    "configuration_changes": [],
                    "migration_steps": [],
                },
                "before_after_comparison": {
                    "vulnerability_demo": "Demo unavailable due to error",
                    "fix_demonstration": "Fix demonstration unavailable",
                },
            }

    def _parse_remediation_response(
        self,
        remediation_data: Dict,
        finding_data: Dict,
        language: str,
        model: str,
        remediation_id: str,
    ) -> RemediationResponse:
        """Parse remediation data into structured response."""
        try:
            # Parse primary fix
            primary_fix_data = remediation_data.get("primary_fix", {})
            primary_fix = CodeFix(
                description=primary_fix_data.get("description", "No description"),
                code=primary_fix_data.get("code", "// No code generated"),
                explanation=primary_fix_data.get(
                    "explanation", "No explanation available"
                ),
                security_benefits=primary_fix_data.get("security_benefits", []),
                potential_issues=primary_fix_data.get("potential_issues", []),
            )

            # Parse alternative fixes
            alternative_fixes = []
            for alt_data in remediation_data.get("alternative_fixes", []):
                alternative_fixes.append(
                    AlternativeFix(
                        name=alt_data.get("name", "Alternative Fix"),
                        description=alt_data.get("description", "No description"),
                        code=alt_data.get("code", "// No code"),
                        pros=alt_data.get("pros", []),
                        cons=alt_data.get("cons", []),
                    )
                )

            # Parse unit test
            unit_test_data = remediation_data.get("unit_test", {})
            unit_test = (
                UnitTest(
                    description=unit_test_data.get(
                        "description", "Test description unavailable"
                    ),
                    code=unit_test_data.get("code", "// No test code generated"),
                    test_explanation=unit_test_data.get(
                        "test_explanation", "Test explanation unavailable"
                    ),
                )
                if unit_test_data
                else None
            )

            # Parse security validation
            security_val_data = remediation_data.get("security_validation", {})
            security_validation = SecurityValidation(
                attack_prevention=security_val_data.get(
                    "attack_prevention", "Attack prevention details unavailable"
                ),
                additional_protections=security_val_data.get(
                    "additional_protections", []
                ),
                security_checklist=security_val_data.get("security_checklist", []),
            )

            # Parse implementation notes
            impl_notes_data = remediation_data.get("implementation_notes", {})
            implementation_notes = ImplementationNotes(
                breaking_changes=impl_notes_data.get("breaking_changes", []),
                dependencies_needed=impl_notes_data.get("dependencies_needed", []),
                configuration_changes=impl_notes_data.get("configuration_changes", []),
                migration_steps=impl_notes_data.get("migration_steps", []),
            )

            # Parse before/after comparison
            comparison_data = remediation_data.get("before_after_comparison", {})
            before_after_comparison = BeforeAfterComparison(
                vulnerability_demo=comparison_data.get(
                    "vulnerability_demo", "Demo unavailable"
                ),
                fix_demonstration=comparison_data.get(
                    "fix_demonstration", "Fix demonstration unavailable"
                ),
            )

            return RemediationResponse(
                remediation_id=remediation_id,
                finding_id=finding_data["finding_id"],
                language=language,
                primary_fix=primary_fix,
                alternative_fixes=alternative_fixes,
                unit_test=unit_test,
                security_validation=security_validation,
                implementation_notes=implementation_notes,
                before_after_comparison=before_after_comparison,
                model_used=model,
                credits_used=0,  # Will be set by caller
            )

        except Exception as e:
            logger.exception(f"Failed to parse remediation response: {e}")

            # Return minimal fallback response
            return RemediationResponse(
                remediation_id=remediation_id,
                finding_id=finding_data["finding_id"],
                language=language,
                primary_fix=CodeFix(
                    description="Remediation parsing failed",
                    code="// Remediation generation failed",
                    explanation=f"Error parsing remediation: {str(e)}",
                    security_benefits=[],
                    potential_issues=["Parsing error occurred"],
                ),
                alternative_fixes=[],
                unit_test=None,
                security_validation=SecurityValidation(
                    attack_prevention="Unknown due to parsing error",
                    additional_protections=[],
                    security_checklist=[],
                ),
                implementation_notes=ImplementationNotes(
                    breaking_changes=[],
                    dependencies_needed=[],
                    configuration_changes=[],
                    migration_steps=[],
                ),
                before_after_comparison=BeforeAfterComparison(
                    vulnerability_demo="Demo unavailable due to error",
                    fix_demonstration="Fix demonstration unavailable",
                ),
                model_used=model,
                credits_used=0,
            )

    def _estimate_tokens(self, prompt: str, response: str) -> int:
        """Estimate token usage for billing."""
        return (len(prompt) + len(response)) // 4

    async def _store_remediation_in_session(
        self, session_id: str, remediation: RemediationResponse
    ) -> None:
        """Store remediation result in interactive session."""
        try:
            # Get current session data
            session = await db.fetch_one(
                "SELECT conversation_history FROM interactive_sessions WHERE session_id = :session_id",
                {"session_id": session_id},
            )

            if session:
                # Parse existing conversation
                conversation = json.loads(session["conversation_history"] or "[]")

                # Add remediation result
                conversation.append(
                    {
                        "type": "remediation",
                        "timestamp": datetime.utcnow().isoformat(),
                        "remediation_id": remediation.remediation_id,
                        "finding_id": remediation.finding_id,
                        "language": remediation.language,
                        "primary_fix_description": remediation.primary_fix.description,
                        "alternatives_count": len(remediation.alternative_fixes),
                        "includes_test": remediation.unit_test is not None,
                    }
                )

                # Update session
                await db.execute(
                    """
                    UPDATE interactive_sessions 
                    SET conversation_history = :conversation,
                        last_activity = :timestamp,
                        total_credits_used = total_credits_used + :credits
                    WHERE session_id = :session_id
                    """,
                    {
                        "session_id": session_id,
                        "conversation": json.dumps(conversation),
                        "timestamp": datetime.utcnow(),
                        "credits": remediation.credits_used,
                    },
                )

        except Exception as e:
            logger.exception(f"Failed to store remediation in session: {e}")


# Global service instance
remediation_generator = RemediationGeneratorService()
