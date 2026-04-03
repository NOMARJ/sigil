"""
Sigil Forge — Classification Engine

Implements LLM-based classification of skills and MCP servers using Claude Haiku.
Takes package description + Sigil scan findings as input and outputs:
- Primary category (Database, API Integration, Code Tools, etc.)
- Capability tags (reads_files, makes_network_calls, etc.)
- Confidence scores and evidence

Designed for cost-effective batch classification of 7,700+ tools at ~$5-15/month.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import anthropic
from api.config import settings
from api.database import db
from api.models import Finding, ScanPhase, Severity

logger = logging.getLogger(__name__)


@dataclass
class ClassificationInput:
    """Input data for classification."""

    ecosystem: str  # 'clawhub', 'mcp', 'npm', 'pypi'
    package_name: str
    package_version: str
    description: str
    scan_findings: list[Finding]
    metadata: dict[str, Any]


@dataclass
class ClassificationResult:
    """Result of LLM classification."""

    category: str
    subcategory: str = ""
    confidence_score: float = 0.0
    description_summary: str = ""
    environment_vars: list[str] = None
    network_protocols: list[str] = None
    file_patterns: list[str] = None
    import_patterns: list[str] = None
    risk_indicators: list[str] = None
    capabilities: list[dict[str, Any]] = None

    def __post_init__(self):
        if self.environment_vars is None:
            self.environment_vars = []
        if self.network_protocols is None:
            self.network_protocols = []
        if self.file_patterns is None:
            self.file_patterns = []
        if self.import_patterns is None:
            self.import_patterns = []
        if self.risk_indicators is None:
            self.risk_indicators = []
        if self.capabilities is None:
            self.capabilities = []


class ForgeClassifier:
    """LLM-based classification engine for Sigil Forge."""

    def __init__(self):
        self.api_key = settings.anthropic_api_key
        self.client = (
            anthropic.AsyncAnthropic(api_key=self.api_key) if self.api_key else None
        )
        self.model = "claude-haiku-4-5-20251001"  # Cost-effective option
        self.classifier_version = "v1.0"

    def _extract_scan_patterns(self, findings: list[Finding]) -> dict[str, Any]:
        """Extract structured patterns from Sigil scan findings."""
        patterns = {
            "environment_vars": set(),
            "network_protocols": set(),
            "file_patterns": set(),
            "import_patterns": set(),
            "risk_indicators": [],
        }

        for finding in findings:
            # Extract environment variable patterns
            if finding.phase == ScanPhase.CREDENTIALS:
                env_match = re.search(
                    r"(AWS_|GITHUB_|API_KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL|REDIS_URL)",
                    finding.snippet,
                    re.IGNORECASE,
                )
                if env_match:
                    patterns["environment_vars"].add(env_match.group(1))

            # Extract network protocols
            if finding.phase == ScanPhase.NETWORK_EXFIL:
                snippet_lower = finding.snippet.lower()
                if any(
                    token in snippet_lower
                    for token in ["http", "fetch", "axios", "request("]
                ):
                    patterns["network_protocols"].add("HTTP")
                if "webhook" in snippet_lower:
                    patterns["network_protocols"].add("Webhook")
                if "socket" in snippet_lower:
                    patterns["network_protocols"].add("WebSocket")
                if "grpc" in snippet_lower:
                    patterns["network_protocols"].add("gRPC")

            # Extract import patterns (key dependencies)
            if finding.phase == ScanPhase.CODE_PATTERNS:
                # Common database libraries
                if any(
                    db in finding.snippet.lower()
                    for db in ["psycopg", "pymongo", "redis", "mysql", "sqlite"]
                ):
                    patterns["import_patterns"].add("database")
                # HTTP clients
                if any(
                    http in finding.snippet.lower()
                    for http in ["requests", "httpx", "axios", "fetch"]
                ):
                    patterns["import_patterns"].add("http_client")
                # File operations
                if any(
                    file_op in finding.snippet.lower()
                    for file_op in ["pathlib", "os.path", "fs.", "file"]
                ):
                    patterns["import_patterns"].add("file_operations")

            # Track high-severity findings as risk indicators
            if finding.severity in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
                patterns["risk_indicators"].append(
                    {
                        "rule": finding.rule,
                        "severity": finding.severity.value,
                        "description": finding.description,
                    }
                )

        # Convert sets to lists for JSON serialization
        return {
            "environment_vars": list(patterns["environment_vars"]),
            "network_protocols": list(patterns["network_protocols"]),
            "file_patterns": list(patterns["file_patterns"]),
            "import_patterns": list(patterns["import_patterns"]),
            "risk_indicators": patterns["risk_indicators"],
        }

    def _build_classification_prompt(self, input_data: ClassificationInput) -> str:
        """Build the prompt for LLM classification."""
        scan_patterns = self._extract_scan_patterns(input_data.scan_findings)

        findings_summary = []
        for finding in input_data.scan_findings[
            :10
        ]:  # Limit to first 10 findings to control prompt size
            findings_summary.append(
                f"- {finding.phase.value}: {finding.description} (severity: {finding.severity.value})"
            )

        prompt = f"""You are an AI agent tool classifier for Sigil Forge. Your job is to categorize AI agent skills and MCP servers based on their functionality.

PACKAGE INFORMATION:
- Ecosystem: {input_data.ecosystem}
- Name: {input_data.package_name}
- Version: {input_data.package_version}
- Description: {input_data.description}

SCAN ANALYSIS:
Environment Variables: {scan_patterns["environment_vars"]}
Network Protocols: {scan_patterns["network_protocols"]}
Import Patterns: {scan_patterns["import_patterns"]}
Security Findings: {len(input_data.scan_findings)} total
{chr(10).join(findings_summary[:5])}  

CATEGORIES (choose the best fit):
- Database: Postgres, MongoDB, Redis, MySQL connectors
- API Integration: Stripe, GitHub, Slack, REST APIs
- Code Tools: Linting, testing, formatting, compilation  
- File System: Filesystem ops, search, git, file processing
- AI/LLM: Prompt engineering, RAG, embeddings, model ops
- Security: Scanning, secrets, auth, compliance
- DevOps: CI/CD, monitoring, deployment, infrastructure
- Communication: Email, chat, notifications
- Data Pipeline: ETL, transformation, analytics
- Testing: Unit tests, integration, QA automation
- Search: Web search, document search, indexing
- Monitoring: Application monitoring, logging, metrics
- Uncategorized: If none of the above fit

CAPABILITIES (list all that apply):
- reads_files: Accesses local file system
- writes_files: Creates or modifies files
- makes_network_calls: Performs HTTP/API requests
- accesses_database: Connects to databases
- requires_env_vars: Needs environment configuration
- creates_processes: Spawns child processes
- modifies_system: Changes system settings/state
- handles_credentials: Works with secrets/auth
- processes_user_input: Takes user data/prompts
- generates_content: Creates text/code/media

Please respond with valid JSON only:
{
            "category": "Database",
  "subcategory": "PostgreSQL",
  "confidence_score": 0.95,
  "description_summary": "A PostgreSQL database connector for AI agents",
  "capabilities": [
    {
                "capability": "accesses_database", "confidence": 0.9, "evidence": "Found DATABASE_URL environment variable"},
    {
                "capability": "requires_env_vars", "confidence": 1.0, "evidence": "Requires DATABASE_URL configuration"}
  ]
}"""

        return prompt

    async def classify_package(
        self, input_data: ClassificationInput
    ) -> ClassificationResult:
        """Classify a single package using Claude Haiku."""
        if not self.client:
            logger.warning(
                "No Anthropic API key configured, using rule-based classification"
            )
            return self._fallback_classification(input_data)

        prompt = self._build_classification_prompt(input_data)

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            content = response.content[0].text

            # Parse JSON response
            classification_data = json.loads(content)

            # Extract scan patterns for database storage
            scan_patterns = self._extract_scan_patterns(input_data.scan_findings)

            return ClassificationResult(
                category=classification_data.get("category", "Uncategorized"),
                subcategory=classification_data.get("subcategory", ""),
                confidence_score=classification_data.get("confidence_score", 0.0),
                description_summary=classification_data.get(
                    "description_summary", input_data.description[:500]
                ),
                environment_vars=scan_patterns["environment_vars"],
                network_protocols=scan_patterns["network_protocols"],
                file_patterns=scan_patterns["file_patterns"],
                import_patterns=scan_patterns["import_patterns"],
                risk_indicators=[ri["rule"] for ri in scan_patterns["risk_indicators"]],
                capabilities=classification_data.get("capabilities", []),
            )

        except Exception as e:
            logger.error(
                f"LLM classification failed for {input_data.package_name}: {e}"
            )
            return self._fallback_classification(input_data)

    def _fallback_classification(
        self, input_data: ClassificationInput
    ) -> ClassificationResult:
        """Rule-based fallback classification when LLM is unavailable."""
        description_lower = input_data.description.lower()
        scan_patterns = self._extract_scan_patterns(input_data.scan_findings)

        # Simple keyword-based classification
        category = "Uncategorized"
        subcategory = ""

        if any(
            db in description_lower
            for db in ["postgres", "mysql", "mongo", "redis", "database", "sql"]
        ):
            category = "Database"
        elif any(
            api in description_lower
            for api in ["github", "slack", "stripe", "api", "rest", "webhook"]
        ):
            category = "API Integration"
        elif any(
            tool in description_lower
            for tool in ["lint", "test", "format", "compile", "build"]
        ):
            category = "Code Tools"
        elif any(
            file in description_lower
            for file in ["file", "filesystem", "git", "directory"]
        ):
            category = "File System"
        elif any(
            ai in description_lower
            for ai in ["llm", "ai", "prompt", "embedding", "rag", "gpt", "claude"]
        ):
            category = "AI/LLM"
        elif any(
            sec in description_lower
            for sec in ["security", "auth", "secret", "scan", "vulnerability"]
        ):
            category = "Security"
        elif any(
            dev in description_lower
            for dev in ["deploy", "ci", "cd", "docker", "kubernetes", "monitoring"]
        ):
            category = "DevOps"
        elif any(
            comm in description_lower
            for comm in ["email", "chat", "notification", "message"]
        ):
            category = "Communication"
        elif any(
            data in description_lower
            for data in ["etl", "pipeline", "analytics", "transform"]
        ):
            category = "Data Pipeline"
        elif any(
            search in description_lower
            for search in ["search", "index", "elastic", "solr"]
        ):
            category = "Search"

        # Determine capabilities based on scan findings
        capabilities = []
        if scan_patterns["environment_vars"]:
            capabilities.append(
                {
                    "capability": "requires_env_vars",
                    "confidence": 1.0,
                    "evidence": "Environment variables detected",
                }
            )
        if scan_patterns["network_protocols"]:
            capabilities.append(
                {
                    "capability": "makes_network_calls",
                    "confidence": 1.0,
                    "evidence": "Network protocols detected",
                }
            )
        if "database" in scan_patterns["import_patterns"]:
            capabilities.append(
                {
                    "capability": "accesses_database",
                    "confidence": 0.8,
                    "evidence": "Database imports detected",
                }
            )
        if "file_operations" in scan_patterns["import_patterns"]:
            capabilities.append(
                {
                    "capability": "reads_files",
                    "confidence": 0.8,
                    "evidence": "File operation imports detected",
                }
            )

        return ClassificationResult(
            category=category,
            subcategory=subcategory,
            confidence_score=0.6,  # Lower confidence for rule-based
            description_summary=input_data.description[:500],
            environment_vars=scan_patterns["environment_vars"],
            network_protocols=scan_patterns["network_protocols"],
            file_patterns=scan_patterns["file_patterns"],
            import_patterns=scan_patterns["import_patterns"],
            risk_indicators=[ri["rule"] for ri in scan_patterns["risk_indicators"]],
            capabilities=capabilities,
        )

    async def save_classification(
        self, input_data: ClassificationInput, result: ClassificationResult
    ) -> str:
        """Save classification result to database and return the ID."""
        try:
            # Save main classification record
            classification_record = await db.insert(
                "forge_classification",
                {
                    "ecosystem": input_data.ecosystem,
                    "package_name": input_data.package_name,
                    "package_version": input_data.package_version,
                    "category": result.category,
                    "subcategory": result.subcategory,
                    "confidence_score": result.confidence_score,
                    "description_summary": result.description_summary,
                    "environment_vars": json.dumps(result.environment_vars),
                    "network_protocols": json.dumps(result.network_protocols),
                    "file_patterns": json.dumps(result.file_patterns),
                    "import_patterns": json.dumps(result.import_patterns),
                    "risk_indicators": json.dumps(result.risk_indicators),
                    "classifier_version": self.classifier_version,
                    "metadata_json": json.dumps(input_data.metadata),
                    "classified_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                },
            )

            classification_id = classification_record["id"]

            # Save capability records
            for capability in result.capabilities:
                await db.insert(
                    "forge_capabilities",
                    {
                        "classification_id": classification_id,
                        "capability": capability["capability"],
                        "confidence": capability.get("confidence", 1.0),
                        "evidence": capability.get("evidence", ""),
                    },
                )

            logger.info(
                f"Saved classification for {input_data.ecosystem}/{input_data.package_name}: {result.category}"
            )
            return classification_id

        except Exception as e:
            logger.error(
                f"Failed to save classification for {input_data.package_name}: {e}"
            )
            raise

    async def get_classification(
        self, ecosystem: str, package_name: str, package_version: str = ""
    ) -> dict[str, Any] | None:
        """Get existing classification from api.database."""
        filters = {"ecosystem": ecosystem, "package_name": package_name}
        if package_version:
            filters["package_version"] = package_version

        classification = await db.select_one("forge_classification", filters)
        if not classification:
            return None

        # Get capabilities
        capabilities = await db.select(
            "forge_capabilities", {"classification_id": classification["id"]}
        )

        return {**classification, "capabilities": capabilities}

    async def classify_from_public_scan(
        self, ecosystem: str, package_name: str, package_version: str = ""
    ) -> ClassificationResult | None:
        """Classify a package from existing public_scans data."""
        # Get scan data
        filters = {"ecosystem": ecosystem, "package_name": package_name}
        if package_version:
            filters["package_version"] = package_version

        scan = await db.select_one("public_scans", filters)
        if not scan:
            logger.warning(f"No scan data found for {ecosystem}/{package_name}")
            return None

        # Parse findings
        findings_data = json.loads(scan.get("findings_json", "[]"))
        findings = [
            Finding(
                phase=ScanPhase(f["phase"]),
                rule=f["rule"],
                severity=Severity(f["severity"]),
                file=f["file"],
                line=f.get("line", 0),
                snippet=f.get("snippet", ""),
                weight=f.get("weight", 1.0),
                description=f.get("description", ""),
                explanation=f.get("explanation", ""),
            )
            for f in findings_data
        ]

        # Parse metadata
        metadata = json.loads(scan.get("metadata_json", "{}"))
        description = metadata.get("description", metadata.get("summary", ""))

        # Create classification input
        input_data = ClassificationInput(
            ecosystem=ecosystem,
            package_name=package_name,
            package_version=package_version,
            description=description,
            scan_findings=findings,
            metadata=metadata,
        )

        # Perform classification
        result = await self.classify_package(input_data)

        # Save to database
        await self.save_classification(input_data, result)

        return result


# Global instance
forge_classifier = ForgeClassifier()
