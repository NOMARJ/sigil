"""
Sigil Forge Classification Pipeline
Auto-classifies skills and MCP servers using LLM + rule-based analysis

Runs as Azure Container Apps job or async task
Cost target: ~$15-25/month for 7,700+ classifications
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Tuple

import anthropic
from pydantic import BaseModel

from api.database import db

logger = logging.getLogger("forge.classifier")


# ============================================================================
# CLASSIFICATION MODELS
# ============================================================================


class ClassificationInput(BaseModel):
    """Input data for package classification."""

    package_name: str
    ecosystem: str  # 'skills', 'mcp', 'npm', 'pypi'
    description: str
    readme_content: Optional[str] = None

    # From Sigil scan findings
    env_vars_detected: List[str] = []
    imports_detected: List[str] = []
    network_calls_detected: List[str] = []
    file_operations: List[str] = []

    # Metadata
    author: Optional[str] = None
    repository_url: Optional[str] = None
    tags: List[str] = []


class ClassificationResult(BaseModel):
    """LLM + rule-based classification output."""

    primary_category: str
    secondary_categories: List[str] = []
    capability_tags: List[str] = []

    env_vars_required: List[str] = []
    protocols_supported: List[str] = []
    runtime_requirements: List[str] = []

    confidence_score: float  # 0.0 to 1.0
    reasoning: str


# ============================================================================
# CATEGORY DEFINITIONS
# ============================================================================

FORGE_CATEGORIES = {
    "database": {
        "name": "Database Connectors",
        "keywords": ["postgres", "mysql", "mongodb", "redis", "sql", "database", "db"],
        "env_patterns": ["DATABASE_URL", "DB_", "POSTGRES_", "MONGO_", "REDIS_"],
        "import_patterns": ["psycopg", "pymongo", "redis", "sqlite", "mysql"],
    },
    "api": {
        "name": "API Integrations",
        "keywords": ["api", "rest", "graphql", "webhook", "http", "client"],
        "env_patterns": ["API_KEY", "SECRET", "TOKEN", "_URL"],
        "import_patterns": ["requests", "fetch", "axios", "httpx", "aiohttp"],
    },
    "code": {
        "name": "Code Tools",
        "keywords": ["lint", "format", "test", "compile", "build", "ast", "parser"],
        "env_patterns": [],
        "import_patterns": ["ast", "black", "pylint", "eslint", "pytest", "jest"],
    },
    "filesystem": {
        "name": "File/System Tools",
        "keywords": ["file", "filesystem", "directory", "path", "os", "system"],
        "env_patterns": ["PATH", "HOME", "TEMP"],
        "import_patterns": ["os", "pathlib", "fs", "glob", "shutil"],
    },
    "ai-llm": {
        "name": "AI/LLM Tools",
        "keywords": ["llm", "ai", "openai", "anthropic", "embeddings", "prompt", "rag"],
        "env_patterns": ["OPENAI_", "ANTHROPIC_", "HUGGING_FACE_", "LLM_"],
        "import_patterns": ["openai", "anthropic", "transformers", "langchain"],
    },
    "security": {
        "name": "Security Tools",
        "keywords": ["auth", "security", "encrypt", "hash", "jwt", "oauth", "scan"],
        "env_patterns": ["SECRET", "KEY", "TOKEN", "AUTH_"],
        "import_patterns": ["cryptography", "jwt", "oauth", "passlib", "bcrypt"],
    },
    "devops": {
        "name": "DevOps Tools",
        "keywords": [
            "docker",
            "kubernetes",
            "deploy",
            "ci",
            "cd",
            "terraform",
            "ansible",
        ],
        "env_patterns": ["DOCKER_", "KUBE_", "CI_", "DEPLOY_"],
        "import_patterns": ["docker", "kubernetes", "terraform", "ansible"],
    },
    "search": {
        "name": "Search Tools",
        "keywords": ["search", "index", "elasticsearch", "solr", "lucene", "query"],
        "env_patterns": ["SEARCH_", "ELASTIC_", "SOLR_"],
        "import_patterns": ["elasticsearch", "solr", "whoosh", "sqlite-fts"],
    },
    "communication": {
        "name": "Communication",
        "keywords": ["email", "slack", "discord", "teams", "notification", "sms"],
        "env_patterns": ["SLACK_", "DISCORD_", "EMAIL_", "SMTP_"],
        "import_patterns": ["slack", "discord", "smtplib", "twilio"],
    },
    "data": {
        "name": "Data Pipeline",
        "keywords": ["etl", "pipeline", "csv", "json", "xml", "pandas", "transform"],
        "env_patterns": ["DATA_", "PIPELINE_"],
        "import_patterns": ["pandas", "numpy", "csv", "json", "xml"],
    },
    "testing": {
        "name": "Testing Tools",
        "keywords": ["test", "mock", "fixture", "coverage", "benchmark"],
        "env_patterns": ["TEST_"],
        "import_patterns": ["pytest", "unittest", "jest", "mocha", "mock"],
    },
    "monitoring": {
        "name": "Monitoring",
        "keywords": ["log", "metric", "alert", "monitor", "trace", "observability"],
        "env_patterns": ["LOG_", "METRIC_", "TRACE_"],
        "import_patterns": ["logging", "prometheus", "grafana", "sentry"],
    },
}


# ============================================================================
# CLASSIFICATION LOGIC
# ============================================================================


class ForgeClassifier:
    """Hybrid LLM + rule-based package classification."""

    def __init__(self, anthropic_api_key: str):
        self.client = anthropic.AsyncAnthropic(api_key=anthropic_api_key)

    async def classify_package(
        self, input_data: ClassificationInput
    ) -> ClassificationResult:
        """Classify a package using hybrid approach."""

        # Step 1: Rule-based pre-classification
        rule_based_result = self._rule_based_classify(input_data)

        # Step 2: LLM enhancement (if confidence is low)
        if rule_based_result.confidence_score < 0.8:
            llm_result = await self._llm_classify(input_data, rule_based_result)
            return llm_result

        return rule_based_result

    def _rule_based_classify(
        self, input_data: ClassificationInput
    ) -> ClassificationResult:
        """Fast rule-based classification using patterns."""

        category_scores = {}

        for category_id, category_def in FORGE_CATEGORIES.items():
            score = 0.0

            # Score based on keywords in description
            description_lower = input_data.description.lower()
            keyword_matches = sum(
                1 for kw in category_def["keywords"] if kw in description_lower
            )
            score += keyword_matches * 0.3

            # Score based on environment variables
            env_matches = sum(
                1
                for pattern in category_def["env_patterns"]
                for env_var in input_data.env_vars_detected
                if pattern in env_var
            )
            score += env_matches * 0.4

            # Score based on imports
            import_matches = sum(
                1
                for pattern in category_def["import_patterns"]
                for import_name in input_data.imports_detected
                if pattern in import_name.lower()
            )
            score += import_matches * 0.3

            category_scores[category_id] = score

        # Find best match
        if not category_scores or max(category_scores.values()) == 0:
            return ClassificationResult(
                primary_category="other",
                confidence_score=0.1,
                reasoning="No clear pattern match found",
            )

        primary_category = max(category_scores.items(), key=lambda x: x[1])[0]
        confidence = min(0.9, category_scores[primary_category] / 3.0)  # Normalize

        # Extract capabilities
        capability_tags = self._extract_capabilities(input_data)

        return ClassificationResult(
            primary_category=primary_category,
            secondary_categories=[
                cat
                for cat, score in category_scores.items()
                if score > 0.5 and cat != primary_category
            ][:2],
            capability_tags=capability_tags,
            env_vars_required=input_data.env_vars_detected[:5],  # Top 5
            protocols_supported=self._extract_protocols(input_data),
            runtime_requirements=self._extract_runtime(input_data),
            confidence_score=confidence,
            reasoning=f"Rule-based match: {FORGE_CATEGORIES[primary_category]['name']}",
        )

    async def _llm_classify(
        self, input_data: ClassificationInput, rule_hint: ClassificationResult
    ) -> ClassificationResult:
        """Use Claude Haiku for detailed classification."""

        prompt = self._build_classification_prompt(input_data, rule_hint)

        try:
            response = await self.client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=500,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse LLM response
            return self._parse_llm_response(response.content[0].text, input_data)

        except Exception as e:
            logger.error(f"LLM classification failed: {e}")
            # Fallback to rule-based result
            return rule_hint

    def _build_classification_prompt(
        self, input_data: ClassificationInput, rule_hint: ClassificationResult
    ) -> str:
        """Build classification prompt for Claude."""

        categories_list = "\n".join(
            [
                f"- {cat_id}: {cat_def['name']}"
                for cat_id, cat_def in FORGE_CATEGORIES.items()
            ]
        )

        return f"""Classify this AI agent tool into categories:

Package: {input_data.package_name}
Ecosystem: {input_data.ecosystem}
Description: {input_data.description}

Environment variables detected: {input_data.env_vars_detected}
Imports detected: {input_data.imports_detected}
Network calls: {input_data.network_calls_detected}

Available categories:
{categories_list}

Rule-based suggestion: {rule_hint.primary_category} (confidence: {rule_hint.confidence_score:.2f})

Please respond with JSON:
{{
    "primary_category": "category_id",
    "secondary_categories": ["category_id"],
    "capability_tags": ["reads_files", "makes_http_calls", "requires_database"],
    "env_vars_required": ["ENV_VAR1", "ENV_VAR2"],
    "protocols_supported": ["http", "postgres", "redis"],
    "runtime_requirements": ["python", "node", "docker"],
    "confidence_score": 0.85,
    "reasoning": "Brief explanation"
}}"""

    def _parse_llm_response(
        self, response: str, input_data: ClassificationInput
    ) -> ClassificationResult:
        """Parse LLM JSON response into classification result."""

        try:
            parsed = json.loads(response.strip())
            return ClassificationResult(
                primary_category=parsed.get("primary_category", "other"),
                secondary_categories=parsed.get("secondary_categories", []),
                capability_tags=parsed.get("capability_tags", []),
                env_vars_required=parsed.get("env_vars_required", []),
                protocols_supported=parsed.get("protocols_supported", []),
                runtime_requirements=parsed.get("runtime_requirements", []),
                confidence_score=min(
                    1.0, max(0.0, parsed.get("confidence_score", 0.5))
                ),
                reasoning=parsed.get("reasoning", "LLM classification"),
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return ClassificationResult(
                primary_category="other",
                confidence_score=0.3,
                reasoning="LLM parsing failed",
            )

    def _extract_capabilities(self, input_data: ClassificationInput) -> List[str]:
        """Extract capability tags from scan findings."""
        capabilities = []

        if input_data.env_vars_detected:
            capabilities.append("reads_env_vars")
        if input_data.network_calls_detected:
            capabilities.append("makes_network_calls")
        if input_data.file_operations:
            capabilities.append("accesses_filesystem")
        if any("database" in imp.lower() for imp in input_data.imports_detected):
            capabilities.append("requires_database")
        if any("http" in call.lower() for call in input_data.network_calls_detected):
            capabilities.append("makes_http_calls")

        return capabilities

    def _extract_protocols(self, input_data: ClassificationInput) -> List[str]:
        """Extract supported protocols from imports and env vars."""
        protocols = []

        # Common protocol patterns
        protocol_patterns = {
            "http": ["http", "https", "rest", "api"],
            "postgres": ["postgres", "psycopg", "pg_"],
            "redis": ["redis"],
            "mongodb": ["mongo", "pymongo"],
            "mysql": ["mysql", "pymysql"],
            "websocket": ["websocket", "ws"],
            "grpc": ["grpc"],
            "ssh": ["ssh", "paramiko"],
            "ftp": ["ftp"],
        }

        all_text = " ".join(
            [
                input_data.description,
                " ".join(input_data.imports_detected),
                " ".join(input_data.env_vars_detected),
            ]
        ).lower()

        for protocol, patterns in protocol_patterns.items():
            if any(pattern in all_text for pattern in patterns):
                protocols.append(protocol)

        return protocols

    def _extract_runtime(self, input_data: ClassificationInput) -> List[str]:
        """Extract runtime requirements."""
        runtimes = []

        # Detect based on ecosystem
        if input_data.ecosystem in ["skills", "mcp"]:
            # Most skills/MCPs are Python or Node.js
            if any(
                imp in ["requests", "fastapi", "flask", "django"]
                for imp in input_data.imports_detected
            ):
                runtimes.append("python")
            if any(
                imp in ["express", "axios", "node-fetch"]
                for imp in input_data.imports_detected
            ):
                runtimes.append("node")
        elif input_data.ecosystem == "pypi":
            runtimes.append("python")
        elif input_data.ecosystem == "npm":
            runtimes.append("node")

        # Docker detection
        if "docker" in input_data.description.lower():
            runtimes.append("docker")

        return runtimes


# ============================================================================
# BATCH CLASSIFICATION JOB
# ============================================================================


class BatchClassificationJob:
    """Azure Container Apps job for bulk classification."""

    def __init__(self, classifier: ForgeClassifier):
        self.classifier = classifier

    async def run_classification_batch(
        self, batch_size: int = 50, max_packages: Optional[int] = None
    ):
        """Run classification on unclassified and rescanned packages."""

        logger.info("Starting batch classification job...")

        # Get packages that need classification (new or rescanned)
        packages = await self._get_packages_needing_classification(max_packages)

        if not packages:
            logger.info("No packages need classification")
            return

        new_count = sum(1 for p in packages if p.get("_action") == "new")
        rescan_count = sum(1 for p in packages if p.get("_action") == "rescan")
        logger.info(
            f"Found {len(packages)} packages to classify "
            f"({new_count} new, {rescan_count} rescanned)"
        )

        classified_count = 0
        reclassified_count = 0
        error_count = 0

        for batch in self._chunked(packages, batch_size):
            batch_results = []

            for package_data in batch:
                try:
                    input_data = self._package_to_input(package_data)
                    result = await self.classifier.classify_package(input_data)

                    batch_results.append((package_data, result))

                    action = package_data.get("_action", "new")
                    if action == "rescan":
                        reclassified_count += 1
                        logger.info(
                            f"Reclassified {input_data.package_name}: "
                            f"{result.primary_category} "
                            f"(confidence: {result.confidence_score:.2f})"
                        )
                    else:
                        classified_count += 1
                        logger.info(
                            f"Classified {input_data.package_name}: "
                            f"{result.primary_category} "
                            f"(confidence: {result.confidence_score:.2f})"
                        )

                except Exception as e:
                    logger.error(
                        f"Classification failed for "
                        f"{package_data.get('package_name')}: {e}"
                    )
                    error_count += 1

            # Upsert results to database
            await self._save_classification_batch(batch_results)

            # Rate limiting (stay within Claude API limits)
            await asyncio.sleep(1.0)

        logger.info(
            f"Batch classification complete: {classified_count} new, "
            f"{reclassified_count} reclassified, {error_count} errors"
        )

        # Trigger stack generation after classification
        await self._trigger_stack_generation()

    async def _get_packages_needing_classification(
        self, max_packages: Optional[int]
    ) -> List[Dict]:
        """Fetch packages that need classification.

        Returns packages that either:
        1. Have never been classified (new)
        2. Have been rescanned since their last classification (rescan)
        """

        top_clause = f"TOP {max_packages}" if max_packages else ""

        query = f"""
        SELECT {top_clause}
               ps.id, ps.ecosystem, ps.package_name,
               ps.package_version, ps.findings_json, ps.metadata_json,
               ps.scanned_at,
               fc.classified_at,
               CASE
                   WHEN fc.id IS NULL THEN 'new'
                   ELSE 'rescan'
               END AS _action
        FROM public_scans ps
        LEFT JOIN forge_classification fc
            ON ps.ecosystem = fc.ecosystem
            AND ps.package_name = fc.package_name
            AND ps.package_version = fc.package_version
        WHERE fc.id IS NULL
           OR ps.scanned_at > fc.classified_at
        ORDER BY
            CASE WHEN fc.id IS NULL THEN 0 ELSE 1 END,
            ps.scanned_at DESC
        """

        return await db.execute_raw_sql(query)

    def _package_to_input(self, package_data: Dict) -> ClassificationInput:
        """Convert public_scans record to classification input."""

        ecosystem = package_data.get("ecosystem", "unknown")
        package_name = package_data.get("package_name", "")

        # Parse metadata and findings from public_scans JSON columns
        metadata = json.loads(package_data.get("metadata_json", "{}"))
        findings = json.loads(package_data.get("findings_json", "[]"))

        # Extract scan data from findings
        env_vars = []
        imports = []
        network_calls = []

        for finding in findings:
            snippet = finding.get("snippet", "").lower()
            phase = finding.get("phase", "")
            if phase == "credentials":
                if "env" in snippet:
                    env_vars.append(finding.get("snippet", ""))
            elif phase == "code_patterns":
                if "import" in snippet:
                    imports.append(finding.get("snippet", ""))
            elif phase == "network_exfil":
                network_calls.append(finding.get("snippet", ""))

        return ClassificationInput(
            package_name=package_name,
            ecosystem=ecosystem,
            description=metadata.get("description", ""),
            readme_content=metadata.get("readme", ""),
            env_vars_detected=env_vars,
            imports_detected=imports,
            network_calls_detected=network_calls,
            author=metadata.get("author"),
            repository_url=metadata.get("repository_url"),
            tags=metadata.get("tags", []),
        )

    async def _save_classification_batch(
        self, batch_results: List[Tuple[Dict, ClassificationResult]]
    ):
        """Save classification results to forge_classification table.

        Uses upsert so rescanned packages update their existing classification
        rather than failing on the unique constraint.
        """

        for package_data, result in batch_results:
            await db.upsert(
                "forge_classification",
                {
                    "ecosystem": package_data.get("ecosystem", "unknown"),
                    "package_name": package_data.get("package_name", ""),
                    "package_version": package_data.get("package_version", ""),
                    "category": result.primary_category,
                    "subcategory": (
                        result.secondary_categories[0]
                        if result.secondary_categories
                        else ""
                    ),
                    "confidence_score": result.confidence_score,
                    "description_summary": result.reasoning[:500],
                    "environment_vars": json.dumps(result.env_vars_required),
                    "network_protocols": json.dumps(result.protocols_supported),
                    "file_patterns": json.dumps([]),
                    "import_patterns": json.dumps(result.runtime_requirements),
                    "risk_indicators": json.dumps(result.capability_tags),
                    "classifier_version": "1.0",
                    "metadata_json": json.dumps({}),
                },
                conflict_columns=["ecosystem", "package_name", "package_version"],
            )

    async def _trigger_stack_generation(self):
        """Trigger stack matching after classification."""
        # This would call the stack matching job
        logger.info("Triggering stack generation...")

    def _chunked(self, lst: List, chunk_size: int):
        """Split list into chunks."""
        for i in range(0, len(lst), chunk_size):
            yield lst[i : i + chunk_size]


# ============================================================================
# AZURE CONTAINER APPS JOB ENTRY POINT
# ============================================================================


async def main():
    """Main entry point for Azure Container Apps scheduled job.

    Runs classification in a loop with a configurable interval.
    On each cycle, picks up new scans and rescanned packages only.

    Environment variables:
        ANTHROPIC_API_KEY              — Required. Claude API key.
        CLASSIFICATION_BATCH_SIZE      — Packages per batch (default 50).
        CLASSIFICATION_MAX_PACKAGES    — Max packages per cycle (default 1000).
        CLASSIFICATION_INTERVAL_SECONDS — Seconds between cycles (default 3600).
                                          Set to 0 for a single run (no loop).
    """

    import os

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Configuration from environment variables
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
    batch_size = int(os.getenv("CLASSIFICATION_BATCH_SIZE", "50"))
    max_packages = int(os.getenv("CLASSIFICATION_MAX_PACKAGES", "1000"))
    interval = int(os.getenv("CLASSIFICATION_INTERVAL_SECONDS", "3600"))

    if not anthropic_api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable required")

    # Initialize classifier and database
    classifier = ForgeClassifier(anthropic_api_key)
    await db.connect()

    try:
        job = BatchClassificationJob(classifier)

        while True:
            try:
                await job.run_classification_batch(
                    batch_size=batch_size, max_packages=max_packages
                )
                logger.info("Classification cycle completed successfully")
            except Exception as e:
                logger.error(f"Classification cycle failed: {e}")

            if interval <= 0:
                # Single run mode
                break

            logger.info(f"Sleeping {interval}s until next classification cycle...")
            await asyncio.sleep(interval)
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
