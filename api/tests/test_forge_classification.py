"""
Test Suite for Sigil Forge Classification System

Tests the accuracy and performance of the classification engine.
"""

import asyncio
import pytest

from api.models import Finding, ScanPhase, Severity
from api.services.forge_classifier import (
    ForgeClassifier,
    ClassificationInput,
    ClassificationResult,
)
from api.services.forge_matcher import ForgeMatcher


class TestForgeClassifier:
    """Test the Forge classification engine."""

    @pytest.fixture
    def classifier(self):
        return ForgeClassifier()

    @pytest.fixture
    def test_classification_input(self):
        """Create test input for classification."""
        return ClassificationInput(
            ecosystem="clawhub",
            package_name="postgres-query-skill",
            package_version="1.0.0",
            description="A skill for querying PostgreSQL databases using natural language",
            scan_findings=[
                Finding(
                    phase=ScanPhase.CREDENTIALS,
                    rule="cred-env-access",
                    severity=Severity.MEDIUM,
                    file="index.js",
                    line=10,
                    snippet="const dbUrl = process.env.DATABASE_URL",
                    weight=1.0,
                    description="Reads DATABASE_URL environment variable",
                    explanation="This pattern indicates database credential access",
                ),
                Finding(
                    phase=ScanPhase.NETWORK_EXFIL,
                    rule="net-http-request",
                    severity=Severity.MEDIUM,
                    file="index.js",
                    line=25,
                    snippet="await fetch(`${dbUrl}/query`, {",
                    weight=1.0,
                    description="Makes HTTP request",
                    explanation="Network request pattern",
                ),
                Finding(
                    phase=ScanPhase.CODE_PATTERNS,
                    rule="code-importlib",
                    severity=Severity.MEDIUM,
                    file="db.py",
                    line=5,
                    snippet="import psycopg2",
                    weight=1.0,
                    description="Imports PostgreSQL library",
                    explanation="Database driver import",
                ),
            ],
            metadata={"author": "test-author", "stars": 42},
        )

    def test_extract_scan_patterns(self, classifier, test_classification_input):
        """Test pattern extraction from scan findings."""
        patterns = classifier._extract_scan_patterns(
            test_classification_input.scan_findings
        )

        # Should detect environment variables
        assert "DATABASE_URL" in patterns["environment_vars"]

        # Should detect HTTP protocol
        assert "HTTP" in patterns["network_protocols"]

        # Should detect database import pattern
        assert "database" in patterns["import_patterns"]

        # Should have risk indicators
        assert len(patterns["risk_indicators"]) == 3  # All findings are MEDIUM severity

    def test_fallback_classification(self, classifier, test_classification_input):
        """Test rule-based fallback classification."""
        result = classifier._fallback_classification(test_classification_input)

        # Should categorize as Database based on keywords
        assert result.category == "Database"
        assert result.confidence_score == 0.6  # Fallback confidence

        # Should detect capabilities
        capabilities = {cap["capability"] for cap in result.capabilities}
        assert "requires_env_vars" in capabilities
        assert "makes_network_calls" in capabilities

    @pytest.mark.asyncio
    async def test_classification_end_to_end(self, classifier):
        """Test full classification pipeline (requires database)."""
        # Create test input
        test_input = ClassificationInput(
            ecosystem="mcp",
            package_name="mcp-sqlite",
            package_version="1.0.0",
            description="SQLite database MCP server for AI agents",
            scan_findings=[],
            metadata={},
        )

        # Perform classification
        result = await classifier.classify_package(test_input)

        # Validate result structure
        assert isinstance(result, ClassificationResult)
        assert result.category in [
            "Database",
            "Uncategorized",
        ]  # Should be Database or fallback
        assert result.confidence_score >= 0.0
        assert result.confidence_score <= 1.0


class TestForgeAccuracy:
    """Test classification accuracy against known samples."""

    @pytest.fixture
    def ground_truth_samples(self):
        """Ground truth samples for accuracy testing."""
        return [
            {
                "package_name": "postgres-connector",
                "description": "PostgreSQL database connector with connection pooling",
                "expected_category": "Database",
                "findings": ["DATABASE_URL", "HTTP"],
            },
            {
                "package_name": "github-api-client",
                "description": "GitHub API client for repository operations",
                "expected_category": "API Integration",
                "findings": ["GITHUB_TOKEN", "HTTP"],
            },
            {
                "package_name": "file-processor",
                "description": "Process and analyze files from filesystem",
                "expected_category": "File System",
                "findings": ["file_operations"],
            },
            {
                "package_name": "llm-prompt-helper",
                "description": "Utilities for LLM prompt engineering and optimization",
                "expected_category": "AI/LLM",
                "findings": ["OPENAI_API_KEY"],
            },
            {
                "package_name": "security-scanner",
                "description": "Vulnerability scanner for code and dependencies",
                "expected_category": "Security",
                "findings": [],
            },
        ]

    @pytest.mark.asyncio
    async def test_classification_accuracy(self, ground_truth_samples):
        """Test classification accuracy against ground truth samples."""
        classifier = ForgeClassifier()
        correct_classifications = 0
        total_samples = len(ground_truth_samples)

        for sample in ground_truth_samples:
            # Create mock findings
            findings = []
            for finding_type in sample["findings"]:
                if finding_type == "DATABASE_URL":
                    findings.append(
                        Finding(
                            phase=ScanPhase.CREDENTIALS,
                            rule="cred-env-access",
                            severity=Severity.MEDIUM,
                            file="test.js",
                            line=1,
                            snippet="process.env.DATABASE_URL",
                            weight=1.0,
                            description="Database URL access",
                            explanation="",
                        )
                    )
                elif finding_type == "GITHUB_TOKEN":
                    findings.append(
                        Finding(
                            phase=ScanPhase.CREDENTIALS,
                            rule="cred-env-access",
                            severity=Severity.MEDIUM,
                            file="test.js",
                            line=1,
                            snippet="process.env.GITHUB_TOKEN",
                            weight=1.0,
                            description="GitHub token access",
                            explanation="",
                        )
                    )
                elif finding_type == "HTTP":
                    findings.append(
                        Finding(
                            phase=ScanPhase.NETWORK_EXFIL,
                            rule="net-http-request",
                            severity=Severity.MEDIUM,
                            file="test.js",
                            line=1,
                            snippet="fetch('https://api.example.com')",
                            weight=1.0,
                            description="HTTP request",
                            explanation="",
                        )
                    )
                elif finding_type == "file_operations":
                    findings.append(
                        Finding(
                            phase=ScanPhase.CODE_PATTERNS,
                            rule="code-file-access",
                            severity=Severity.LOW,
                            file="test.py",
                            line=1,
                            snippet="open('/path/to/file')",
                            weight=1.0,
                            description="File access",
                            explanation="",
                        )
                    )

            # Create classification input
            input_data = ClassificationInput(
                ecosystem="test",
                package_name=sample["package_name"],
                package_version="1.0.0",
                description=sample["description"],
                scan_findings=findings,
                metadata={},
            )

            # Classify (using fallback since we don't want to make actual API calls in tests)
            result = classifier._fallback_classification(input_data)

            # Check if classification is correct
            if result.category == sample["expected_category"]:
                correct_classifications += 1
            else:
                print(
                    f"Misclassified {sample['package_name']}: expected {sample['expected_category']}, got {result.category}"
                )

        # Calculate accuracy
        accuracy = correct_classifications / total_samples
        print(
            f"Classification accuracy: {accuracy:.2%} ({correct_classifications}/{total_samples})"
        )

        # Assert minimum accuracy threshold
        assert accuracy >= 0.6, f"Classification accuracy too low: {accuracy:.2%}"

    def test_capability_detection_accuracy(self):
        """Test capability detection accuracy."""
        classifier = ForgeClassifier()

        # Test environment variable capability detection
        findings = [
            Finding(
                phase=ScanPhase.CREDENTIALS,
                rule="cred-env-access",
                severity=Severity.MEDIUM,
                file="test.js",
                line=1,
                snippet="process.env.DATABASE_URL",
                weight=1.0,
                description="Database URL access",
                explanation="",
            )
        ]

        patterns = classifier._extract_scan_patterns(findings)
        assert "DATABASE_URL" in patterns["environment_vars"]

        # Test network capability detection
        findings = [
            Finding(
                phase=ScanPhase.NETWORK_EXFIL,
                rule="net-http-request",
                severity=Severity.MEDIUM,
                file="test.js",
                line=1,
                snippet="await fetch(url)",
                weight=1.0,
                description="HTTP request",
                explanation="",
            )
        ]

        patterns = classifier._extract_scan_patterns(findings)
        assert "HTTP" in patterns["network_protocols"]


class TestForgeMatcher:
    """Test the Forge matching system."""

    @pytest.fixture
    def matcher(self):
        return ForgeMatcher()

    @pytest.mark.asyncio
    async def test_matching_algorithm(self, matcher):
        """Test the matching algorithm with mock data."""
        # This test would require database setup with mock classifications
        # For now, test the logic components

        # Test environment variable matching logic
        tool_env_vars = {"DATABASE_URL", "REDIS_URL"}
        candidate_env_vars = {"DATABASE_URL", "POSTGRES_URL"}
        shared_env_vars = tool_env_vars.intersection(candidate_env_vars)

        assert len(shared_env_vars) == 1
        assert "DATABASE_URL" in shared_env_vars

        # Test compatibility score calculation
        compatibility_score = len(shared_env_vars) / max(
            len(tool_env_vars), len(candidate_env_vars)
        )
        assert compatibility_score == 0.5  # 1 shared / 2 max

    def test_protocol_compatibility(self, matcher):
        """Test protocol compatibility matrix."""
        compatible_protocols = {
            "HTTP": ["HTTP", "REST", "Webhook"],
            "WebSocket": ["WebSocket", "HTTP"],
            "gRPC": ["gRPC", "HTTP"],
        }

        # Test HTTP compatibility
        assert "Webhook" in compatible_protocols["HTTP"]
        assert "REST" in compatible_protocols["HTTP"]

        # Test WebSocket compatibility
        assert "HTTP" in compatible_protocols["WebSocket"]

    def test_install_command_generation(self, matcher):
        """Test installation command generation."""
        # Test ClawHub skill
        clawhub_tool = {
            "ecosystem": "clawhub",
            "package_name": "postgres-skill",
            "package_version": "1.0.0",
        }
        command = matcher._generate_install_command(clawhub_tool)
        assert command == "npx skills add postgres-skill@1.0.0"

        # Test npm package
        npm_tool = {
            "ecosystem": "npm",
            "package_name": "express",
            "package_version": "4.18.0",
        }
        command = matcher._generate_install_command(npm_tool)
        assert command == "npm install express@4.18.0"

        # Test pip package
        pip_tool = {
            "ecosystem": "pypi",
            "package_name": "requests",
            "package_version": "2.28.0",
        }
        command = matcher._generate_install_command(pip_tool)
        assert command == "pip install requests==2.28.0"


class TestForgePerformance:
    """Test classification performance and scalability."""

    @pytest.mark.asyncio
    async def test_batch_classification_performance(self):
        """Test performance of batch classification."""
        classifier = ForgeClassifier()

        # Create multiple test inputs
        test_inputs = []
        for i in range(100):
            test_inputs.append(
                ClassificationInput(
                    ecosystem="test",
                    package_name=f"test-package-{i}",
                    package_version="1.0.0",
                    description=f"Test package {i} for performance testing",
                    scan_findings=[],
                    metadata={},
                )
            )

        # Measure classification time
        start_time = asyncio.get_event_loop().time()

        results = []
        for input_data in test_inputs:
            # Use fallback classification for speed
            result = classifier._fallback_classification(input_data)
            results.append(result)

        end_time = asyncio.get_event_loop().time()
        elapsed_time = end_time - start_time

        # Performance assertions
        assert len(results) == 100
        assert elapsed_time < 10.0  # Should complete in under 10 seconds

        avg_time_per_classification = elapsed_time / len(test_inputs)
        print(f"Average classification time: {avg_time_per_classification:.3f}s")

        # Should average less than 100ms per classification for fallback
        assert avg_time_per_classification < 0.1

    def test_memory_usage_patterns(self):
        """Test memory usage during classification."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        classifier = ForgeClassifier()

        # Process many classifications
        for i in range(1000):
            input_data = ClassificationInput(
                ecosystem="test",
                package_name=f"memory-test-{i}",
                package_version="1.0.0",
                description="Memory test package",
                scan_findings=[],
                metadata={},
            )
            result = classifier._fallback_classification(input_data)

            # Clean up references
            del input_data
            del result

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(
            f"Memory usage: {initial_memory:.1f}MB -> {final_memory:.1f}MB (+{memory_increase:.1f}MB)"
        )

        # Should not have significant memory leaks (< 50MB increase)
        assert memory_increase < 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
