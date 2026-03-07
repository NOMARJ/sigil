#!/usr/bin/env python3
"""
Test Forge Enrichment Worker

This tests the forge enrichment worker logic without requiring a database connection.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from bot.worker.forge_enrichment import ForgeEnrichmentWorker


def test_finding_mapping():
    """Test mapping findings to 8 scan phases."""
    worker = ForgeEnrichmentWorker()

    # Test findings with different patterns
    test_findings = [
        {
            "rule": "install_script_detected",
            "severity": "high",
            "snippet": "setup.py install",
            "description": "Install script found",
        },
        {
            "rule": "eval_usage",
            "severity": "critical",
            "snippet": "eval(user_input)",
            "description": "Dangerous eval usage",
        },
        {
            "rule": "network_request",
            "severity": "medium",
            "snippet": "fetch('https://api.example.com')",
            "description": "External API call",
        },
        {
            "rule": "environment_access",
            "severity": "low",
            "snippet": "process.env.API_KEY",
            "description": "Environment variable access",
        },
        {
            "rule": "base64_encoded",
            "severity": "medium",
            "snippet": "atob(encoded_data)",
            "description": "Base64 decoding detected",
        },
        {
            "rule": "git_history",
            "severity": "info",
            "snippet": "single commit",
            "description": "Limited git history",
        },
        {
            "rule": "prompt_injection",
            "severity": "high",
            "snippet": "ignore previous instructions",
            "description": "Potential prompt injection",
        },
        {
            "rule": "skill_tampering",
            "severity": "medium",
            "snippet": "skill.yaml modified",
            "description": "Skill configuration modified",
        },
    ]

    # Map findings to phases
    scan_phases = worker._map_to_eight_phases(test_findings)

    # Verify we have all 8 phases
    assert len(scan_phases) == 8, f"Expected 8 phases, got {len(scan_phases)}"

    # Check that phases have correct structure
    for i, phase in enumerate(scan_phases):
        assert "phase" in phase, f"Phase {i} missing 'phase' field"
        assert "name" in phase, f"Phase {i} missing 'name' field"
        assert "weight" in phase, f"Phase {i} missing 'weight' field"
        assert "score" in phase, f"Phase {i} missing 'score' field"
        assert "risk_level" in phase, f"Phase {i} missing 'risk_level' field"
        assert "findings" in phase, f"Phase {i} missing 'findings' field"
        assert phase["phase"] == i + 1, f"Phase {i} has wrong phase number"

    # Check that findings were mapped correctly
    install_hooks_phase = scan_phases[0]  # Phase 1
    assert len(install_hooks_phase["findings"]) > 0, (
        "Install hooks phase should have findings"
    )
    assert install_hooks_phase["risk_level"] != "clean", (
        "Install hooks should be marked risky"
    )

    code_patterns_phase = scan_phases[1]  # Phase 2
    assert len(code_patterns_phase["findings"]) > 0, (
        "Code patterns phase should have findings"
    )
    assert code_patterns_phase["risk_level"] != "clean", (
        "Code patterns should be marked risky"
    )

    prompt_injection_phase = scan_phases[6]  # Phase 7
    assert len(prompt_injection_phase["findings"]) > 0, (
        "Prompt injection phase should have findings"
    )

    print("✅ Finding mapping test passed")


def test_trust_score_calculation():
    """Test trust score calculation from scan phases."""
    worker = ForgeEnrichmentWorker()

    # Test with clean phases (should get high trust score)
    clean_phases = [
        {
            "phase": 1,
            "name": "Install Hooks",
            "weight": 10,
            "score": 10,
            "risk_level": "clean",
        },
        {
            "phase": 2,
            "name": "Code Patterns",
            "weight": 5,
            "score": 5,
            "risk_level": "clean",
        },
        {
            "phase": 3,
            "name": "Network / Exfil",
            "weight": 3,
            "score": 3,
            "risk_level": "clean",
        },
        {
            "phase": 4,
            "name": "Credentials",
            "weight": 2,
            "score": 2,
            "risk_level": "clean",
        },
        {
            "phase": 5,
            "name": "Obfuscation",
            "weight": 5,
            "score": 5,
            "risk_level": "clean",
        },
        {
            "phase": 6,
            "name": "Provenance",
            "weight": 3,
            "score": 3,
            "risk_level": "clean",
        },
        {
            "phase": 7,
            "name": "Prompt Injection",
            "weight": 10,
            "score": 10,
            "risk_level": "clean",
        },
        {
            "phase": 8,
            "name": "Skill Security",
            "weight": 5,
            "score": 5,
            "risk_level": "clean",
        },
    ]

    clean_trust_score = worker._calculate_trust_score(clean_phases)
    assert 90 <= clean_trust_score <= 100, (
        f"Clean phases should have high trust score, got {clean_trust_score}"
    )

    # Test with risky phases (should get lower trust score)
    risky_phases = [
        {
            "phase": 1,
            "name": "Install Hooks",
            "weight": 10,
            "score": 5,
            "risk_level": "high",
        },  # 50% score
        {
            "phase": 2,
            "name": "Code Patterns",
            "weight": 5,
            "score": 2,
            "risk_level": "medium",
        },  # 40% score
        {
            "phase": 3,
            "name": "Network / Exfil",
            "weight": 3,
            "score": 3,
            "risk_level": "clean",
        },
        {
            "phase": 4,
            "name": "Credentials",
            "weight": 2,
            "score": 2,
            "risk_level": "clean",
        },
        {
            "phase": 5,
            "name": "Obfuscation",
            "weight": 5,
            "score": 5,
            "risk_level": "clean",
        },
        {
            "phase": 6,
            "name": "Provenance",
            "weight": 3,
            "score": 3,
            "risk_level": "clean",
        },
        {
            "phase": 7,
            "name": "Prompt Injection",
            "weight": 10,
            "score": 10,
            "risk_level": "clean",
        },
        {
            "phase": 8,
            "name": "Skill Security",
            "weight": 5,
            "score": 5,
            "risk_level": "clean",
        },
    ]

    risky_trust_score = worker._calculate_trust_score(risky_phases)
    assert risky_trust_score < clean_trust_score, (
        "Risky phases should have lower trust score than clean"
    )

    print("✅ Trust score calculation test passed")


def test_capability_extraction():
    """Test capability extraction from findings and metadata."""
    worker = ForgeEnrichmentWorker()

    findings = [
        {
            "snippet": "fetch('https://api.example.com')",
            "description": "Network request",
        },
        {"snippet": "fs.readFile('/path/to/file')", "description": "File access"},
        {"snippet": "writeFile('output.txt')", "description": "File write"},
    ]

    metadata = {
        "description": "An AI assistant tool that uses GPT models to help with coding"
    }

    capabilities = worker._extract_capabilities(findings, metadata)

    # Should detect network, file, and AI capabilities
    cap_types = [cap["type"] for cap in capabilities]
    assert "network" in cap_types, "Should detect network capability"
    assert "file" in cap_types, "Should detect file capability"
    assert "ai" in cap_types, "Should detect AI capability from description"

    print("✅ Capability extraction test passed")


def test_environment_variable_extraction():
    """Test environment variable extraction."""
    worker = ForgeEnrichmentWorker()

    findings = [
        {"snippet": "process.env.ANTHROPIC_API_KEY", "description": "API key access"},
        {"snippet": "os.environ['DATABASE_URL']", "description": "Database URL"},
        {
            "snippet": "const token = process.env.GITHUB_TOKEN",
            "description": "GitHub token",
        },
    ]

    env_vars = worker._extract_environment_variables(findings, {})

    expected_vars = ["ANTHROPIC_API_KEY", "DATABASE_URL", "GITHUB_TOKEN"]
    for var in expected_vars:
        assert var in env_vars, f"Should extract {var}"

    print("✅ Environment variable extraction test passed")


def test_category_determination():
    """Test category determination logic."""
    worker = ForgeEnrichmentWorker()

    # Test database tool
    db_category = worker._determine_category(
        "postgres-connector", "A PostgreSQL database connector"
    )
    assert db_category == "database_connectors", (
        f"Expected database_connectors, got {db_category}"
    )

    # Test AI tool
    ai_category = worker._determine_category(
        "gpt-helper", "An AI assistant using GPT models"
    )
    assert ai_category == "ai_llm_tools", f"Expected ai_llm_tools, got {ai_category}"

    # Test API tool
    api_category = worker._determine_category(
        "stripe-api", "Stripe payment API integration"
    )
    assert api_category == "api_integrations", (
        f"Expected api_integrations, got {api_category}"
    )

    print("✅ Category determination test passed")


def test_install_command_generation():
    """Test install command generation."""
    worker = ForgeEnrichmentWorker()

    # Test different ecosystems
    assert (
        worker._generate_install_command("skills", "test-skill")
        == "npx skills.sh add test-skill"
    )
    assert worker._generate_install_command("mcp", "test-mcp") == "npm install test-mcp"
    assert (
        worker._generate_install_command("npm", "test-package")
        == "npm install test-package"
    )
    assert (
        worker._generate_install_command("pypi", "test-package")
        == "pip install test-package"
    )

    print("✅ Install command generation test passed")


def test_security_finding_generation():
    """Test security finding generation."""
    worker = ForgeEnrichmentWorker()

    findings = [
        {
            "rule": "eval_detected",
            "severity": "critical",
            "description": "Dangerous eval usage",
        },
        {
            "rule": "network_call",
            "severity": "medium",
            "description": "External network request",
        },
        {
            "rule": "info_log",
            "severity": "info",
            "description": "Informational finding",
        },
    ]

    security_findings = worker._generate_security_findings(findings)

    # Should only include critical and medium findings, not info
    assert len(security_findings) == 2, (
        f"Expected 2 security findings, got {len(security_findings)}"
    )

    for finding in security_findings:
        assert "id" in finding
        assert "severity" in finding
        assert "category" in finding
        assert "description" in finding
        assert "impact" in finding
        assert "recommendation" in finding

    print("✅ Security finding generation test passed")


def test_enriched_data_generation():
    """Test the complete enriched data generation."""
    worker = ForgeEnrichmentWorker()

    # Mock scan record

    findings = [
        {
            "rule": "network_request",
            "severity": "low",
            "snippet": "fetch('/api')",
            "description": "API call",
        }
    ]

    metadata = {
        "description": "A test package for demonstration",
        "author": "test-author",
        "repository": {"url": "https://github.com/test/test-package"},
    }

    # This would normally be async, but we can test the synchronous parts
    # enriched_data = await worker._generate_enriched_data(
    #     "npm", "test-package", "1.0.0", scan_record, findings, metadata
    # )

    # Test individual components
    phases = worker._map_to_eight_phases(findings)
    assert len(phases) == 8

    trust_score = worker._calculate_trust_score(phases)
    assert 0 <= trust_score <= 100

    capabilities = worker._extract_capabilities(findings, metadata)
    assert isinstance(capabilities, list)

    env_vars = worker._extract_environment_variables(findings, metadata)
    assert isinstance(env_vars, list)

    print("✅ Enriched data generation test passed")


def run_all_tests():
    """Run all tests."""
    tests = [
        test_finding_mapping,
        test_trust_score_calculation,
        test_capability_extraction,
        test_environment_variable_extraction,
        test_category_determination,
        test_install_command_generation,
        test_security_finding_generation,
        test_enriched_data_generation,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
            failed += 1

    print(f"\n📊 Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All tests passed!")
        return True
    else:
        print("💥 Some tests failed!")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
