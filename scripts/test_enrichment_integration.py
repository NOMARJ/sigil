#!/usr/bin/env python3
"""
Test Forge Enrichment Integration

This script tests the enrichment worker with sample data to verify
the complete data flow without requiring a real database.
"""

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from bot.worker.forge_enrichment import ForgeEnrichmentWorker


def test_complete_enrichment_flow():
    """Test the complete enrichment flow with sample data."""
    print("🧪 Testing complete enrichment flow")

    worker = ForgeEnrichmentWorker()

    # Sample scan record (simulates data from public_scans)
    scan_record = {
        "id": "test-123",
        "ecosystem": "skills",
        "package_name": "claude-code-assistant",
        "package_version": "1.2.0",
        "risk_score": 12,
        "verdict": "LOW_RISK",
        "scanned_at": "2026-03-06T10:00:00Z",
    }

    # Sample findings (simulates findings_json from public_scans)
    findings = [
        {
            "rule": "network_request_detected",
            "severity": "medium",
            "snippet": "fetch('https://api.anthropic.com/v1/messages')",
            "description": "External API call to Anthropic API detected",
            "phase": "network_exfil",
        },
        {
            "rule": "environment_variable_access",
            "severity": "low",
            "snippet": "process.env.ANTHROPIC_API_KEY",
            "description": "Access to ANTHROPIC_API_KEY environment variable",
            "phase": "credentials",
        },
        {
            "rule": "file_write_operation",
            "severity": "low",
            "snippet": "fs.writeFileSync('./output.txt', content)",
            "description": "File write operation detected",
            "phase": "file_access",
        },
    ]

    # Sample metadata (simulates metadata_json from public_scans)
    metadata = {
        "description": "A Claude Code skill that provides AI-powered code assistance and debugging capabilities",
        "author": "claude-team",
        "license": "MIT",
        "repository": {"url": "https://github.com/anthropic/claude-code-assistant"},
        "keywords": ["ai", "coding", "assistant", "claude"],
        "downloads": 15420,
        "stars": 342,
    }

    print("📋 Sample Data:")
    print(
        f"  Package: {scan_record['ecosystem']}/{scan_record['package_name']} v{scan_record['package_version']}"
    )
    print(f"  Findings: {len(findings)} detected")
    print(f"  Risk Score: {scan_record['risk_score']}")
    print(f"  Verdict: {scan_record['verdict']}")

    print("\n⚙️ Processing enrichment...")

    try:
        # Test the enrichment process (excluding async database operations)
        enriched_data = worker._generate_enriched_data_sync(
            scan_record["ecosystem"],
            scan_record["package_name"],
            scan_record["package_version"],
            scan_record,
            findings,
            metadata,
        )

        print("✅ Enrichment completed successfully!")

        # Validate enriched data structure
        required_fields = [
            "id",
            "slug",
            "name",
            "ecosystem",
            "category",
            "description",
            "trust_score",
            "scan_phases",
            "security_findings",
            "capabilities",
            "environment_variables",
            "file_access",
            "network_connectivity",
            "usage_examples",
            "security_report",
        ]

        missing_fields = []
        for field in required_fields:
            if field not in enriched_data:
                missing_fields.append(field)

        if missing_fields:
            print(f"❌ Missing required fields: {missing_fields}")
            return False

        # Validate scan phases (should have all 8 phases)
        scan_phases = enriched_data["scan_phases"]
        if len(scan_phases) != 8:
            print(f"❌ Expected 8 scan phases, got {len(scan_phases)}")
            return False

        # Validate trust score
        trust_score = enriched_data["trust_score"]
        if not (0 <= trust_score <= 100):
            print(f"❌ Invalid trust score: {trust_score} (should be 0-100)")
            return False

        # Print summary
        print("\n📊 Enrichment Results:")
        print(f"  Tool ID: {enriched_data['id']}")
        print(f"  Category: {enriched_data['category']}")
        print(f"  Trust Score: {enriched_data['trust_score']}/100")
        print(f"  Scan Phases: {len(enriched_data['scan_phases'])} phases")
        print(
            f"  Security Findings: {len(enriched_data['security_findings'])} findings"
        )
        print(f"  Capabilities: {len(enriched_data['capabilities'])} capabilities")
        print(
            f"  Environment Variables: {len(enriched_data['environment_variables'])} vars"
        )
        print(f"  Usage Examples: {len(enriched_data['usage_examples'])} examples")

        # Show sample scan phase results
        print("\n🔍 Sample Scan Phase Results:")
        for phase in enriched_data["scan_phases"][:3]:
            print(
                f"  Phase {phase['phase']}: {phase['name']} - {phase['risk_level']} ({phase['score']}/{phase['weight']})"
            )

        # Show capabilities
        if enriched_data["capabilities"]:
            print("\n⚡ Detected Capabilities:")
            for cap in enriched_data["capabilities"]:
                print(f"  {cap['type']}: {cap['description']}")

        # Show environment variables
        if enriched_data["environment_variables"]:
            print(
                f"\n🔧 Environment Variables: {', '.join(enriched_data['environment_variables'])}"
            )

        print("\n🎉 Integration test completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Enrichment failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Add the sync method to worker for testing
    def _generate_enriched_data_sync(
        self, ecosystem, package_name, package_version, scan_record, findings, metadata
    ):
        """Synchronous version of _generate_enriched_data for testing."""
        from datetime import datetime, timezone

        # Generate deterministic UUID for tool
        tool_uuid = self._generate_tool_uuid(ecosystem, package_name)

        # Map findings to 8-phase scan results
        scan_phases = self._map_to_eight_phases(findings)

        # Calculate trust score from phases
        trust_score = self._calculate_trust_score(scan_phases)

        # Extract capabilities
        capabilities = self._extract_capabilities(findings, metadata)

        # Generate security findings
        security_findings = self._generate_security_findings(findings)

        # Extract environment variables
        environment_variables = self._extract_environment_variables(findings, metadata)

        # Extract network connectivity
        network_connectivity = self._extract_network_connectivity(findings, metadata)

        # Extract file access patterns
        file_access = self._extract_file_access_patterns(findings, metadata)

        # Generate usage examples
        usage_examples = self._generate_usage_examples(
            ecosystem, package_name, metadata
        )

        # Generate security report
        security_report = self._generate_security_report(scan_phases, security_findings)

        # Build the enriched data structure (simplified for testing)
        return {
            "id": tool_uuid,
            "slug": self._generate_tool_slug(package_name),
            "name": package_name,
            "ecosystem": ecosystem,
            "category": self._determine_category(
                package_name, metadata.get("description", "")
            ),
            "description": metadata.get(
                "description", f"A {ecosystem} tool for AI agents"
            ),
            "tags": self._extract_tags(metadata, package_name),
            "license": metadata.get("license", ""),
            "author": metadata.get("author", ""),
            "version": package_version or "latest",
            "created_at": scan_record.get("scanned_at"),
            "last_updated": scan_record.get("scanned_at"),
            "downloads": metadata.get("downloads", 0),
            "github_stars": metadata.get("stars", 0),
            "github_forks": metadata.get("forks", 0),
            "install_command": self._generate_install_command(ecosystem, package_name),
            "package_url": self._generate_package_url(ecosystem, package_name),
            "github_url": metadata.get("repository", {}).get("url"),
            "repository_url": metadata.get("repository", {}).get("url"),
            "documentation_url": metadata.get("documentation_url"),
            "trust_score": trust_score,
            "last_scanned": scan_record.get("scanned_at"),
            "last_analyzed": scan_record.get("scanned_at"),
            "scan_phases": scan_phases,
            "security_findings": security_findings,
            "capabilities": capabilities,
            "environment_variables": environment_variables,
            "protocols": ["https", "http"],
            "file_access": file_access,
            "network_connectivity": network_connectivity,
            "compatible_tools": [],
            "conflicts_with": [],
            "usage_examples": usage_examples,
            "related_tools": [],  # Simplified for testing
            "security_report": security_report,
        }

    # Monkey patch the sync method for testing
    ForgeEnrichmentWorker._generate_enriched_data_sync = _generate_enriched_data_sync

    success = test_complete_enrichment_flow()
    sys.exit(0 if success else 1)
