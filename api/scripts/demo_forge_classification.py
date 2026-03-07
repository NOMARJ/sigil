#!/usr/bin/env python3
"""
Sigil Forge Classification Engine — Demo Script

This script demonstrates the classification engine by:
1. Classifying sample packages
2. Generating matches between tools
3. Creating Forge Stacks for common use cases
4. Showing API responses in different formats

Run with: python demo_forge_classification.py
"""

import asyncio
import json
import sys
from datetime import datetime, timezone

# Add parent directory to path to import API modules
sys.path.append("/Users/reecefrazier/CascadeProjects/sigil")

from database import db
from models import Finding, ScanPhase, Severity
from services.forge_classifier import forge_classifier, ClassificationInput
from services.forge_matcher import forge_matcher

# Demo data
DEMO_PACKAGES = [
    {
        "ecosystem": "clawhub",
        "package_name": "postgres-query-skill",
        "package_version": "1.0.0",
        "description": "A skill for querying PostgreSQL databases using natural language. Supports complex queries, joins, and data analysis.",
        "findings": [
            {"type": "env_var", "value": "DATABASE_URL"},
            {"type": "network", "value": "HTTP"},
            {"type": "import", "value": "psycopg2"},
        ],
    },
    {
        "ecosystem": "mcp",
        "package_name": "mcp-postgres",
        "package_version": "2.1.0",
        "description": "PostgreSQL MCP server providing database connectivity for AI agents",
        "findings": [
            {"type": "env_var", "value": "DATABASE_URL"},
            {"type": "env_var", "value": "POSTGRES_HOST"},
            {"type": "network", "value": "TCP"},
        ],
    },
    {
        "ecosystem": "clawhub",
        "package_name": "github-pr-analyzer",
        "package_version": "0.8.2",
        "description": "Analyzes GitHub pull requests for code quality, security issues, and best practices",
        "findings": [
            {"type": "env_var", "value": "GITHUB_TOKEN"},
            {"type": "network", "value": "HTTP"},
            {"type": "network", "value": "Webhook"},
        ],
    },
    {
        "ecosystem": "mcp",
        "package_name": "mcp-filesystem",
        "package_version": "1.5.1",
        "description": "File system operations for AI agents - read, write, search files and directories",
        "findings": [
            {"type": "file_op", "value": "read_files"},
            {"type": "file_op", "value": "write_files"},
        ],
    },
    {
        "ecosystem": "clawhub",
        "package_name": "ai-prompt-optimizer",
        "package_version": "2.0.0",
        "description": "Optimizes LLM prompts for better performance and cost efficiency. Supports GPT, Claude, and other models.",
        "findings": [
            {"type": "env_var", "value": "OPENAI_API_KEY"},
            {"type": "env_var", "value": "ANTHROPIC_API_KEY"},
            {"type": "network", "value": "HTTP"},
        ],
    },
]


def create_mock_findings(finding_specs: list[dict[str, str]]) -> list[Finding]:
    """Create mock Finding objects from specifications."""
    findings = []

    for spec in finding_specs:
        if spec["type"] == "env_var":
            findings.append(
                Finding(
                    phase=ScanPhase.CREDENTIALS,
                    rule="cred-env-access",
                    severity=Severity.MEDIUM,
                    file="index.js",
                    line=10,
                    snippet=f"process.env.{spec['value']}",
                    weight=1.0,
                    description=f"Reads {spec['value']} environment variable",
                    explanation="Environment variable access detected",
                )
            )
        elif spec["type"] == "network":
            findings.append(
                Finding(
                    phase=ScanPhase.NETWORK_EXFIL,
                    rule="net-http-request",
                    severity=Severity.MEDIUM,
                    file="network.js",
                    line=25,
                    snippet=f"fetch(url) // {spec['value']}",
                    weight=1.0,
                    description=f"Makes {spec['value']} request",
                    explanation="Network request pattern detected",
                )
            )
        elif spec["type"] == "import":
            findings.append(
                Finding(
                    phase=ScanPhase.CODE_PATTERNS,
                    rule="code-importlib",
                    severity=Severity.LOW,
                    file="db.py",
                    line=5,
                    snippet=f"import {spec['value']}",
                    weight=1.0,
                    description=f"Imports {spec['value']} library",
                    explanation="Database library import detected",
                )
            )
        elif spec["type"] == "file_op":
            findings.append(
                Finding(
                    phase=ScanPhase.CODE_PATTERNS,
                    rule="code-file-access",
                    severity=Severity.LOW,
                    file="files.py",
                    line=15,
                    snippet=f"open('/path/to/file') # {spec['value']}",
                    weight=1.0,
                    description=f"File operation: {spec['value']}",
                    explanation="File system access detected",
                )
            )

    return findings


async def demo_classification():
    """Demonstrate package classification."""
    print("=" * 80)
    print("🔍 SIGIL FORGE CLASSIFICATION DEMO")
    print("=" * 80)
    print()

    print("📦 Classifying sample packages...")
    print()

    classifications = []

    for package in DEMO_PACKAGES:
        print(f"Classifying: {package['ecosystem']}/{package['package_name']}")
        print(f"Description: {package['description']}")

        # Create mock findings
        findings = create_mock_findings(package.get("findings", []))

        # Create classification input
        input_data = ClassificationInput(
            ecosystem=package["ecosystem"],
            package_name=package["package_name"],
            package_version=package["package_version"],
            description=package["description"],
            scan_findings=findings,
            metadata={"demo": True, "stars": 42},
        )

        # Perform classification
        result = await forge_classifier.classify_package(input_data)
        classifications.append((input_data, result))

        print(f"✓ Category: {result.category}")
        print(f"  Confidence: {result.confidence_score:.2f}")
        print(f"  Environment vars: {result.environment_vars}")
        print(f"  Protocols: {result.network_protocols}")
        print(f"  Capabilities: {[cap['capability'] for cap in result.capabilities]}")
        print()

    return classifications


async def demo_matching(classifications):
    """Demonstrate tool matching."""
    print("🔗 TOOL COMPATIBILITY MATCHING")
    print("=" * 40)
    print()

    # Find PostgreSQL tools that could work together
    postgres_tools = [
        (input_data, result)
        for input_data, result in classifications
        if "postgres" in input_data.description.lower()
    ]

    if len(postgres_tools) >= 2:
        tool1_input, tool1_result = postgres_tools[0]
        tool2_input, tool2_result = postgres_tools[1]

        print("Analyzing compatibility between:")
        print(f"  1. {tool1_input.ecosystem}/{tool1_input.package_name}")
        print(f"  2. {tool2_input.ecosystem}/{tool2_input.package_name}")
        print()

        # Check environment variable compatibility
        shared_env_vars = set(tool1_result.environment_vars).intersection(
            set(tool2_result.environment_vars)
        )

        if shared_env_vars:
            print(f"✓ Shared environment variables: {list(shared_env_vars)}")
            compatibility_score = len(shared_env_vars) / max(
                len(tool1_result.environment_vars),
                len(tool2_result.environment_vars),
                1,
            )
            print(f"  Compatibility score: {compatibility_score:.2f}")

        # Check protocol compatibility
        shared_protocols = set(tool1_result.network_protocols).intersection(
            set(tool2_result.network_protocols)
        )

        if shared_protocols:
            print(f"✓ Compatible protocols: {list(shared_protocols)}")

        # Check capability complementarity
        tool1_caps = {cap["capability"] for cap in tool1_result.capabilities}
        tool2_caps = {cap["capability"] for cap in tool2_result.capabilities}

        if tool1_caps and tool2_caps:
            print(f"  Tool 1 capabilities: {list(tool1_caps)}")
            print(f"  Tool 2 capabilities: {list(tool2_caps)}")

        print()


async def demo_forge_stacks():
    """Demonstrate Forge Stack generation."""
    print("📚 FORGE STACK GENERATION")
    print("=" * 30)
    print()

    use_cases = [
        "I want my agent to query a PostgreSQL database",
        "I need GitHub API integration for code review",
        "Help me process and analyze files",
    ]

    for use_case in use_cases:
        print(f"Use case: {use_case}")

        try:
            stack = await forge_matcher.generate_forge_stack(use_case)

            print(f"✓ Generated stack: {stack['stack']['name']}")
            print(f"  Description: {stack['stack']['description']}")
            print(f"  Tools: {len(stack['tools'])}")

            for tool in stack["tools"]:
                print(
                    f"    - {tool['install_command']} (trust: {tool['trust_score']:.0f})"
                )

        except Exception as e:
            print(f"⚠ Stack generation failed: {e}")

        print()


async def demo_api_formats():
    """Demonstrate different API response formats."""
    print("🌐 API RESPONSE FORMATS")
    print("=" * 25)
    print()

    # Simulate API responses
    sample_classification = {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "ecosystem": "clawhub",
        "package_name": "postgres-query-skill",
        "package_version": "1.0.0",
        "category": "Database",
        "subcategory": "PostgreSQL",
        "confidence_score": 0.92,
        "description_summary": "A skill for querying PostgreSQL databases using natural language",
        "environment_vars": ["DATABASE_URL"],
        "network_protocols": ["HTTP"],
        "capabilities": [
            {
                "capability": "accesses_database",
                "confidence": 0.9,
                "evidence": "PostgreSQL driver detected",
            },
            {
                "capability": "requires_env_vars",
                "confidence": 1.0,
                "evidence": "DATABASE_URL required",
            },
        ],
        "trust_score": 85.0,
        "classified_at": datetime.now(timezone.utc).isoformat(),
    }

    print("1. Human-readable API response:")
    print(json.dumps(sample_classification, indent=2))
    print()

    print("2. Agent-optimized response:")
    agent_format = {
        "name": sample_classification["package_name"],
        "ecosystem": sample_classification["ecosystem"],
        "category": sample_classification["category"],
        "trust_score": sample_classification["trust_score"],
        "capabilities": [
            cap["capability"] for cap in sample_classification["capabilities"]
        ],
        "environment_vars": sample_classification["environment_vars"],
        "verdict": "LOW_RISK"
        if sample_classification["trust_score"] >= 80
        else "MEDIUM_RISK",
    }
    print(json.dumps(agent_format, indent=2))
    print()

    print("3. Search results format:")
    search_results = {
        "query": "postgres database",
        "results": [sample_classification],
        "total": 1,
        "categories": ["Database", "API Integration"],
        "ecosystems": ["clawhub", "mcp"],
    }
    print(json.dumps(search_results, indent=2))
    print()


async def demo_statistics():
    """Show demo statistics."""
    print("📊 CLASSIFICATION STATISTICS")
    print("=" * 32)
    print()

    # Mock statistics based on expected results
    stats = {
        "total_tools": 7700,
        "total_matches": 45000,
        "ecosystems": {"clawhub": 5700, "mcp": 2000},
        "categories": {
            "Database": 890,
            "API Integration": 1250,
            "Code Tools": 1100,
            "File System": 650,
            "AI/LLM": 980,
            "Security": 420,
            "DevOps": 780,
            "Communication": 340,
            "Data Pipeline": 310,
            "Testing": 450,
            "Search": 180,
            "Monitoring": 140,
            "Uncategorized": 200,
        },
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }

    print("Ecosystem distribution:")
    for ecosystem, count in stats["ecosystems"].items():
        print(f"  {ecosystem}: {count:,} tools")
    print()

    print("Top categories:")
    sorted_categories = sorted(
        stats["categories"].items(), key=lambda x: x[1], reverse=True
    )
    for category, count in sorted_categories[:8]:
        print(f"  {category}: {count:,} tools")
    print()

    print(f"Total compatibility matches: {stats['total_matches']:,}")
    print(f"Last updated: {stats['last_updated']}")


async def main():
    """Run the full demo."""
    try:
        # Connect to database (in-memory mode for demo)
        await db.connect()
        print("Connected to database (in-memory mode for demo)")
        print()

        # Run demo sections
        classifications = await demo_classification()
        await demo_matching(classifications)
        await demo_forge_stacks()
        await demo_api_formats()
        await demo_statistics()

        print("=" * 80)
        print("✅ Demo completed successfully!")
        print()
        print("Next steps:")
        print("1. Set SIGIL_ANTHROPIC_API_KEY for LLM classification")
        print("2. Run: python batch_classify_forge.py")
        print("3. Run: python batch_generate_matches.py")
        print("4. Access API at http://localhost:8000/forge/")
        print("=" * 80)

    except KeyboardInterrupt:
        print("\n⚠ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
