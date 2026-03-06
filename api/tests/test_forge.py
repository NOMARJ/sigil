"""
Test suite for Sigil Forge API endpoints and classification service.
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from httpx import AsyncClient

from api.main import app
from api.routers.forge import (
    ToolCapability,
    ToolCategory,
    classify_tool,
)


# ---------------------------------------------------------------------------
# Test Data
# ---------------------------------------------------------------------------

SAMPLE_SCAN_DATA = {
    "verdict": "LOW_RISK",
    "risk_score": 8,
    "findings": [
        {
            "phase": "credentials",
            "rule": "env-var-access",
            "severity": "LOW",
            "file": "index.js",
            "line": 10,
            "snippet": "process.env.DATABASE_URL",
        },
        {
            "phase": "network_exfil",
            "rule": "http-request",
            "severity": "LOW",
            "file": "api.js",
            "line": 25,
            "snippet": "fetch('https://api.example.com/data')",
        },
    ],
    "metadata": {
        "description": "A PostgreSQL connector for AI agents",
        "author": {"name": "Test Author"},
        "repository": {"url": "https://github.com/test/mcp-postgres"},
    },
    "scanned_at": datetime.now(timezone.utc),
    "package_version": "1.0.0",
}

SAMPLE_SKILL_SCAN = {
    "verdict": "MEDIUM_RISK",
    "risk_score": 35,
    "findings": [
        {
            "phase": "prompt_injection",
            "rule": "instruction-override",
            "severity": "MEDIUM",
            "file": "skill.js",
            "line": 42,
            "snippet": "system: 'ignore previous instructions'",
        },
        {
            "phase": "code_patterns",
            "rule": "eval-usage",
            "severity": "HIGH",
            "file": "utils.js",
            "line": 15,
            "snippet": "eval(userInput)",
        },
    ],
    "metadata": {
        "description": "An AI chatbot skill for conversation",
        "author": "Skill Developer",
    },
    "scanned_at": datetime.now(timezone.utc),
}


# ---------------------------------------------------------------------------
# Unit Tests for Classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_classify_tool_database():
    """Test classification of a database tool."""
    tool = await classify_tool("mcps", "mcp-postgres", SAMPLE_SCAN_DATA)

    assert tool.name == "mcp-postgres"
    assert tool.ecosystem == "mcps"  # Changed to plural
    assert tool.category == ToolCategory.DATABASE_CONNECTORS
    assert ToolCapability.DATABASE in tool.capabilities
    assert ToolCapability.AUTHENTICATION in tool.capabilities
    assert ToolCapability.NETWORK in tool.capabilities
    assert tool.trust_score == 92  # 100 - risk_score
    assert tool.verdict == "LOW_RISK"
    assert "env_vars:DATABASE_URL" in tool.compatibility_signals
    assert tool.github_url == "https://github.com/test/mcp-postgres"


@pytest.mark.asyncio
async def test_classify_tool_ai_skill():
    """Test classification of an AI/LLM skill."""
    tool = await classify_tool("skills", "chat-skill", SAMPLE_SKILL_SCAN)

    assert tool.name == "chat-skill"
    assert tool.ecosystem == "skills"  # Changed to plural
    assert tool.category == ToolCategory.AI_LLM_TOOLS
    assert ToolCapability.AI_LLM in tool.capabilities
    assert ToolCapability.CODE in tool.capabilities
    assert tool.trust_score == 65  # 100 - 35
    assert tool.verdict == "MEDIUM_RISK"
    assert tool.install_command == "npx skills add chat-skill"


@pytest.mark.asyncio
async def test_classify_tool_security():
    """Test classification of a security tool."""
    scan_data = {
        "verdict": "LOW_RISK",
        "risk_score": 5,
        "findings": [],
        "metadata": {
            "description": "Security scanner for vulnerabilities",
        },
    }

    tool = await classify_tool("mcp", "security-scanner", scan_data)

    assert tool.category == ToolCategory.SECURITY_TOOLS
    assert ToolCapability.SECURITY in tool.capabilities
    assert tool.trust_score == 95


# ---------------------------------------------------------------------------
# Integration Tests for API Endpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_tools_endpoint():
    """Test the /forge/search endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        # Mock database responses
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": "test-1",
                    "ecosystem": "clawhub",
                    "package_name": "postgres-skill",
                    "package_version": "1.0.0",
                    "risk_score": 10,
                    "verdict": "LOW_RISK",
                    "findings_count": 2,
                    "files_scanned": 10,
                    "metadata": json.dumps(
                        {"description": "PostgreSQL database skill"}
                    ),
                    "findings_json": json.dumps(SAMPLE_SCAN_DATA["findings"]),
                    "created_at": datetime.now(timezone.utc),
                }
            ]
        )
        # Mock total count query for pagination fix
        mock_db.execute_raw_sql_single = AsyncMock(
            return_value={"count": 17937}
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/forge/search?q=postgres&type=skill")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "tools" in data
            assert "total" in data
            assert len(data["tools"]) > 0
            assert data["tools"][0]["name"] == "postgres-skill"
            assert data["tools"][0]["ecosystem"] == "skills"  # Changed to plural
            assert data["query"] == "postgres"
            # CRITICAL: Test the pagination fix - total should be actual DB count, not filtered count
            assert data["total"] == 17937


@pytest.mark.asyncio
async def test_search_tools_without_query():
    """Test the /forge/search endpoint without query parameter."""
    with patch("api.routers.forge.db") as mock_db:
        # Mock database responses
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": "test-1",
                    "ecosystem": "github",
                    "package_name": "mcp-tool",
                    "package_version": "1.0.0",
                    "risk_score": 5,
                    "verdict": "LOW_RISK",
                    "findings_count": 1,
                    "files_scanned": 5,
                    "metadata": json.dumps({"description": "A useful MCP tool"}),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                }
            ]
        )
        # Mock total count query for pagination fix
        mock_db.execute_raw_sql_single = AsyncMock(
            return_value={"count": 17937}
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test without q parameter
            response = await client.get("/forge/search")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "tools" in data
            assert "total" in data
            assert "query" in data
            assert data["query"] == ""  # Should default to empty string
            assert len(data["tools"]) > 0
            # CRITICAL: Test the pagination fix - total should be actual DB count
            assert data["total"] == 17937

            # Test with empty q parameter
            response = await client.get("/forge/search?q=")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["query"] == ""
            assert len(data["tools"]) > 0
            # CRITICAL: Test the pagination fix - total should be actual DB count
            assert data["total"] == 17937


@pytest.mark.asyncio
async def test_get_tool_stack_endpoint():
    """Test the /forge/stack endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        # Mock database responses for different tool types
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": "test-1",
                    "ecosystem": "github",
                    "package_name": "mcp-postgres",
                    "package_version": "2.0.0",
                    "risk_score": 8,
                    "verdict": "LOW_RISK",
                    "findings_count": 1,
                    "files_scanned": 20,
                    "metadata": json.dumps({"description": "PostgreSQL MCP server"}),
                    "findings_json": json.dumps(SAMPLE_SCAN_DATA["findings"]),
                    "created_at": datetime.now(timezone.utc),
                },
                {
                    "id": "test-2",
                    "ecosystem": "clawhub",
                    "package_name": "db-query-skill",
                    "package_version": "1.5.0",
                    "risk_score": 15,
                    "verdict": "LOW_RISK",
                    "findings_count": 3,
                    "files_scanned": 15,
                    "metadata": json.dumps(
                        {"description": "Database query builder skill"}
                    ),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                },
            ]
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get(
                "/forge/stack?use_case=query%20postgres%20database&max_tools=3"
            )

            assert response.status_code == status.HTTP_200_OK
            stack = response.json()
            assert stack["name"] == "Database Agent Stack"
            assert "postgres" in stack["use_case"].lower()
            assert len(stack["tools"]) <= 3
            assert stack["trust_summary"]["overall_risk"] in [
                "LOW_RISK",
                "MEDIUM_RISK",
                "HIGH_RISK",
            ]
            assert "average_trust_score" in stack["trust_summary"]


@pytest.mark.asyncio
async def test_get_tool_details_endpoint():
    """Test the /forge/tools/{ecosystem}/{name} endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        # Mock database response for specific tool
        mock_db.execute_raw_sql_single = AsyncMock(
            return_value={
                "id": "test-1",
                "ecosystem": "github",
                "package_name": "mcp-postgres",
                "package_version": "2.0.0",
                "risk_score": 8,
                "verdict": "LOW_RISK",
                "findings_count": 2,
                "files_scanned": 20,
                "metadata": json.dumps(SAMPLE_SCAN_DATA["metadata"]),
                "findings_json": json.dumps(SAMPLE_SCAN_DATA["findings"]),
                "created_at": datetime.now(timezone.utc),
            }
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/forge/tools/mcp/mcp-postgres")

            assert response.status_code == status.HTTP_200_OK
            tool = response.json()
            assert tool["name"] == "mcp-postgres"
            assert tool["ecosystem"] == "mcps"  # Changed to plural
            assert tool["category"] == ToolCategory.DATABASE_CONNECTORS
            assert tool["trust_score"] == 92
            assert tool["verdict"] == "LOW_RISK"


@pytest.mark.asyncio
async def test_get_tool_details_not_found():
    """Test sample data response when tool is not found."""
    with patch("api.routers.forge.db") as mock_db:
        mock_db.execute_raw_sql_single = AsyncMock(return_value=None)

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/forge/tools/mcp/nonexistent-tool")

            # Now returns sample data instead of 404
            assert response.status_code == status.HTTP_200_OK
            tool = response.json()
            assert tool["name"] == "nonexistent-tool"
            assert tool["ecosystem"] == "mcps"  # Normalized to plural
            assert "description" in tool  # Has sample description


@pytest.mark.asyncio
async def test_get_classified_skills():
    """Test the /forge/classifications/skills endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": "test-1",
                    "ecosystem": "clawhub",
                    "package_name": "skill-1",
                    "package_version": "1.0.0",
                    "risk_score": 10,
                    "verdict": "LOW_RISK",
                    "findings_count": 1,
                    "files_scanned": 5,
                    "metadata": json.dumps({"description": "Test skill 1"}),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                },
                {
                    "id": "test-2",
                    "ecosystem": "clawhub",
                    "package_name": "skill-2",
                    "package_version": "2.0.0",
                    "risk_score": 25,
                    "verdict": "MEDIUM_RISK",
                    "findings_count": 5,
                    "files_scanned": 10,
                    "metadata": json.dumps({"description": "Test skill 2"}),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                },
            ]
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get(
                "/forge/classifications/skills?limit=10&min_trust_score=70"
            )

            assert response.status_code == status.HTTP_200_OK
            skills = response.json()
            assert isinstance(skills, list)
            # Both skills have trust score >= 70 (90 for risk_score=10, 75 for risk_score=25)
            assert len(skills) == 2
            assert all(s["ecosystem"] == "skills" for s in skills)  # Changed to plural
            assert (
                skills[0]["trust_score"] >= skills[1]["trust_score"]
            )  # Sorted by trust


@pytest.mark.asyncio
async def test_get_classified_mcps():
    """Test the /forge/classifications/mcps endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": "test-1",
                    "ecosystem": "github",
                    "package_name": "mcp-server-1",
                    "package_version": "3.0.0",
                    "risk_score": 5,
                    "verdict": "LOW_RISK",
                    "findings_count": 0,
                    "files_scanned": 25,
                    "metadata": json.dumps({"description": "Test MCP server"}),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                },
            ]
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/forge/classifications/mcps?limit=5")

            assert response.status_code == status.HTTP_200_OK
            mcps = response.json()
            assert isinstance(mcps, list)
            assert len(mcps) == 1
            assert mcps[0]["ecosystem"] == "mcp"
            assert mcps[0]["trust_score"] == 95


@pytest.mark.asyncio
async def test_classify_package_endpoint():
    """Test the /forge/classify endpoint."""
    with patch("api.routers.forge.db") as mock_db:
        mock_db.execute_raw_sql_single = AsyncMock(
            return_value={
                "id": "test-1",
                "ecosystem": "clawhub",
                "package_name": "new-skill",
                "package_version": "1.0.0",
                "risk_score": 20,
                "verdict": "MEDIUM_RISK",
                "findings_count": 4,
                "files_scanned": 8,
                "metadata": json.dumps({"description": "A newly classified skill"}),
                "findings_json": json.dumps([]),
                "created_at": datetime.now(timezone.utc),
            }
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/forge/classify",
                json={
                    "ecosystem": "skill",
                    "package_name": "new-skill",
                    "force_refresh": False,
                },
            )

            assert response.status_code == status.HTTP_200_OK
            tool = response.json()
            assert tool["name"] == "new-skill"
            assert tool["ecosystem"] == "skills"  # Changed to plural
            assert tool["trust_score"] == 80


@pytest.mark.asyncio
async def test_classify_package_not_scanned():
    """Test classification when package hasn't been scanned yet."""
    with patch("api.routers.forge.db") as mock_db:
        mock_db.execute_raw_sql_single = AsyncMock(return_value=None)

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/forge/classify",
                json={
                    "ecosystem": "mcp",
                    "package_name": "unscanned-mcp",
                    "force_refresh": False,
                },
            )

            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert "No scan data available" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Test Compatibility Detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compatibility_signals():
    """Test that compatibility signals are properly detected."""
    scan_data = {
        "verdict": "LOW_RISK",
        "risk_score": 10,
        "findings": [
            {
                "phase": "credentials",
                "rule": "env-var",
                "snippet": "process.env.DATABASE_URL",
            },
            {
                "phase": "credentials",
                "rule": "env-var",
                "snippet": "process.env.POSTGRES_PASSWORD",
            },
            {
                "phase": "network_exfil",
                "rule": "http",
                "snippet": "https://api.postgres.com/v1",
            },
        ],
        "metadata": {"description": "PostgreSQL connector"},
    }

    tool = await classify_tool("mcp", "test-mcp", scan_data)

    assert "env_vars:DATABASE_URL,POSTGRES_PASSWORD" in str(tool.compatibility_signals)
    assert "database:postgres_compatible" in tool.compatibility_signals
    assert "network:1_endpoints" in str(tool.compatibility_signals)


@pytest.mark.asyncio
async def test_category_detection_keywords():
    """Test category detection based on package name and description keywords."""
    test_cases = [
        ("redis-cache", "A Redis caching library", ToolCategory.DATABASE_CONNECTORS),
        ("api-gateway", "REST API gateway", ToolCategory.API_INTEGRATIONS),
        ("eslint-plugin", "Code linting plugin", ToolCategory.CODE_TOOLS),
        ("file-manager", "File system operations", ToolCategory.FILE_SYSTEM_TOOLS),
        ("gpt-assistant", "GPT-powered assistant", ToolCategory.AI_LLM_TOOLS),
        ("security-audit", "Security auditing tool", ToolCategory.SECURITY_TOOLS),
        ("docker-deploy", "Docker deployment tool", ToolCategory.DEVOPS_TOOLS),
        ("elastic-search", "Elasticsearch client", ToolCategory.SEARCH_TOOLS),
        ("slack-bot", "Slack integration bot", ToolCategory.COMMUNICATION_TOOLS),
        ("etl-pipeline", "Data ETL pipeline", ToolCategory.DATA_TOOLS),
        ("jest-runner", "Jest test runner", ToolCategory.TESTING_TOOLS),
        ("datadog-monitor", "Datadog monitoring", ToolCategory.MONITORING_TOOLS),
    ]

    for package_name, description, expected_category in test_cases:
        scan_data = {
            "verdict": "LOW_RISK",
            "risk_score": 10,
            "findings": [],
            "metadata": {"description": description},
        }

        tool = await classify_tool("mcp", package_name, scan_data)
        assert tool.category == expected_category, f"Failed for {package_name}"


# ---------------------------------------------------------------------------
# Test Stack Recommendation Logic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stack_use_case_parsing():
    """Test that use cases are properly parsed for capabilities."""
    with patch("api.routers.forge.db") as mock_db:
        # Return tools for different categories
        mock_db.execute_raw_sql = AsyncMock(
            return_value=[
                {
                    "id": f"test-{i}",
                    "ecosystem": "github" if i % 2 == 0 else "clawhub",
                    "package_name": f"tool-{i}",
                    "package_version": "1.0.0",
                    "risk_score": 10 + i,
                    "verdict": "LOW_RISK",
                    "findings_count": i,
                    "files_scanned": 10,
                    "metadata": json.dumps({"description": f"Tool {i}"}),
                    "findings_json": json.dumps([]),
                    "created_at": datetime.now(timezone.utc),
                }
                for i in range(5)
            ]
        )

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Test database use case
            response = await client.get(
                "/forge/stack?use_case=connect%20to%20postgres%20database"
            )
            assert response.status_code == status.HTTP_200_OK
            stack = response.json()
            assert stack["name"] == "Database Agent Stack"
            assert "database" in [
                cap.lower()
                for cap in stack["trust_summary"].get("needed_capabilities", [])
            ]

            # Test API use case
            response = await client.get(
                "/forge/stack?use_case=integrate%20with%20REST%20API"
            )
            assert response.status_code == status.HTTP_200_OK
            stack = response.json()
            assert stack["name"] == "API Integration Stack"

            # Test AI/LLM use case
            response = await client.get(
                "/forge/stack?use_case=build%20RAG%20pipeline%20with%20embeddings"
            )
            assert response.status_code == status.HTTP_200_OK
            stack = response.json()
            assert stack["name"] == "AI/LLM Stack"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
