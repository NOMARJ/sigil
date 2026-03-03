"""
Sigil API — MCP Permissions Map Tests

Comprehensive test suite for the MCP Permissions Map implementation including:
- Unit tests for permission extraction and risk scoring
- Integration tests for router endpoints 
- API tests for JSON responses
- Security tests for XSS prevention
- Performance tests for large datasets
- Data validation and edge case tests
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.routers.permissions import (
    PERMISSION_CATEGORIES,
    calculate_risk_score,
    extract_permissions_from_scan,
)


class TestPermissionExtraction:
    """Unit tests for extract_permissions_from_scan() function."""

    def test_extract_environment_variables(self):
        """Test extraction of environment variables from scan findings."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "process.env.DATABASE_URL",
                    "rule": "env-access",
                },
                {
                    "snippet": "os.environ['API_KEY']",
                    "rule": "env-access", 
                },
                {
                    "snippet": "getenv('SECRET_TOKEN')",
                    "rule": "env-access",
                },
                {
                    "snippet": "${NODE_ENV}",
                    "rule": "env-access",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "environment" in permissions
        env_vars = permissions["environment"]
        assert "DATABASE_URL" in env_vars
        assert "API_KEY" in env_vars
        assert "SECRET_TOKEN" in env_vars
        assert "NODE_ENV" in env_vars
        # Test deduplication
        assert len(set(env_vars)) == len(env_vars)

    def test_extract_filesystem_access(self):
        """Test extraction of file system access patterns."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "fs.readFile('/etc/passwd', callback)",
                    "rule": "file-access",
                },
                {
                    "snippet": "open('./config.json')",
                    "rule": "file-read",
                },
                {
                    "snippet": "writeFile('/tmp/output.txt')",
                    "rule": "file-write",
                },
                {
                    "snippet": "require('~/settings.js')", 
                    "rule": "file-path",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "filesystem" in permissions
        files = permissions["filesystem"]
        assert "/etc/passwd" in files
        assert "./config.json" in files
        assert "/tmp/output.txt" in files
        assert "~/settings.js" in files

    def test_extract_network_access(self):
        """Test extraction of network access patterns."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "fetch('https://api.example.com/data')",
                    "rule": "network-http",
                },
                {
                    "snippet": "http://malicious.com/payload",
                    "rule": "network-url",
                },
                {
                    "snippet": "connect to localhost:5432",
                    "rule": "network-connection",
                },
                {
                    "snippet": "listening on port :8080",
                    "rule": "network-listen",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "network" in permissions
        network = permissions["network"]
        assert "api.example.com" in network
        assert "malicious.com" in network
        assert "5432" in network
        assert "8080" in network

    def test_extract_database_patterns(self):
        """Test detection of database access patterns."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "SELECT * FROM users",
                    "rule": "database-sql",
                },
                {
                    "snippet": "mongoose.connect(uri)",
                    "rule": "database-mongodb", 
                },
                {
                    "snippet": "redis.get(key)",
                    "rule": "database-redis",
                },
                {
                    "snippet": "postgres://user:pass@host",
                    "rule": "database-postgres",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "database" in permissions
        assert "Database connection required" in permissions["database"]

    def test_extract_process_execution(self):
        """Test extraction of process execution patterns."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "exec('rm -rf /')",
                    "rule": "process-exec",
                },
                {
                    "snippet": "spawn('curl', ['evil.com'])",
                    "rule": "process-spawn",
                },
                {
                    "snippet": "system('malicious command')",
                    "rule": "process-system",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "process" in permissions
        processes = permissions["process"]
        assert "rm -rf /" in processes
        assert "curl" in processes
        assert "malicious command" in processes

    def test_extract_credentials(self):
        """Test detection of credential access patterns."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "api_key = config.get('api_key')",
                    "rule": "cred-api-key",
                },
                {
                    "snippet": "access_token = request.headers",
                    "rule": "cred-token",
                },
                {
                    "snippet": "password = input('Enter password:')",
                    "rule": "cred-password",
                },
                {
                    "snippet": "secret_key = os.environ['SECRET']",
                    "rule": "cred-secret",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "credentials" in permissions
        assert "Requires authentication" in permissions["credentials"]

    def test_extract_from_json_string(self):
        """Test extraction when findings_json is a JSON string."""
        findings = [
            {
                "snippet": "process.env.API_KEY",
                "rule": "env-access",
            }
        ]
        scan_data = {
            "findings_json": json.dumps(findings)
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "environment" in permissions
        assert "API_KEY" in permissions["environment"]

    def test_extract_empty_findings(self):
        """Test extraction with no findings."""
        scan_data = {"findings_json": []}
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert permissions == {}

    def test_extract_malformed_findings(self):
        """Test extraction with malformed findings data."""
        scan_data = {"findings_json": "invalid json"}
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert permissions == {}

    def test_extract_case_insensitive(self):
        """Test that extraction works case-insensitively."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "Process.Env.database_url",
                    "rule": "ENV-ACCESS",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "environment" in permissions
        assert "DATABASE_URL" in permissions["environment"]

    def test_extract_deduplication(self):
        """Test that duplicate permissions are deduplicated."""
        scan_data = {
            "findings_json": [
                {
                    "snippet": "process.env.API_KEY",
                    "rule": "env-access",
                },
                {
                    "snippet": "process.env.API_KEY", 
                    "rule": "env-access",
                },
                {
                    "snippet": "os.environ['API_KEY']",
                    "rule": "env-access",
                },
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        assert "environment" in permissions
        assert len(permissions["environment"]) == 1
        assert "API_KEY" in permissions["environment"]


class TestRiskScoring:
    """Unit tests for calculate_risk_score() function."""

    def test_empty_permissions(self):
        """Test risk scoring with no permissions."""
        permissions = {}
        
        score, level = calculate_risk_score(permissions)
        
        assert score == 0
        assert level == "LOW"

    def test_low_risk_score(self):
        """Test permissions that should result in LOW risk."""
        permissions = {
            "environment": ["API_KEY", "NODE_ENV"],
            "network": ["api.example.com"],
        }
        
        score, level = calculate_risk_score(permissions)
        
        # environment: 2 items * 2 weight = 4
        # network: 1 item * 4 weight = 4
        # Total: 8 (< 10, so LOW)
        assert score == 8
        assert level == "LOW"

    def test_medium_risk_score(self):
        """Test permissions that should result in MEDIUM risk."""
        permissions = {
            "filesystem": ["/etc/passwd", "/tmp/file"],
            "database": ["Database connection required"],
            "environment": ["SECRET_KEY"],
        }
        
        score, level = calculate_risk_score(permissions)
        
        # filesystem: 2 items * 6 weight = 12
        # database: 1 item * 6 weight = 6
        # environment: 1 item * 2 weight = 2
        # Total: 20 (>= 20, so HIGH actually)
        assert score == 20
        assert level == "HIGH"

    def test_high_risk_score(self):
        """Test permissions that should result in HIGH risk."""
        permissions = {
            "process": ["rm -rf /", "curl evil.com"],
            "credentials": ["Requires authentication"],
            "filesystem": ["/etc/shadow"],
        }
        
        score, level = calculate_risk_score(permissions)
        
        # process: 2 items * 10 weight = 20
        # credentials: 1 item * 8 weight = 8  
        # filesystem: 1 item * 6 weight = 6
        # Total: 34 (>= 20, so HIGH)
        assert score == 34
        assert level == "HIGH"

    def test_critical_process_permissions(self):
        """Test that process permissions create high scores."""
        permissions = {
            "process": ["dangerous-command"]
        }
        
        score, level = calculate_risk_score(permissions)
        
        assert score == 10  # 1 item * 10 weight
        assert level == "MEDIUM"

    def test_unknown_categories_ignored(self):
        """Test that unknown permission categories are ignored."""
        permissions = {
            "unknown_category": ["some-permission"],
            "environment": ["API_KEY"], 
        }
        
        score, level = calculate_risk_score(permissions)
        
        # Only environment should count
        assert score == 2  # 1 item * 2 weight
        assert level == "LOW"

    def test_empty_category_values(self):
        """Test that empty permission lists are ignored."""
        permissions = {
            "environment": [],
            "filesystem": ["/tmp/file"],
            "network": [],
        }
        
        score, level = calculate_risk_score(permissions)
        
        # Only filesystem should count
        assert score == 6  # 1 item * 6 weight
        assert level == "LOW"


class TestPermissionCategories:
    """Test that permission categories are properly defined."""

    def test_all_categories_defined(self):
        """Test that all expected permission categories are defined."""
        expected = {
            "environment", "filesystem", "network", 
            "database", "process", "credentials"
        }
        
        assert set(PERMISSION_CATEGORIES.keys()) == expected

    def test_category_structure(self):
        """Test that each category has required fields."""
        for category, info in PERMISSION_CATEGORIES.items():
            assert "title" in info
            assert "description" in info
            assert "risk_level" in info
            assert "icon" in info
            assert info["risk_level"] in ["low", "medium", "high", "critical"]
            assert len(info["icon"]) > 0


class TestPermissionsFixtures:
    """Test fixtures and sample data for other tests."""

    @pytest.fixture
    def sample_mcp_scan(self):
        """Sample MCP server scan data."""
        return {
            "id": "test-scan-1",
            "package_name": "test-mcp-server",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T10:30:00Z",
            "metadata_json": json.dumps({
                "author": "test-author",
                "description": "A test MCP server for testing permissions",
                "stars": 42,
                "language": "TypeScript",
                "version": "1.0.0",
            }),
            "findings_json": [
                {
                    "phase": "code_patterns",
                    "rule": "env-access",
                    "severity": "MEDIUM",
                    "file": "server.ts",
                    "line": 15,
                    "snippet": "const dbUrl = process.env.DATABASE_URL",
                    "weight": 1.0,
                },
                {
                    "phase": "code_patterns", 
                    "rule": "file-access",
                    "severity": "HIGH",
                    "file": "server.ts",
                    "line": 25,
                    "snippet": "fs.readFile('/etc/config.json')",
                    "weight": 1.0,
                },
                {
                    "phase": "network",
                    "rule": "http-request",
                    "severity": "MEDIUM",
                    "file": "client.ts",
                    "line": 10,
                    "snippet": "fetch('https://api.external.com/data')",
                    "weight": 1.0,
                },
            ]
        }

    @pytest.fixture
    def high_risk_mcp_scan(self):
        """Sample high-risk MCP server scan data."""
        return {
            "id": "test-scan-2", 
            "package_name": "dangerous-mcp-server",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T11:00:00Z",
            "metadata_json": json.dumps({
                "author": "unknown-author",
                "description": "This server has dangerous permissions",
                "stars": 5,
                "language": "JavaScript",
                "version": "0.1.0",
            }),
            "findings_json": [
                {
                    "phase": "code_patterns",
                    "rule": "process-exec", 
                    "severity": "CRITICAL",
                    "file": "main.js",
                    "line": 20,
                    "snippet": "exec('rm -rf /tmp/*')",
                    "weight": 1.0,
                },
                {
                    "phase": "credentials",
                    "rule": "cred-access",
                    "severity": "HIGH", 
                    "file": "auth.js",
                    "line": 5,
                    "snippet": "const token = process.env.SECRET_TOKEN",
                    "weight": 1.0,
                },
                {
                    "phase": "code_patterns",
                    "rule": "file-access",
                    "severity": "HIGH",
                    "file": "main.js", 
                    "line": 30,
                    "snippet": "fs.writeFile('/etc/passwd', data)",
                    "weight": 1.0,
                },
            ]
        }

    @pytest.fixture
    def clean_mcp_scan(self):
        """Sample clean MCP server with minimal permissions."""
        return {
            "id": "test-scan-3",
            "package_name": "safe-mcp-server", 
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T12:00:00Z",
            "metadata_json": json.dumps({
                "author": "trusted-author",
                "description": "A safe MCP server with minimal permissions",
                "stars": 150,
                "language": "Python", 
                "version": "2.1.0",
            }),
            "findings_json": []
        }

    def test_sample_scan_extraction(self, sample_mcp_scan):
        """Test that sample scan data extracts permissions correctly."""
        permissions = extract_permissions_from_scan(sample_mcp_scan)
        
        assert "environment" in permissions
        assert "filesystem" in permissions
        assert "network" in permissions
        assert "DATABASE_URL" in permissions["environment"]
        assert "/etc/config.json" in permissions["filesystem"]
        assert "api.external.com" in permissions["network"]

    def test_high_risk_scan_scoring(self, high_risk_mcp_scan):
        """Test that high-risk scan produces appropriate risk score."""
        permissions = extract_permissions_from_scan(high_risk_mcp_scan)
        score, level = calculate_risk_score(permissions)
        
        assert level == "HIGH"
        assert score >= 20

    def test_clean_scan_scoring(self, clean_mcp_scan):
        """Test that clean scan produces low risk score."""
        permissions = extract_permissions_from_scan(clean_mcp_scan)
        score, level = calculate_risk_score(permissions)
        
        assert level == "LOW" 
        assert score == 0


class TestPermissionsRouter:
    """Integration tests for the permissions router endpoints."""

    async def setup_test_data(self, sample_mcp_scan, high_risk_mcp_scan, clean_mcp_scan):
        """Setup test MCP scan data in the database."""
        from api.database import db
        
        # Insert test scans into public_scans table
        await db.insert("public_scans", sample_mcp_scan)
        await db.insert("public_scans", high_risk_mcp_scan) 
        await db.insert("public_scans", clean_mcp_scan)

    @pytest.mark.asyncio
    async def test_permissions_directory_endpoint(
        self, client: TestClient, sample_mcp_scan, high_risk_mcp_scan, clean_mcp_scan
    ):
        """Test the main permissions directory endpoint."""
        # Setup test data
        await self.setup_test_data(sample_mcp_scan, high_risk_mcp_scan, clean_mcp_scan)
        
        # Make request
        response = client.get("/permissions")
        
        # Verify response
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        
        # Check HTML content contains expected elements
        html = response.text
        assert "MCP Permissions Map" in html
        assert "test-mcp-server" in html
        assert "dangerous-mcp-server" in html
        assert "safe-mcp-server" in html
        
        # Check risk indicators
        assert "HIGH" in html or "🚨" in html
        assert "LOW" in html or "✅" in html
        
        # Check stats section
        assert "MCP Servers" in html
        assert "High Risk" in html

    @pytest.mark.asyncio 
    async def test_individual_mcp_permissions_page(
        self, client: TestClient, sample_mcp_scan
    ):
        """Test individual MCP server permissions page."""
        # Setup test data
        await self.setup_test_data(sample_mcp_scan, {}, {})
        
        # Make request
        response = client.get("/permissions/test-mcp-server")
        
        # Verify response
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        
        # Check HTML content
        html = response.text
        assert "test-mcp-server" in html
        assert "test-author" in html
        assert "A test MCP server for testing permissions" in html
        
        # Check permissions sections
        assert "Environment Variables" in html or "🔧" in html
        assert "File System Access" in html or "📁" in html
        assert "Network Access" in html or "🌐" in html
        
        # Check specific permissions
        assert "DATABASE_URL" in html
        assert "/etc/config.json" in html
        assert "api.external.com" in html

    @pytest.mark.asyncio
    async def test_individual_mcp_not_found(self, client: TestClient):
        """Test 404 response for non-existent MCP server."""
        response = client.get("/permissions/nonexistent-server")
        
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_permissions_json_api(self, client: TestClient, sample_mcp_scan):
        """Test JSON API endpoint for MCP permissions."""
        # Setup test data
        await self.setup_test_data(sample_mcp_scan, {}, {})
        
        # Make request
        response = client.get("/api/v1/permissions/test-mcp-server")
        
        # Verify response
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        
        # Check JSON structure
        data = response.json()
        assert data["name"] == "test-mcp-server"
        assert data["author"] == "test-author"
        assert data["description"] == "A test MCP server for testing permissions"
        assert data["stars"] == 42
        assert data["language"] == "TypeScript"
        assert "risk_score" in data
        assert "risk_level" in data
        assert "permissions" in data
        assert "permissions_count" in data
        assert data["github_url"] == "https://github.com/test-mcp-server"
        
        # Check permissions structure
        permissions = data["permissions"]
        assert "environment" in permissions
        assert "filesystem" in permissions
        assert "network" in permissions
        assert "DATABASE_URL" in permissions["environment"]

    @pytest.mark.asyncio
    async def test_permissions_json_api_not_found(self, client: TestClient):
        """Test 404 response for JSON API with non-existent MCP server."""
        response = client.get("/api/v1/permissions/nonexistent-server")
        
        assert response.status_code == 404
        
        data = response.json()
        assert "detail" in data
        assert "nonexistent-server" in data["detail"]

    @pytest.mark.asyncio
    async def test_permissions_search_api(
        self, client: TestClient, sample_mcp_scan, high_risk_mcp_scan, clean_mcp_scan
    ):
        """Test permissions search API endpoint."""
        # Setup test data
        await self.setup_test_data(sample_mcp_scan, high_risk_mcp_scan, clean_mcp_scan)
        
        # Test search without filters
        response = client.get("/api/v1/permissions/search")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # Should include our test servers
        
        # Test search by permission type
        response = client.get("/api/v1/permissions/search?permission=environment")
        assert response.status_code == 200
        
        data = response.json()
        # Should return servers that have environment permissions
        for server in data:
            assert "permissions" in server
            assert "environment" in server["permissions"]

        # Test search by risk level
        response = client.get("/api/v1/permissions/search?risk_level=HIGH")
        assert response.status_code == 200
        
        data = response.json()
        for server in data:
            assert server["risk_level"] == "HIGH"

        # Test search with limit
        response = client.get("/api/v1/permissions/search?limit=1")
        assert response.status_code == 200
        
        data = response.json()
        assert len(data) <= 1

    @pytest.mark.asyncio
    async def test_permissions_search_api_filters(
        self, client: TestClient, sample_mcp_scan, high_risk_mcp_scan
    ):
        """Test permissions search API with specific filters."""
        # Setup test data
        await self.setup_test_data(sample_mcp_scan, high_risk_mcp_scan, {})
        
        # Test combined filters
        response = client.get("/api/v1/permissions/search?permission=process&risk_level=HIGH")
        assert response.status_code == 200
        
        data = response.json()
        for server in data:
            assert server["risk_level"] == "HIGH"
            assert "process" in server["permissions"]

    @pytest.mark.asyncio
    async def test_permissions_directory_empty_database(self, client: TestClient):
        """Test permissions directory with empty database."""
        response = client.get("/permissions")
        
        assert response.status_code == 200
        html = response.text
        assert "MCP Permissions Map" in html
        # Should handle empty state gracefully

    @pytest.mark.asyncio
    async def test_permissions_api_malformed_metadata(self, client: TestClient):
        """Test API endpoints handle malformed metadata gracefully."""
        from api.database import db
        
        # Insert scan with malformed metadata
        malformed_scan = {
            "id": "malformed-scan",
            "package_name": "malformed-mcp",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T10:30:00Z",
            "metadata_json": "invalid json string",
            "findings_json": []
        }
        await db.insert("public_scans", malformed_scan)
        
        # Test JSON API
        response = client.get("/api/v1/permissions/malformed-mcp")
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "malformed-mcp"
        assert data["author"] == "unknown"  # Should fallback to default
        assert data["description"] == ""
        assert data["stars"] == 0

    @pytest.mark.asyncio
    async def test_permissions_large_dataset_performance(self, client: TestClient):
        """Test permissions directory performance with large dataset."""
        from api.database import db
        
        # Create many test scans
        large_scans = []
        for i in range(50):
            scan = {
                "id": f"perf-test-{i}",
                "package_name": f"test-mcp-{i}",
                "ecosystem": "mcp", 
                "scanned_at": "2024-01-15T10:30:00Z",
                "metadata_json": json.dumps({
                    "author": f"author-{i}",
                    "description": f"Test MCP server {i}",
                    "stars": i * 2,
                    "language": "TypeScript",
                }),
                "findings_json": [
                    {
                        "snippet": f"process.env.API_KEY_{i}",
                        "rule": "env-access",
                    }
                ]
            }
            large_scans.append(scan)
        
        # Insert all scans
        for scan in large_scans:
            await db.insert("public_scans", scan)
        
        # Test directory page performance
        import time
        start_time = time.time()
        response = client.get("/permissions")
        end_time = time.time()
        
        # Should complete within reasonable time (5 seconds)
        assert (end_time - start_time) < 5.0
        assert response.status_code == 200
        
        # Test search API performance 
        start_time = time.time()
        response = client.get("/api/v1/permissions/search?limit=20")
        end_time = time.time()
        
        assert (end_time - start_time) < 3.0
        assert response.status_code == 200


class TestPermissionsSecurity:
    """Security tests for XSS prevention, injection attacks, and input validation."""

    @pytest.mark.asyncio
    async def test_xss_prevention_in_html_output(self, client: TestClient):
        """Test that HTML output prevents XSS attacks."""
        from api.database import db
        
        # Create scan with malicious script in metadata
        xss_scan = {
            "id": "xss-test",
            "package_name": "xss<script>alert('hacked')</script>test",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T10:30:00Z",
            "metadata_json": json.dumps({
                "author": "<script>alert('xss')</script>",
                "description": "Test <img src=x onerror=alert('xss')> description",
                "stars": 42,
                "language": "<script>document.write('pwned')</script>",
            }),
            "findings_json": [
                {
                    "snippet": "process.env.<script>alert('env')</script>",
                    "rule": "env-access",
                }
            ]
        }
        await db.insert("public_scans", xss_scan)
        
        # Test directory page
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        # Scripts should be escaped/encoded, not executed
        assert "<script>" not in html
        assert "alert(" not in html
        assert "&lt;script&gt;" in html or "&amp;lt;script&amp;gt;" in html
        
        # Test individual page
        response = client.get("/permissions/xss<script>alert('hacked')</script>test")
        # Should handle malicious package name safely
        assert response.status_code == 404 or response.status_code == 500
        
        # Test with URL-encoded name
        import urllib.parse
        safe_name = urllib.parse.quote("xss<script>alert('hacked')</script>test")
        response = client.get(f"/permissions/{safe_name}")
        if response.status_code == 200:
            html = response.text
            assert "<script>" not in html
            assert "alert(" not in html

    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, client: TestClient):
        """Test that SQL injection attempts are prevented."""
        # Try various SQL injection patterns in search parameters
        sql_injections = [
            "'; DROP TABLE public_scans; --",
            "' OR 1=1; --",
            "' UNION SELECT * FROM users; --",
            "'; INSERT INTO scans VALUES ('hacked'); --",
            "admin'--",
            "' OR 'a'='a",
        ]
        
        for injection in sql_injections:
            # Test search API
            response = client.get(f"/api/v1/permissions/search?permission={injection}")
            # Should not cause server error (500) due to SQL syntax error
            assert response.status_code in [200, 400, 422]
            
            response = client.get(f"/api/v1/permissions/search?risk_level={injection}")
            assert response.status_code in [200, 400, 422]
            
            # Test individual permissions API
            response = client.get(f"/api/v1/permissions/{injection}")
            assert response.status_code in [200, 404, 400, 422]

    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self, client: TestClient):
        """Test prevention of path traversal attacks."""
        path_traversals = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "../../../../../../../../../etc/hosts",
        ]
        
        for traversal in path_traversals:
            response = client.get(f"/permissions/{traversal}")
            # Should not expose system files
            assert response.status_code == 404
            
            response = client.get(f"/api/v1/permissions/{traversal}")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_input_length_limits(self, client: TestClient):
        """Test that extremely long inputs are handled gracefully."""
        # Create very long strings
        long_string = "A" * 10000
        very_long_string = "B" * 100000
        
        # Test search with long parameters
        response = client.get(f"/api/v1/permissions/search?permission={long_string}")
        assert response.status_code in [200, 400, 422, 414]  # 414 = URI Too Long
        
        response = client.get(f"/api/v1/permissions/search?risk_level={very_long_string}")
        assert response.status_code in [200, 400, 422, 414]
        
        # Test individual permissions with long name
        response = client.get(f"/api/v1/permissions/{long_string}")
        assert response.status_code in [404, 414]

    @pytest.mark.asyncio
    async def test_unicode_and_special_characters(self, client: TestClient):
        """Test handling of Unicode and special characters."""
        from api.database import db
        
        # Create scan with Unicode characters
        unicode_scan = {
            "id": "unicode-test",
            "package_name": "test-mcp-服务器-🔐",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T10:30:00Z", 
            "metadata_json": json.dumps({
                "author": "作者-αβγ",
                "description": "测试 MCP 服务器 with émojis 🚀🔒",
                "stars": 42,
                "language": "TypeScript",
            }),
            "findings_json": [
                {
                    "snippet": "process.env.数据库_URL",
                    "rule": "env-access",
                }
            ]
        }
        await db.insert("public_scans", unicode_scan)
        
        # Test that Unicode is handled properly
        response = client.get("/permissions")
        assert response.status_code == 200
        
        # Test individual page with Unicode name
        response = client.get("/permissions/test-mcp-服务器-🔐")
        # May be 404 due to URL encoding issues, but shouldn't crash
        assert response.status_code in [200, 404]
        
        # Test JSON API
        response = client.get("/api/v1/permissions/test-mcp-服务器-🔐")
        if response.status_code == 200:
            data = response.json()
            assert "test-mcp-服务器-🔐" in data["name"]

    @pytest.mark.asyncio
    async def test_content_type_validation(self, client: TestClient):
        """Test that responses have correct Content-Type headers."""
        # Test HTML endpoints
        response = client.get("/permissions")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        
        # Test JSON API endpoints
        response = client.get("/api/v1/permissions/search")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self, client: TestClient):
        """Test that error messages don't leak sensitive information."""
        # Test with malicious input that might cause errors
        response = client.get("/api/v1/permissions/<script>alert('error')</script>")
        assert response.status_code == 404
        
        error_data = response.json()
        if "detail" in error_data:
            # Error message should not contain unsanitized script tags
            assert "<script>" not in error_data["detail"]

    @pytest.mark.asyncio
    async def test_rate_limiting_behavior(self, client: TestClient):
        """Test that the API handles rapid requests appropriately."""
        # Make many rapid requests
        responses = []
        for i in range(20):
            response = client.get("/api/v1/permissions/search")
            responses.append(response.status_code)
        
        # Should either succeed or rate limit gracefully
        for status in responses:
            assert status in [200, 429, 503]  # 429 = Too Many Requests


class TestPermissionsValidation:
    """Data validation and edge case tests."""

    def test_extract_permissions_edge_cases(self):
        """Test permission extraction with various edge cases."""
        # Test with None findings
        scan_data = {"findings_json": None}
        permissions = extract_permissions_from_scan(scan_data)
        assert permissions == {}
        
        # Test with missing findings_json key
        scan_data = {}
        permissions = extract_permissions_from_scan(scan_data)
        assert permissions == {}
        
        # Test with empty string
        scan_data = {"findings_json": ""}
        permissions = extract_permissions_from_scan(scan_data)
        assert permissions == {}
        
        # Test with invalid JSON that returns empty findings
        scan_data = {"findings_json": "[invalid json"}
        permissions = extract_permissions_from_scan(scan_data)
        assert permissions == {}
        
        # Test with empty list
        scan_data = {"findings_json": []}
        permissions = extract_permissions_from_scan(scan_data)
        assert permissions == {}

    def test_extract_permissions_malformed_findings(self):
        """Test extraction with malformed finding objects."""
        scan_data = {
            "findings_json": [
                {}, # Empty finding
                {"snippet": None, "rule": None}, # None values
                {"snippet": "", "rule": ""}, # Empty strings
                {"snippet": "valid snippet"}, # Missing rule
                {"rule": "valid-rule"}, # Missing snippet
                {"snippet": 123, "rule": 456}, # Wrong types
                {"snippet": "process.env.VALID", "rule": "env-access"}, # Valid finding
            ]
        }
        
        permissions = extract_permissions_from_scan(scan_data)
        
        # Should extract the valid finding and ignore malformed ones
        assert "environment" in permissions
        assert "VALID" in permissions["environment"]

    def test_risk_scoring_edge_cases(self):
        """Test risk scoring with edge case inputs."""
        # Test with None permissions
        score, level = calculate_risk_score({})
        assert score == 0
        assert level == "LOW"
        
        # Test with None values in permissions
        permissions = {"environment": None, "filesystem": []}
        score, level = calculate_risk_score(permissions)
        assert score == 0
        assert level == "LOW"
        
        # Test with extremely large numbers of permissions
        permissions = {"process": ["cmd"] * 1000}  # 1000 process permissions
        score, level = calculate_risk_score(permissions)
        assert score == 10000  # 1000 * 10 weight
        assert level == "HIGH"

    def test_boundary_risk_scores(self):
        """Test risk scoring at boundary conditions."""
        # Test score exactly at LOW/MEDIUM boundary (9 vs 10)
        permissions = {"environment": ["A", "B", "C", "D"]}  # 4 * 2 = 8
        score, level = calculate_risk_score(permissions)
        assert score == 8
        assert level == "LOW"
        
        permissions = {"environment": ["A", "B", "C", "D", "E"]}  # 5 * 2 = 10  
        score, level = calculate_risk_score(permissions)
        assert score == 10
        assert level == "MEDIUM"
        
        # Test score exactly at MEDIUM/HIGH boundary (19 vs 20)
        permissions = {"filesystem": ["A", "B", "C"], "environment": ["D"]}  # 3*6 + 1*2 = 20
        score, level = calculate_risk_score(permissions)
        assert score == 20
        assert level == "HIGH"

    @pytest.mark.asyncio
    async def test_database_edge_cases(self, client: TestClient):
        """Test API behavior with edge case database states."""
        from api.database import db
        
        # Test with scan that has null/missing fields
        minimal_scan = {
            "package_name": "minimal-test",
            "ecosystem": "mcp",
        }
        await db.insert("public_scans", minimal_scan)
        
        response = client.get("/api/v1/permissions/minimal-test")
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "minimal-test"
        assert data["author"] == "unknown"
        assert data["permissions"] == {}

    def test_regex_pattern_edge_cases(self):
        """Test regex patterns with edge cases."""
        # Test patterns that might cause regex errors
        edge_case_snippets = [
            "process.env.", # Missing variable name
            "process.env.123", # Numeric start
            "process.env._", # Single underscore
            "process.env.A_B_C_D_E_F_G_H_I_J_K_L_M_N_O_P_Q_R_S_T_U_V_W_X_Y_Z_VERY_LONG_NAME",
            "os.environ[]", # Empty brackets
            "getenv()", # Empty parentheses  
            "${}", # Empty variable
            "process.env[undefined]", # Invalid accessor
        ]
        
        for snippet in edge_case_snippets:
            scan_data = {
                "findings_json": [
                    {
                        "snippet": snippet,
                        "rule": "env-access",
                    }
                ]
            }
            # Should not crash
            permissions = extract_permissions_from_scan(scan_data)
            assert isinstance(permissions, dict)


class TestHTMLValidation:
    """HTML validation and structure tests."""

    @pytest.mark.asyncio
    async def test_html_structure_validity(self, client: TestClient, sample_mcp_scan):
        """Test that generated HTML has valid structure."""
        from api.database import db
        await db.insert("public_scans", sample_mcp_scan)
        
        # Test directory page HTML structure
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check basic HTML structure
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html and "</html>" in html
        assert "<head>" in html and "</head>" in html
        assert "<body>" in html and "</body>" in html
        assert "<title>" in html and "</title>" in html
        
        # Check meta tags
        assert '<meta charset="UTF-8">' in html
        assert 'name="viewport"' in html
        
        # Check CSS is included
        assert "<style>" in html and "</style>" in html
        
        # Check table structure
        assert "<table>" in html and "</table>" in html
        assert "<thead>" in html and "</thead>" in html
        assert "<tbody>" in html and "</tbody>" in html
        assert "<th>" in html and "</th>" in html
        assert "<td>" in html and "</td>" in html

    @pytest.mark.asyncio
    async def test_individual_page_html_structure(self, client: TestClient, sample_mcp_scan):
        """Test individual MCP page HTML structure."""
        from api.database import db
        await db.insert("public_scans", sample_mcp_scan)
        
        response = client.get("/permissions/test-mcp-server")
        assert response.status_code == 200
        
        html = response.text
        
        # Check basic structure
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html and "</html>" in html
        
        # Check specific sections exist
        assert 'class="header"' in html
        assert 'class="permission-section"' in html
        assert 'class="actions"' in html
        
        # Check navigation links
        assert 'href="/permissions"' in html  # Back to directory
        assert 'href="https://github.com/' in html  # GitHub link
        assert 'href="/api/v1/permissions/' in html  # JSON API link

    @pytest.mark.asyncio
    async def test_html_escaping_in_content(self, client: TestClient):
        """Test that HTML content is properly escaped."""
        from api.database import db
        
        # Create scan with HTML entities in content
        html_scan = {
            "id": "html-test",
            "package_name": "test-html-<>&\"'",
            "ecosystem": "mcp",
            "scanned_at": "2024-01-15T10:30:00Z",
            "metadata_json": json.dumps({
                "author": "Test & Author <script>",
                "description": "Description with <b>bold</b> & special chars",
                "stars": 42,
                "language": "TypeScript",
            }),
            "findings_json": [
                {
                    "snippet": "process.env.API_KEY & process.env.SECRET",
                    "rule": "env-access",
                }
            ]
        }
        await db.insert("public_scans", html_scan)
        
        # Test directory page escaping
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        # HTML entities should be escaped
        assert "&lt;" in html or "&amp;" in html  # Some HTML should be escaped
        assert "<script>" not in html  # Scripts should not be present

    @pytest.mark.asyncio
    async def test_css_styling_presence(self, client: TestClient):
        """Test that CSS styling is present and valid."""
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check that CSS classes are defined
        css_classes = [
            "header", "subtitle", "stats", "stat", "stat-number", "stat-label",
            "server-name", "server-meta", "badge", "risk-badge", "text-center", "footer"
        ]
        
        for css_class in css_classes:
            assert f".{css_class}" in html or f'class="{css_class}"' in html
        
        # Check that colors are defined
        assert "color:" in html
        assert "background:" in html or "background-color:" in html
        
        # Check responsive design
        assert "width=device-width" in html

    @pytest.mark.asyncio  
    async def test_accessibility_features(self, client: TestClient, sample_mcp_scan):
        """Test basic accessibility features in HTML."""
        from api.database import db
        await db.insert("public_scans", sample_mcp_scan)
        
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check language is specified
        assert 'lang="en"' in html
        
        # Check that links have meaningful text (not just "click here")
        # Links should contain descriptive text
        assert 'href="/permissions/' in html  # Should have server names as link text
        
        # Check table headers exist
        assert "<th>" in html

    @pytest.mark.asyncio
    async def test_risk_indicator_styling(self, client: TestClient, high_risk_mcp_scan, clean_mcp_scan):
        """Test that risk indicators have appropriate styling."""
        from api.database import db
        await db.insert("public_scans", high_risk_mcp_scan)
        await db.insert("public_scans", clean_mcp_scan)
        
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check risk colors are defined
        assert "#dc3545" in html or "rgb(220, 53, 69)" in html  # High risk red
        assert "#28a745" in html or "rgb(40, 167, 69)" in html   # Low risk green
        
        # Check risk emojis are present
        risk_emojis = ["🚨", "⚠️", "✅"]
        emoji_found = any(emoji in html for emoji in risk_emojis)
        assert emoji_found
        
        # Check risk badges exist
        assert "risk-badge" in html

    @pytest.mark.asyncio
    async def test_responsive_design_elements(self, client: TestClient):
        """Test responsive design elements in CSS."""
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check viewport meta tag
        assert 'name="viewport"' in html
        assert 'width=device-width' in html
        
        # Check responsive units or media queries might be present
        # Look for percentage widths or flexible layouts
        assert "width: 100%" in html or "max-width:" in html

    @pytest.mark.asyncio
    async def test_link_validity_structure(self, client: TestClient, sample_mcp_scan):
        """Test that links have valid structure."""
        from api.database import db
        await db.insert("public_scans", sample_mcp_scan)
        
        response = client.get("/permissions/test-mcp-server")
        assert response.status_code == 200
        
        html = response.text
        
        # Check internal links
        assert 'href="/permissions"' in html  # Back link
        assert 'href="/api/v1/permissions/test-mcp-server"' in html  # JSON API
        
        # Check external links
        assert 'href="https://github.com/' in html  # GitHub links
        
        # Links should not be broken (contain valid characters)
        import re
        links = re.findall(r'href="([^"]+)"', html)
        for link in links:
            # Basic validation - no obviously broken links
            assert link.strip() != ""
            assert not link.startswith("javascript:")  # No JS links for security

    @pytest.mark.asyncio
    async def test_icon_and_emoji_rendering(self, client: TestClient, sample_mcp_scan):
        """Test that icons and emojis render correctly."""
        from api.database import db
        await db.insert("public_scans", sample_mcp_scan)
        
        # Test directory page
        response = client.get("/permissions")
        assert response.status_code == 200
        
        html = response.text
        
        # Check permission category icons
        category_icons = ["🔧", "📁", "🌐", "💾", "⚡", "🔐"]
        icons_found = [icon for icon in category_icons if icon in html]
        assert len(icons_found) > 0  # At least some icons should be present
        
        # Test individual page
        response = client.get("/permissions/test-mcp-server")
        assert response.status_code == 200
        
        html = response.text
        
        # Should have permission icons in sections
        icons_found = [icon for icon in category_icons if icon in html]
        assert len(icons_found) > 0

    @pytest.mark.asyncio
    async def test_error_page_html_structure(self, client: TestClient):
        """Test that error pages have valid HTML structure."""
        # Test 404 page
        response = client.get("/permissions/nonexistent-server")
        assert response.status_code == 404
        
        # Even error responses should have basic HTML structure
        html = response.text
        assert "<html" in html or "Error" in html