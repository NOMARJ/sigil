"""
Sigil API — Threat Intelligence Tests

Tests for threat lookup, signature endpoints, and threat report submission.
"""

from __future__ import annotations


from fastapi.testclient import TestClient

from api.database import _memory_store


class TestThreatLookup:
    """Tests for GET /v1/threat/{hash}."""

    def test_threat_not_found(self, client: TestClient) -> None:
        """Looking up a non-existent hash returns 404."""
        resp = client.get("/v1/threat/0000000000000000000000000000000000000000")
        assert resp.status_code == 404
        assert "No threat entry found" in resp.json()["detail"]

    def test_threat_found(self, client: TestClient) -> None:
        """Looking up an existing threat hash returns the threat entry."""
        # Seed a threat into the in-memory store
        threat = {
            "id": "test-threat-1",
            "hash": "abc123deadbeef456",
            "package_name": "evil-pkg",
            "version": "1.0.0",
            "severity": "CRITICAL",
            "source": "internal",
            "description": "Test malicious package",
            "confirmed_at": "2024-01-01T00:00:00",
        }
        _memory_store.setdefault("threats", {})["test-threat-1"] = threat

        resp = client.get("/v1/threat/abc123deadbeef456")
        assert resp.status_code == 200

        data = resp.json()
        assert data["package_name"] == "evil-pkg"
        assert data["severity"] == "CRITICAL"
        assert data["hash"] == "abc123deadbeef456"


class TestSignatures:
    """Tests for GET /v1/signatures."""

    def test_get_all_signatures(self, client: TestClient) -> None:
        """Fetching signatures without a filter returns the built-in set."""
        resp = client.get("/v1/signatures")
        assert resp.status_code == 200

        data = resp.json()
        assert "signatures" in data
        assert "total" in data
        assert data["total"] > 0
        assert len(data["signatures"]) == data["total"]

        # Verify structure
        sig = data["signatures"][0]
        assert "id" in sig
        assert "phase" in sig
        assert "pattern" in sig
        assert "severity" in sig

    def test_get_signatures_since_filter(self, client: TestClient) -> None:
        """Passing a 'since' parameter filters signatures by update time."""
        # All built-in signatures have updated_at = now, so a future date should
        # return nothing
        resp = client.get("/v1/signatures?since=2099-01-01T00:00:00")
        assert resp.status_code == 200

        data = resp.json()
        assert data["total"] == 0
        assert data["signatures"] == []

    def test_signatures_contain_all_phases(self, client: TestClient) -> None:
        """Built-in signatures should cover multiple scan phases."""
        resp = client.get("/v1/signatures")
        data = resp.json()

        phases = {sig["phase"] for sig in data["signatures"]}
        # At minimum, the built-in set covers these phases
        assert "install_hooks" in phases
        assert "code_patterns" in phases
        assert "obfuscation" in phases


class TestThreatReport:
    """Tests for POST /v1/report."""

    def test_submit_report(self, client: TestClient) -> None:
        """Submitting a threat report returns 201 with a report ID."""
        payload = {
            "package_name": "sus-package",
            "package_version": "2.0.0",
            "ecosystem": "npm",
            "reason": "Contains obfuscated code that phones home",
            "evidence": "Found base64-encoded URL in postinstall script",
            "reporter_email": "reporter@example.com",
        }
        resp = client.post("/v1/report", json=payload)
        assert resp.status_code == 201

        data = resp.json()
        assert "report_id" in data
        assert data["status"] == "received"
        assert "Thank you" in data["message"]

    def test_submit_report_minimal(self, client: TestClient) -> None:
        """Submitting a report with only required fields succeeds."""
        payload = {
            "package_name": "minimal-report",
            "reason": "Looks suspicious",
        }
        resp = client.post("/v1/report", json=payload)
        assert resp.status_code == 201

    def test_submit_report_missing_required(self, client: TestClient) -> None:
        """Missing required fields returns 422."""
        resp = client.post(
            "/v1/report",
            json={
                "package_name": "missing-reason",
            },
        )
        assert resp.status_code == 422


class TestPublisherReputation:
    """Tests for GET /v1/publisher/{publisher_id}."""

    def test_unknown_publisher_returns_default(self, client: TestClient) -> None:
        """Unknown publisher should return a default neutral profile."""
        resp = client.get("/v1/publisher/unknown-person")
        assert resp.status_code == 200

        data = resp.json()
        assert data["publisher_id"] == "unknown-person"
        assert data["trust_score"] == 50.0
        assert "not yet indexed" in data["notes"].lower()

    def test_known_publisher(self, client: TestClient) -> None:
        """Known publisher should return their actual reputation."""
        # Seed a publisher
        pub = {
            "id": "pub-1",
            "publisher_id": "known-dev",
            "trust_score": 85.0,
            "total_packages": 42,
            "flagged_count": 1,
            "notes": "Generally trusted developer",
        }
        _memory_store.setdefault("publishers", {})["pub-1"] = pub

        resp = client.get("/v1/publisher/known-dev")
        assert resp.status_code == 200

        data = resp.json()
        assert data["publisher_id"] == "known-dev"
        assert data["trust_score"] == 85.0
        assert data["total_packages"] == 42
