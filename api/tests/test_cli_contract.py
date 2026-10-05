"""
Sigil API — CLI contract tests.

Every request body the `sigil` CLI sends for `sigil scan --submit`,
`--enhanced`, `--enrich`, `sigil report` and `sigil explain` must be accepted,
both from the released CLI 1.3.7 and from the CLI in this tree, and the
responses must carry what each CLI reads. The bodies are the shared golden
fixtures in tests/fixtures/api_contract (see its README); the Rust side tests
against the same files in cli/src/api.rs.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.database import db
from api.models import Finding, ScanPhase, Severity

CONTRACT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "api_contract"


def fixture(rel: str) -> Any:
    return json.loads((CONTRACT / rel).read_text())


SCAN_BODIES = [
    "cli-1.3.7/scan_submit.json",
    "cli-current/scan_submit.json",
    "cli-1.3.7/explain_scan.json",
    "cli-current/explain_scan.json",
]
ENHANCED_BODIES = ["cli-1.3.7/scan_enhanced.json", "cli-current/scan_enhanced.json"]
REPORT_BODIES = ["cli-1.3.7/report.json", "cli-current/report.json"]

# The phases the captured scans contain, as the API stores them.
CAPTURED_PHASES = {
    "install_hooks",
    "code_patterns",
    "network_exfil",
    "inference_security",
}


# ---------------------------------------------------------------------------
# POST /v1/scan — `sigil scan --submit` and `sigil explain`
# ---------------------------------------------------------------------------


class TestScanSubmission:
    @pytest.mark.parametrize("body_path", SCAN_BODIES)
    def test_cli_scan_body_is_accepted_and_stored_normalised(
        self, client: TestClient, auth_headers: dict[str, str], body_path: str
    ) -> None:
        body = fixture(body_path)
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text

        data = resp.json()
        # Current CLI reads scan_id; CLI 1.3.7 requires `id` and `status`.
        assert data["scan_id"]
        assert data["id"] == data["scan_id"]
        assert data["status"] == "completed"
        assert {f["phase"] for f in data["findings"]} == CAPTURED_PHASES
        assert {f["severity"] for f in data["findings"]} <= {s.value for s in Severity}

        row = db._memory_store["scans"][data["scan_id"]]
        assert len(row["findings_json"]) == len(body["findings"])
        assert {f["phase"] for f in row["findings_json"]} == CAPTURED_PHASES

    def test_released_cli_submit_without_target_is_filed_as_cli_scan(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        body = fixture("cli-1.3.7/scan_submit.json")
        assert "target" not in body  # the raw ScanResult 1.3.7 posts
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["target"] == "cli-scan"
        assert resp.json()["files_scanned"] == body["files_scanned"]

    def test_current_cli_sends_the_fixed_target_and_its_own_verdict(self) -> None:
        body = fixture("cli-current/scan_submit.json")
        assert body["target"] == "cli-scan"
        assert set(body["metadata"]) == {"source", "cli_score", "cli_verdict"}

    def test_missing_target_is_still_refused_for_other_clients(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.post(
            "/v1/scan",
            json={"target_type": "pip", "findings": [], "score": 0},
            headers=auth_headers,
        )
        assert resp.status_code == 422
        assert ("body", "target") in [tuple(e["loc"]) for e in resp.json()["errors"]]

    def test_unknown_phase_and_severity_are_still_refused(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        finding = {"rule": "R", "file": "a.py", "snippet": "", "weight": 1}
        for bad in (
            {**finding, "phase": "NotAPhase", "severity": "High"},
            {**finding, "phase": "CodePatterns", "severity": "Severe"},
        ):
            resp = client.post(
                "/v1/scan",
                json={"target": "t", "findings": [bad]},
                headers=auth_headers,
            )
            assert resp.status_code == 422, bad


class TestFindingSpellings:
    @pytest.mark.parametrize(
        ("spelling", "expected"),
        [
            ("InstallHooks", ScanPhase.INSTALL_HOOKS),
            ("install_hooks", ScanPhase.INSTALL_HOOKS),
            ("InferenceSecurity", ScanPhase.INFERENCE_SECURITY),
            ("inferencesecurity", ScanPhase.INFERENCE_SECURITY),
            ("inference_security", ScanPhase.INFERENCE_SECURITY),
            ("LlmAnalysis", ScanPhase.LLM_ANALYSIS),
            ("SkillSecurity", ScanPhase.SKILL_SECURITY),
        ],
    )
    def test_phase_spellings(self, spelling: str, expected: ScanPhase) -> None:
        finding = Finding(phase=spelling, rule="R", severity="High", file="a")
        assert finding.phase is expected
        assert finding.severity is Severity.HIGH


# ---------------------------------------------------------------------------
# POST /v1/scan-enhanced — `sigil scan --enhanced`
# ---------------------------------------------------------------------------


class TestEnhancedScan:
    @pytest.mark.parametrize("body_path", ENHANCED_BODIES)
    def test_free_plan_gets_static_result_and_upgrade_notice(
        self, client: TestClient, auth_headers: dict[str, str], body_path: str
    ) -> None:
        resp = client.post(
            "/v1/scan-enhanced", json=fixture(body_path), headers=auth_headers
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["id"] == data["scan_id"]
        assert data["metadata"]["upgrade_required"] is True
        assert data["metadata"].get("llm_analysis_performed") is not True

    def _as_pro(self, client: TestClient) -> None:
        from api.middleware.tier_check import get_scan_capabilities

        client.app.dependency_overrides[get_scan_capabilities] = lambda: {
            "llm_analysis": True,
            "tier": "pro",
            "upgrade_required": False,
        }

    def test_pro_llm_failure_falls_back_to_static_without_leaking_detail(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        self._as_pro(client)
        with patch(
            "api.routers.scan.scanner_engine.scan_with_pro_features",
            new=AsyncMock(side_effect=RuntimeError("internal-detail-canary")),
        ):
            resp = client.post(
                "/v1/scan-enhanced",
                json=fixture("cli-current/scan_enhanced.json"),
                headers=auth_headers,
            )
        assert resp.status_code == 200, resp.text
        meta = resp.json()["metadata"]
        assert meta["llm_analysis_performed"] is False
        assert meta["fallback_to_static"] is True
        assert meta["llm_error"] == "RuntimeError"
        assert "internal-detail-canary" not in resp.text

    def test_pro_llm_success_is_marked_and_adds_llm_findings(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        self._as_pro(client)
        llm_finding = Finding(
            phase=ScanPhase.LLM_ANALYSIS,
            rule="LLM-TEST-1",
            severity=Severity.HIGH,
            file="src/net.py",
            line=2,
            description="contract-test LLM finding",
        )
        with (
            patch(
                "api.routers.scan.scanner_engine.scan_with_pro_features",
                new=AsyncMock(return_value=[llm_finding]),
            ),
            patch(
                "api.routers.scan.subscription_service.track_pro_feature_usage",
                new=AsyncMock(return_value=None),
            ),
        ):
            resp = client.post(
                "/v1/scan-enhanced",
                json=fixture("cli-1.3.7/scan_enhanced.json"),
                headers=auth_headers,
            )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # What the current CLI keys on before it reports LLM analysis.
        assert data["metadata"]["llm_analysis_performed"] is True
        llm = [f for f in data["findings"] if f["phase"] == "llm_analysis"]
        assert [f["rule"] for f in llm] == ["LLM-TEST-1"]
        assert data["id"] == data["scan_id"]


# ---------------------------------------------------------------------------
# POST /v1/report — `sigil report` and the dashboard
# ---------------------------------------------------------------------------


class TestThreatReportContract:
    @pytest.mark.parametrize("body_path", [*REPORT_BODIES, "dashboard/report.json"])
    def test_report_body_is_accepted(self, client: TestClient, body_path: str) -> None:
        resp = client.post("/v1/report", json=fixture(body_path))
        assert resp.status_code == 201, resp.text
        data = resp.json()
        # Dashboard and current CLI read report_id; CLI 1.3.7 reads id.
        assert data["id"] == data["report_id"]
        assert data["status"] == "received"
        # threat_reports.id is UNIQUEIDENTIFIER: a full GUID, not a hex prefix.
        assert str(uuid.UUID(data["report_id"])) == data["report_id"]

    def test_both_cli_versions_file_the_same_record(self, client: TestClient) -> None:
        stored = []
        for body_path in REPORT_BODIES:
            report_id = client.post("/v1/report", json=fixture(body_path)).json()[
                "report_id"
            ]
            row = db._memory_store["threat_reports"][report_id]
            stored.append(
                {k: row[k] for k in ("package_name", "ecosystem", "reason", "evidence")}
            )
        released = fixture("cli-1.3.7/report.json")
        assert stored[0] == stored[1]
        assert stored[0] == {
            "package_name": f"sha256:{released['hash']}",
            "ecosystem": "unknown",
            "reason": released["description"],
            "evidence": f"Threat type: {released['threat_type']}\n"
            f"SHA-256: {released['hash']}",
        }

    def test_dashboard_report_is_stored_as_sent(self, client: TestClient) -> None:
        body = fixture("dashboard/report.json")
        report_id = client.post("/v1/report", json=body).json()["report_id"]
        row = db._memory_store["threat_reports"][report_id]
        for key in ("package_name", "ecosystem", "reason", "evidence"):
            assert row[key] == body[key]

    def test_hash_report_without_description_is_refused(
        self, client: TestClient
    ) -> None:
        resp = client.post("/v1/report", json={"hash": "ab", "threat_type": "x"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /v1/threat/{hash} — `sigil scan --enrich`
# ---------------------------------------------------------------------------


class TestThreatLookupContract:
    def _seed(self, digest: str) -> None:
        db._memory_store.setdefault("threats", {})["contract-1"] = {
            "id": "contract-1",
            "hash": digest,
            "package_name": "contract-test-pkg",
            "version": "0.0.1",
            "severity": "CRITICAL",
            "source": "internal",
            "description": "seeded contract-test threat entry",
            "confirmed_at": "2026-10-01T00:00:00",
        }

    def test_match_carries_the_fields_cli_1_3_7_requires(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        captured = fixture("api-patched/threat_lookup_response.json")
        self._seed(captured["hash"])
        resp = client.get(f"/v1/threat/{captured['hash']}", headers=pro_auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["known_malicious"] is True
        assert data["references"] == []
        assert set(data) == set(captured)
        # Every field the deployed API returned is still there, unchanged.
        deployed = fixture("api-deployed/threat_lookup_response.json")
        assert {k: data[k] for k in deployed} == deployed

    def test_unknown_hash_is_still_404(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/v1/threat/" + "0" * 64, headers=pro_auth_headers)
        assert resp.status_code == 404

    def test_free_plan_is_still_refused(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/v1/threat/" + "0" * 64, headers=auth_headers)
        assert resp.status_code == 403
