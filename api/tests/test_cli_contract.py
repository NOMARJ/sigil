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
import unicodedata
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.database import db
from api.models import EnhancedScanResponse, Finding, ScanPhase, Severity
from api.services.scanner import _RUST_PHASE_MAP, _map_rust_finding

CONTRACT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "api_contract"
MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


def fixture(rel: str) -> Any:
    return json.loads((CONTRACT / rel).read_text())


def cli_1_3_7_reads_as_success(body: dict[str, Any]) -> bool:
    """Whether CLI 1.3.7 parses *body* as a successful scan response.

    1.3.7's `ScanResponse` is `{id: String, status: String, message:
    Option<String>}` (cli/src/api.rs at v1.3.7). When a scan or enhanced
    response parses, it prints success ("results submitted to Sigil cloud",
    "Enhanced LLM analysis completed") without reading anything else.
    """
    return isinstance(body.get("id"), str) and isinstance(body.get("status"), str)


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
        assert cli_1_3_7_reads_as_success(data)
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

    def test_released_cli_suppressions_and_provenance_are_not_stored(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # CLI 1.3.7 posts its whole ScanResult. Beyond the fixture's `scanner`
        # and `platform`, a result with suppressions also carries the
        # suppressed findings and their attributions, one of them a reason
        # the user wrote. The API keeps only the active findings.
        body = fixture("cli-1.3.7/scan_submit.json")
        assert "scanner" in body and "platform" in body
        suppressed = {
            **body["findings"][0],
            "rule": "SUPPRESSED-CANARY-1",
            "snippet": "suppressed-snippet-canary",
        }
        inline = {**suppressed, "rule": "SUPPRESSED-CANARY-2"}
        body = {
            **body,
            "suppressed_findings": [suppressed],
            "suppressed_by": "ledger:approved-source-canary#ab12 approved 2026-10-01",
            "inline_suppressed": [inline],
            "inline_suppressions": [
                "src/app.js:2 SUPPRESSED-CANARY-2 — user-reason-canary"
            ],
        }
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text

        row = db._memory_store["scans"][resp.json()["scan_id"]]
        assert row["metadata_json"] == {}
        assert [f["rule"] for f in row["findings_json"]] == [
            f["rule"] for f in fixture("cli-1.3.7/scan_submit.json")["findings"]
        ]
        stored = json.dumps(row, default=str)
        for canary in (
            "SUPPRESSED-CANARY",
            "suppressed-snippet-canary",
            "approved-source-canary",
            "user-reason-canary",
            body["scanner"]["corpus_digest"],
        ):
            assert canary not in stored, canary
        assert "canary" not in resp.text

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


# Every phase the CLI has (`Phase::ALL`), in both spellings it sends. The Rust
# test `phases_fixture_lists_every_cli_phase` (cli/src/api.rs) fails when the
# CLI gains a phase this file does not list, so a new CLI phase reaches these
# tests before it can reach the API as an HTTP 422.
CLI_PHASES = fixture("cli-current/phases.json")["phases"]


class TestCliPhaseCoverage:
    @pytest.mark.parametrize("phase", CLI_PHASES, ids=lambda p: p["api"])
    def test_every_cli_phase_is_an_api_phase(self, phase: dict[str, str]) -> None:
        for spelling in (phase["serde"], phase["api"]):
            finding = Finding(phase=spelling, rule="R", severity="High", file="a")
            assert finding.phase.value == phase["api"], spelling

    @pytest.mark.parametrize("phase", CLI_PHASES, ids=lambda p: p["api"])
    def test_rust_engine_path_files_a_finding_under_the_same_phase(
        self, phase: dict[str, str]
    ) -> None:
        # The API's own Rust-engine scans (SIGIL_RUST_ENGINE) and CLI
        # submissions must not file one rule under two phases.
        raw = {"phase": phase["serde"], "rule": "R-1", "severity": "High", "file": "a"}
        assert _map_rust_finding(raw).phase is Finding(**raw).phase

    def test_inference_security_is_not_filed_as_llm_analysis(self) -> None:
        raw = {
            "phase": "InferenceSecurity",
            "rule": "INFER-001",
            "severity": "High",
            "file": "c.py",
        }
        assert _map_rust_finding(raw).phase is ScanPhase.INFERENCE_SECURITY

    def test_rust_engine_map_covers_every_cli_phase(self) -> None:
        assert set(_RUST_PHASE_MAP) == {p["serde"] for p in CLI_PHASES}


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
        assert data["scan_id"]
        assert data["metadata"]["upgrade_required"] is True
        assert data["metadata"].get("llm_analysis_performed") is not True
        # No LLM analysis ran, so CLI 1.3.7 must not be able to read this as
        # its success ("Enhanced LLM analysis completed"): no `id` alias.
        assert "id" not in data
        assert not cli_1_3_7_reads_as_success(data)

    @staticmethod
    def _assert_files_not_kept(
        client: TestClient,
        headers: dict[str, str],
        scan_id: str,
        body: dict[str, Any],
    ) -> None:
        """The scan record, and the scan-detail API, hold no uploaded file."""
        uploaded = body["metadata"]["file_contents"]
        multi_line = [c for c in uploaded.values() if c.strip().count("\n") >= 1]
        assert multi_line, "the fixture needs a multi-line file to look for"

        row = db._memory_store["scans"][scan_id]
        # Everything else the request's metadata held is still recorded.
        assert row["metadata_json"] == {
            k: v for k, v in body["metadata"].items() if k != "file_contents"
        }

        detail = client.get(f"/v1/scans/{scan_id}", headers=headers)
        assert detail.status_code == 200, detail.text
        assert "file_contents" not in detail.json()["metadata_json"]
        for stored in (json.dumps(row, default=str), detail.text):
            for content in multi_line:
                assert json.dumps(content)[1:-1] not in stored

    @pytest.mark.parametrize("body_path", ENHANCED_BODIES)
    def test_uploaded_files_are_not_stored_with_the_scan(
        self, client: TestClient, auth_headers: dict[str, str], body_path: str
    ) -> None:
        body = fixture(body_path)
        resp = client.post("/v1/scan-enhanced", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        self._assert_files_not_kept(client, auth_headers, resp.json()["scan_id"], body)

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
        assert resp.json()["scan_id"]
        assert not cli_1_3_7_reads_as_success(resp.json())

    def test_pro_llm_step_as_deployed_is_not_reported_as_analysis(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # The real LLM step, unpatched: it is called without a path or
        # content and raises, so the response is the static fallback.
        self._as_pro(client)
        resp = client.post(
            "/v1/scan-enhanced",
            json=fixture("cli-1.3.7/scan_enhanced.json"),
            headers=auth_headers,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["metadata"]["llm_analysis_performed"] is False
        assert data["metadata"]["llm_error"] == "ValueError"
        assert not cli_1_3_7_reads_as_success(data)

    def test_pro_without_files_is_not_reported_as_analysis(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        self._as_pro(client)
        body = fixture("cli-current/scan_submit.json")
        assert "file_contents" not in body["metadata"]
        resp = client.post("/v1/scan-enhanced", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["metadata"]["llm_analysis_performed"] is False
        assert data["metadata"]["reason"]
        assert not cli_1_3_7_reads_as_success(data)

    def test_response_schema_keeps_the_fields_and_an_optional_id(self) -> None:
        # The OpenAPI document is built from this schema.
        schema = EnhancedScanResponse.model_json_schema(mode="serialization")
        assert {"scan_id", "id", "status", "metadata", "findings"} <= set(
            schema["properties"]
        )
        assert "scan_id" in schema["required"]
        assert "id" not in schema["required"]

    def test_migration_removes_the_keys_no_longer_stored(self) -> None:
        # Scans stored before the fix kept the uploaded files in
        # metadata_json; migration 011 removes the same keys the endpoint
        # now drops. (SQL not executed here: the tests use the memory store.)
        from api.routers.scan import _UPLOADED_SOURCE_KEYS

        sql = (
            MIGRATIONS / "011_remove_uploaded_files_from_scan_metadata.sql"
        ).read_text()
        for key in _UPLOADED_SOURCE_KEYS:
            assert f"'$.{key}', NULL" in sql, key
            assert f"N'{key}'" in sql, key

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
        llm_step = AsyncMock(return_value=[llm_finding])
        body = fixture("cli-1.3.7/scan_enhanced.json")
        with (
            patch(
                "api.routers.scan.scanner_engine.scan_with_pro_features",
                new=llm_step,
            ),
            patch(
                "api.routers.scan.subscription_service.track_pro_feature_usage",
                new=AsyncMock(return_value=None),
            ),
        ):
            resp = client.post("/v1/scan-enhanced", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # What the current CLI keys on before it reports LLM analysis.
        assert data["metadata"]["llm_analysis_performed"] is True
        llm = [f for f in data["findings"] if f["phase"] == "llm_analysis"]
        assert [f["rule"] for f in llm] == ["LLM-TEST-1"]
        # LLM analysis ran: CLI 1.3.7's "completed" is true, so it may parse.
        assert data["id"] == data["scan_id"]
        assert cli_1_3_7_reads_as_success(data)
        # The LLM step still gets the uploaded files; the scan record does not.
        context = llm_step.call_args.kwargs["repository_context"]
        assert context["file_contents"] == body["metadata"]["file_contents"]
        self._assert_files_not_kept(client, auth_headers, data["scan_id"], body)


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

    @pytest.mark.parametrize(
        "bad_hash",
        ["x" * 300, "x|.*", "ab", "0" * 63, "0" * 65, "g" * 64, "sha256:" + "0" * 64],
    )
    def test_hash_report_needs_a_sha256_digest(
        self, client: TestClient, bad_hash: str
    ) -> None:
        resp = client.post(
            "/v1/report",
            json={"hash": bad_hash, "threat_type": "malware", "description": "d"},
        )
        assert resp.status_code == 422, resp.text
        assert not db._memory_store.get("threat_reports")

    def test_hash_report_digest_is_accepted_in_any_case(
        self, client: TestClient
    ) -> None:
        digest = fixture("cli-1.3.7/report.json")["hash"]
        resp = client.post(
            "/v1/report",
            json={"hash": f"  {digest.upper()} ", "description": "d"},
        )
        assert resp.status_code == 201, resp.text
        row = db._memory_store["threat_reports"][resp.json()["report_id"]]
        assert row["package_name"] == f"sha256:{digest}"


class TestReportPromotion:
    """Confirming a report creates a threat entry (POST /v1/report -> review)."""

    @staticmethod
    def _confirm(client: TestClient, headers: dict[str, str], report_id: str) -> None:
        for new_status in ("under_review", "confirmed"):
            resp = client.patch(
                f"/v1/threat-reports/{report_id}",
                json={"status": new_status},
                headers=headers,
            )
            assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize("body_path", REPORT_BODIES)
    def test_confirmed_hash_report_matches_lookups_of_that_hash(
        self,
        client: TestClient,
        reviewer_auth_headers: dict[str, str],
        body_path: str,
    ) -> None:
        digest = fixture("cli-1.3.7/report.json")["hash"]
        report_id = client.post("/v1/report", json=fixture(body_path)).json()[
            "report_id"
        ]
        self._confirm(client, reviewer_auth_headers, report_id)

        threats = list(db._memory_store["threats"].values())
        assert [t["hash"] for t in threats] == [digest]
        # threats.id is UNIQUEIDENTIFIER: a full GUID, not a hex prefix.
        assert str(uuid.UUID(threats[0]["id"])) == threats[0]["id"]

        resp = client.get(f"/v1/threat/{digest}", headers=reviewer_auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["package_name"] == f"sha256:{digest}"
        assert resp.json()["source"] == "community"
        # CLI 1.3.7 prints only the description: it says whose text it is.
        reason = fixture("cli-1.3.7/report.json")["description"]
        assert resp.json()["description"] == (
            f"Community report (unverified hash): {reason}"
        )
        # No import-matching signature for a hash, and the CLI-composed
        # evidence is never used as a regex.
        assert not db._memory_store.get("signatures")

    def test_confirmed_package_report_gets_a_guid_and_a_signature(
        self, client: TestClient, reviewer_auth_headers: dict[str, str]
    ) -> None:
        report_id = client.post(
            "/v1/report", json=fixture("dashboard/report.json")
        ).json()["report_id"]
        self._confirm(client, reviewer_auth_headers, report_id)

        (threat,) = db._memory_store["threats"].values()
        assert str(uuid.UUID(threat["id"])) == threat["id"]
        assert threat["package_name"] == "contract-test-pkg"
        (signature,) = db._memory_store["signatures"].values()
        assert signature["id"] == f"sig-community-{threat['id']}"

        resp = client.get(f"/v1/threat/{threat['hash']}", headers=reviewer_auth_headers)
        assert resp.status_code == 200, resp.text
        reason = fixture("dashboard/report.json")["reason"]
        assert resp.json()["description"] == f"Community report: {reason}"


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

    @pytest.mark.parametrize(
        ("package_name", "description", "expected"),
        [
            ("sha256:" + "a" * 64, "", "Community report (unverified hash)"),
            ("evil-pkg", "  ", "Community report"),
            ("sha256:not-a-digest", "text", "Community report: text"),
        ],
    )
    def test_community_entry_text_is_attributed(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
        package_name: str,
        description: str,
        expected: str,
    ) -> None:
        digest = "e" * 64
        db._memory_store.setdefault("threats", {})["community-1"] = {
            "id": "community-1",
            "hash": digest,
            "package_name": package_name,
            "severity": "HIGH",
            "source": "community",
            "description": description,
        }
        resp = client.get(f"/v1/threat/{digest}", headers=pro_auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["description"] == expected

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
        # The body the CLI's 403 handling is tested against (cli/src/api.rs).
        assert resp.json() == fixture("api-patched/threat_lookup_403_free_plan.json")

    def test_match_text_carries_no_control_characters(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        # CLI 1.3.7 prints the description raw; a community entry's
        # description is the reporter's text.
        hostile = (
            "evil\x1b[2J\x1b]8;;https://x.invalid\x07click\x1b]8;;\x07\r\nfake\x85"
        )
        digest = "f" * 64
        db._memory_store.setdefault("threats", {})["hostile"] = {
            "id": "hostile",
            "hash": digest,
            "package_name": "pkg\x1b[31m",
            "version": "1.0\r",
            "severity": "HIGH",
            "source": "community\x07",
            "description": hostile,
        }
        resp = client.get(f"/v1/threat/{digest}", headers=pro_auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        for key, value in data.items():
            if isinstance(value, str):
                assert not any(unicodedata.category(c) == "Cc" for c in value), key
        assert data["description"].startswith("evil ")
        assert data["description"].rstrip().endswith("fake")
        assert data["package_name"] == "pkg [31m"
        assert data["hash"] == digest
