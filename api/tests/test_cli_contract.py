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

import hashlib
import itertools
import json
import unicodedata
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.database import db
from api.models import (
    EnhancedScanResponse,
    Finding,
    ScanPhase,
    Severity,
    without_control_characters,
)
from api.services.scanner import _RUST_PHASE_MAP, _map_rust_finding
from api.services.scoring import PHASE_WEIGHTS, score_finding
from api.services.threat_correlator import ThreatCorrelator

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


# Unicode categories that must not reach a terminal from the API's text:
# controls, format characters (bidi overrides, zero-width) and the line and
# paragraph separators. The CLI's `terminal_text` replaces the same set.
UNPRINTABLE_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}


def unprintable_chars(value: str) -> list[str]:
    return [c for c in value if unicodedata.category(c) in UNPRINTABLE_CATEGORIES]


# The four keys of the Rust CLI's ScanResult that, with no `target`, mark a
# body as `sigil scan --submit` <= 1.3.7 (api/models.py).
CLI_SCAN_RESULT = {"score": 5, "verdict": "HighRisk", "duration_ms": 3, "findings": []}

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

    def test_the_four_cli_keys_alone_are_filed_as_cli_scan(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.post("/v1/scan", json=CLI_SCAN_RESULT, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["target"] == "cli-scan"

    @pytest.mark.parametrize(
        "missing", list(CLI_SCAN_RESULT), ids=lambda key: f"without-{key}"
    )
    def test_three_of_the_four_cli_keys_are_refused(
        self, client: TestClient, auth_headers: dict[str, str], missing: str
    ) -> None:
        # Only the whole set marks the released CLI; a body with one key
        # missing is some other client's, and needs its `target`.
        body = {k: v for k, v in CLI_SCAN_RESULT.items() if k != missing}
        assert len(body) == 3 and "target" not in body
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 422, resp.text
        assert ("body", "target") in [tuple(e["loc"]) for e in resp.json()["errors"]]

    @pytest.mark.parametrize(
        "keys",
        [()] + [c for n in (1, 2) for c in itertools.combinations(CLI_SCAN_RESULT, n)],
    )
    def test_fewer_cli_keys_are_refused(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        keys: tuple[str, ...],
    ) -> None:
        body = {k: CLI_SCAN_RESULT[k] for k in keys}
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 422, resp.text

    def test_an_explicit_null_target_is_refused_not_filled_in(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # A `target` key that is present is the client's own choice, null
        # included: only an absent one is filled in for the released CLI.
        resp = client.post(
            "/v1/scan",
            json={**CLI_SCAN_RESULT, "target": None},
            headers=auth_headers,
        )
        assert resp.status_code == 422, resp.text
        assert ("body", "target") in [tuple(e["loc"]) for e in resp.json()["errors"]]

    def test_the_cli_keys_do_not_excuse_an_invalid_finding(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        bad = {"rule": "R", "file": "a.py", "phase": "NotAPhase", "severity": "High"}
        body = {**CLI_SCAN_RESULT, "findings": [bad]}
        resp = client.post("/v1/scan", json=body, headers=auth_headers)
        assert resp.status_code == 422, resp.text

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

        # The endpoints that return a stored scan's metadata: the detail
        # endpoints and, with the in-memory store, the list endpoints.
        detail = client.get(f"/v1/scans/{scan_id}", headers=headers)
        assert detail.status_code == 200, detail.text
        assert "file_contents" not in detail.json()["metadata_json"]
        listings = [
            client.get("/scans?scope=own", headers=headers),
            client.get("/v1/scans", headers=headers),
        ]
        for listing in listings:
            assert listing.status_code == 200, listing.text
            assert scan_id in listing.text, listing.url
        for stored in (
            json.dumps(row, default=str),
            detail.text,
            *(listing.text for listing in listings),
        ):
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

    def test_only_the_scans_own_metadata_keys_are_stored(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # A denylist of the CLI's key names would store the files of any
        # other client that calls them something else.
        body = fixture("cli-current/scan_enhanced.json")
        body["metadata"].update(
            {
                "content": "SECRET=1\nSECRET=2\n",
                "filename": "a.py",
                "files": {"a.py": "SECRET=3\nSECRET=4\n"},
                "sources": ["SECRET=5\nSECRET=6\n"],
                "hash": "a" * 64,
                "publisher": "pub-1",
            }
        )
        resp = client.post("/v1/scan-enhanced", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        scan_id = resp.json()["scan_id"]
        stored = db._memory_store["scans"][scan_id]["metadata_json"]
        assert set(stored) == {
            "source",
            "cli_score",
            "cli_verdict",
            "hash",
            "publisher",
        }
        for listing in (
            client.get("/scans?scope=own", headers=auth_headers),
            client.get(f"/v1/scans/{scan_id}", headers=auth_headers),
        ):
            assert listing.status_code == 200, listing.text
            assert "SECRET=" not in listing.text

    def test_the_llm_step_still_reads_the_uploaded_files(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # Only the stored copy lacks them.
        self._as_pro(client)
        body = fixture("cli-current/scan_enhanced.json")
        analyse = AsyncMock(return_value=[])
        with patch(
            "api.routers.scan.scanner_engine.scan_with_pro_features", new=analyse
        ):
            resp = client.post("/v1/scan-enhanced", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        context = analyse.await_args.kwargs["repository_context"]
        assert context["file_contents"] == body["metadata"]["file_contents"]

    def test_migration_removes_the_keys_the_old_api_stored(self) -> None:
        # Scans stored before the fix kept the uploaded files in
        # metadata_json; migration 011 removes the keys the old endpoint
        # stored them under. (SQL not executed here: the tests use the memory
        # store, and no MSSQL was available.)
        sql = (
            MIGRATIONS / "011_remove_uploaded_files_from_scan_metadata.sql"
        ).read_text()
        statement = "\n".join(
            line for line in sql.splitlines() if not line.lstrip().startswith("--")
        )
        for key in ("file_contents", "content"):
            assert f"'$.{key}', NULL" in statement, key
            assert f"N'{key}'" in statement, key
        # OPENJSON is never handed text that is not JSON: T-SQL does not
        # promise to evaluate `ISJSON(...) = 1 AND EXISTS (...)` left to right.
        assert "OPENJSON(CASE WHEN ISJSON(scans.metadata_json) = 1" in statement
        assert "WHERE ISJSON" not in statement
        # What the header says about the exposure and the scope.
        header = sql.split("UPDATE scans")[0]
        for phrase in ("GET /scans", "GET /v1/scans", "EVERY stored scan"):
            assert phrase in header, phrase

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
        # The scan is stored before the LLM step runs and nothing from the step
        # is stored: the LLM finding and the recalculated score are in this
        # response only (docs/CLI_LLM_FEATURES.md, "What comes back"), while
        # the CLI prints this scan id next to the LLM findings.
        stored = client.get(f"/v1/scans/{data['scan_id']}", headers=auth_headers)
        assert stored.status_code == 200, stored.text
        record = stored.json()
        assert [f["phase"] for f in record["findings_json"]].count("llm_analysis") == 0
        assert record["findings_count"] == len(body["findings"])
        assert len(data["findings"]) == record["findings_count"] + 1
        assert record["risk_score"] == data["metadata"]["original_risk_score"]
        assert data["risk_score"] > record["risk_score"]


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
        assert data["report_id"]

    @pytest.mark.parametrize("body_path", [*REPORT_BODIES, "dashboard/report.json"])
    def test_report_id_is_a_guid(self, client: TestClient, body_path: str) -> None:
        # schema.sql declares threat_reports.id UNIQUEIDENTIFIER, which only a
        # GUID converts to: a truncated hex id would fail to insert on MSSQL
        # (this suite uses the in-memory store, which accepts any string).
        data = client.post("/v1/report", json=fixture(body_path)).json()
        parsed = uuid.UUID(data["report_id"])
        assert str(parsed) == data["report_id"]
        row = db._memory_store["threat_reports"][data["report_id"]]
        assert row["id"] == data["report_id"]

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
    """What confirming a report does (POST /v1/report -> review).

    A `sigil report <hash>` report is filed as package `sha256:<hash>` and is
    recorded and promoted like any other report: the threat entry is keyed by
    a hash of the package identity (`ecosystem:name:version`), never by the
    hash the reporter typed. So a confirmed hash report is not findable by
    that hash: `sigil scan --enrich`, POST /v1/verify and POST /v1/scan do
    not match it.
    """

    @staticmethod
    def _confirm(client: TestClient, headers: dict[str, str], report_id: str) -> None:
        for new_status in ("under_review", "confirmed"):
            resp = client.patch(
                f"/v1/threat-reports/{report_id}",
                json={"status": new_status},
                headers=headers,
            )
            assert resp.status_code == 200, resp.text

    @staticmethod
    def _identity_hash(ecosystem: str, name: str, version: str = "") -> str:
        return hashlib.sha256(f"{ecosystem}:{name}:{version}".encode()).hexdigest()

    @staticmethod
    def _verify(client: TestClient, digest: str) -> dict[str, Any]:
        resp = client.post(
            "/v1/verify",
            json={
                "package_name": "some-package",
                "package_version": "1.0.0",
                "ecosystem": "npm",
                "artifact_hash": digest,
            },
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    @staticmethod
    def _scan(
        client: TestClient, headers: dict[str, str], metadata: dict[str, Any]
    ) -> dict[str, Any]:
        resp = client.post(
            "/v1/scan",
            json={
                "target": "t",
                "target_type": "directory",
                "findings": [],
                "metadata": metadata,
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    @pytest.mark.parametrize("body_path", REPORT_BODIES)
    def test_confirmed_hash_report_is_keyed_by_package_identity_not_its_hash(
        self,
        client: TestClient,
        pro_auth_headers: dict[str, str],
        reviewer_auth_headers: dict[str, str],
        body_path: str,
    ) -> None:
        digest = fixture("cli-1.3.7/report.json")["hash"]
        report_id = client.post("/v1/report", json=fixture(body_path)).json()[
            "report_id"
        ]
        self._confirm(client, reviewer_auth_headers, report_id)

        (threat,) = db._memory_store["threats"].values()
        assert threat["package_name"] == f"sha256:{digest}"
        assert threat["hash"] == self._identity_hash("unknown", f"sha256:{digest}")
        assert threat["hash"] != digest
        assert threat["source"] == "community"

        # `sigil scan --enrich` (GET /v1/threat/{hash}): the reported hash is
        # an unknown hash; the entry is found only under its identity hash.
        resp = client.get(f"/v1/threat/{digest}", headers=pro_auth_headers)
        assert resp.status_code == 404, resp.text
        resp = client.get(f"/v1/threat/{threat['hash']}", headers=pro_auth_headers)
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize("body_path", REPORT_BODIES)
    def test_confirmed_hash_report_changes_no_verify_verdict_or_scan_score(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        reviewer_auth_headers: dict[str, str],
        body_path: str,
    ) -> None:
        digest = fixture("cli-1.3.7/report.json")["hash"]
        verify_keys = ("verdict", "risk_score", "verified", "findings_summary")
        scan_keys = ("verdict", "risk_score", "threat_intel_hits")

        def verdicts() -> tuple[dict[str, Any], list[dict[str, Any]]]:
            verify = self._verify(client, digest)
            scans = [
                self._scan(client, auth_headers, metadata)
                for metadata in ({"hashes": [digest]}, {"hash": digest})
            ]
            return (
                {k: verify[k] for k in verify_keys},
                [{k: scan[k] for k in scan_keys} for scan in scans],
            )

        before = verdicts()
        report_id = client.post("/v1/report", json=fixture(body_path)).json()[
            "report_id"
        ]
        self._confirm(client, reviewer_auth_headers, report_id)
        assert db._memory_store["threats"], "the report was confirmed"

        assert verdicts() == before
        verify, scans = before
        assert verify["verdict"] == "LOW_RISK"
        assert verify["risk_score"] == 0.0
        assert [scan["risk_score"] for scan in scans] == [0.0, 0.0]
        assert [scan["threat_intel_hits"] for scan in scans] == [[], []]

    def test_confirmed_package_report_is_promoted_as_before(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        reviewer_auth_headers: dict[str, str],
    ) -> None:
        # Unchanged by this fix, for contrast: a package report's entry is
        # keyed by the hash of its identity, which a verify request or a scan
        # can carry, and it gets an import-matching signature.
        body = fixture("dashboard/report.json")
        report_id = client.post("/v1/report", json=body).json()["report_id"]
        self._confirm(client, reviewer_auth_headers, report_id)

        (threat,) = db._memory_store["threats"].values()
        assert threat["hash"] == self._identity_hash(
            body["ecosystem"], body["package_name"]
        )
        (signature,) = db._memory_store["signatures"].values()
        assert signature["id"] == f"sig-community-{threat['id']}"

        verify = self._verify(client, threat["hash"])
        assert verify["verdict"] == "CRITICAL_RISK"
        assert verify["risk_score"] == 50.0
        scan = self._scan(client, auth_headers, {"hashes": [threat["hash"]]})
        assert scan["risk_score"] == 10.0
        assert len(scan["threat_intel_hits"]) == 1

    def test_promoted_threat_id_is_a_guid(
        self, client: TestClient, reviewer_auth_headers: dict[str, str]
    ) -> None:
        # schema.sql declares threats.id UNIQUEIDENTIFIER; the in-memory store
        # accepts any string, so the format is pinned here. The signature id
        # (signatures.id is NVARCHAR) is built from it.
        resp = client.post("/v1/report", json=fixture("dashboard/report.json"))
        self._confirm(client, reviewer_auth_headers, resp.json()["report_id"])
        (threat,) = db._memory_store["threats"].values()
        assert str(uuid.UUID(threat["id"])) == threat["id"]
        (signature,) = db._memory_store["signatures"].values()
        assert signature["id"] == f"sig-community-{threat['id']}"


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
                assert unprintable_chars(value) == [], key
        assert data["description"].startswith("evil ")
        assert data["description"].rstrip().endswith("fake")
        assert data["package_name"] == "pkg [31m"
        assert data["hash"] == digest

    def test_match_text_carries_no_format_characters_or_line_separators(
        self, client: TestClient, pro_auth_headers: dict[str, str]
    ) -> None:
        # Bidirectional overrides and isolates reorder what follows them on a
        # terminal, zero-width characters hide text, and U+2028 starts a new
        # line in some viewers: none is a control character (Cc).
        spoof = (
            "safe \u202e)(txet desrever\u2069 \u200b\u2066 end \u009b31m "
            "CSI-C1 and U+2028:\u2028next-line\u2029\ufeff\U000e0041"
        )
        digest = "d" * 64
        db._memory_store.setdefault("threats", {})["bidi"] = {
            "id": "bidi",
            "hash": digest,
            "package_name": "pkg\u202e",
            "version": "9.9.9\u200d",
            "severity": "HIGH",
            "source": "internal",
            "description": spoof,
        }
        resp = client.get(f"/v1/threat/{digest}", headers=pro_auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        for key, value in data.items():
            if isinstance(value, str):
                assert unprintable_chars(value) == [], (key, value)
        assert "next-line" in data["description"]
        assert data["package_name"] == "pkg "
        assert data["version"] == "9.9.9 "


class TestWithoutControlCharacters:
    @pytest.mark.parametrize(
        "char",
        [
            "\x1b",  # ESC
            "\x07",  # BEL
            "\r",
            "\n",
            "\x85",  # NEL
            "\x9b",  # C1 control sequence introducer
            "\u202a",  # left-to-right embedding
            "\u202e",  # right-to-left override
            "\u2066",  # left-to-right isolate
            "\u2069",  # pop directional isolate
            "\u200b",  # zero-width space
            "\u200c",  # zero-width non-joiner
            "\u200d",  # zero-width joiner
            "\u2060",  # word joiner
            "\ufeff",  # byte order mark
            "\u00ad",  # soft hyphen
            "\u061c",  # arabic letter mark
            "\u2028",  # line separator
            "\u2029",  # paragraph separator
            "\U000e0041",  # tag latin capital letter a
        ],
        ids=lambda c: f"U+{ord(c):04X}",
    )
    def test_is_replaced_by_a_space(self, char: str) -> None:
        assert without_control_characters(f"a{char}b") == "a b"

    def test_text_that_is_only_text_is_unchanged(self) -> None:
        plain = "naïve – 日本語 Привет שלום ✓ 🎉 100% <b>&amp;</b>"
        assert without_control_characters(plain) == plain
        assert without_control_characters("") == ""


class TestThreatTextReachesClientsPrintable:
    """A confirmed report's description is its reporter's text. The readers
    that go through `lookup_threat` (GET /v1/threat/{hash}, POST /v1/verify)
    show it without control characters. The dashboard list (GET /v1/threats)
    does not go through `lookup_threat` and returns entries as stored."""

    HOSTILE = (
        "totally malware\x1b[2J\x1b]0;pwn\x07 trust me\r\nVerdict: CLEAN"
        "\u202e)(txet\u2028end"
    )

    def _confirmed_threat(
        self, client: TestClient, reviewer_headers: dict[str, str]
    ) -> dict[str, Any]:
        body = {**fixture("dashboard/report.json"), "reason": self.HOSTILE}
        resp = client.post("/v1/report", json=body)
        assert resp.status_code == 201, resp.text
        TestReportPromotion._confirm(client, reviewer_headers, resp.json()["report_id"])
        (threat,) = db._memory_store["threats"].values()
        # Stored as the reporter wrote it.
        assert threat["description"] == self.HOSTILE
        return threat

    def test_lookup_text_is_printable(
        self, client: TestClient, reviewer_auth_headers: dict[str, str]
    ) -> None:
        threat = self._confirmed_threat(client, reviewer_auth_headers)
        resp = client.get(f"/v1/threat/{threat['hash']}", headers=reviewer_auth_headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["description"].startswith("totally malware ")
        for key, value in data.items():
            if isinstance(value, str):
                assert unprintable_chars(value) == [], key

    def test_verify_summary_is_printable(
        self, client: TestClient, reviewer_auth_headers: dict[str, str]
    ) -> None:
        threat = self._confirmed_threat(client, reviewer_auth_headers)
        data = TestReportPromotion._verify(client, threat["hash"])
        assert data["verdict"] == "CRITICAL_RISK"
        assert data["findings_summary"].startswith("Known threat: totally malware ")
        assert unprintable_chars(json.dumps(data, ensure_ascii=False)) == []

    def test_internal_entries_keep_their_text_but_lose_control_characters(
        self, client: TestClient
    ) -> None:
        digest = "c" * 64
        db._memory_store.setdefault("threats", {})["internal-1"] = {
            "id": "internal-1",
            "hash": digest,
            "package_name": "pkg",
            "severity": "HIGH",
            "source": "internal",
            "description": "known\x1b[2J backdoor\u202e",
        }
        summary = TestReportPromotion._verify(client, digest)["findings_summary"]
        assert summary == "Known threat: known [2J backdoor  (severity=HIGH)"


# ---------------------------------------------------------------------------
# Scoring of the phase the CLI added (Inference Security)
# ---------------------------------------------------------------------------


class TestInferenceSecurityScoring:
    @pytest.mark.parametrize("phase", CLI_PHASES, ids=lambda p: p["api"])
    def test_every_cli_phase_has_a_score_weight_and_a_threat_category(
        self, phase: dict[str, str]
    ) -> None:
        api_phase = ScanPhase(phase["api"])
        assert api_phase in PHASE_WEIGHTS
        category = ThreatCorrelator()._map_phase_to_threat_category(phase["api"])
        assert category != "unknown_threats"

    def test_inference_security_scores_like_a_code_finding_of_the_same_severity(
        self,
    ) -> None:
        # The CLI weights Phase 10 at 5, like code patterns (cli/src/scanner/
        # mod.rs). The API's default weight of 1.0 scored it five times lower.
        def high(phase: ScanPhase) -> Finding:
            return Finding(
                phase=phase, rule="R", severity=Severity.HIGH, file="src/a.py", weight=5
            )

        inference = score_finding(high(ScanPhase.INFERENCE_SECURITY))
        assert inference == score_finding(high(ScanPhase.CODE_PATTERNS)) == 75.0
        assert PHASE_WEIGHTS[ScanPhase.INFERENCE_SECURITY] == 5.0

    def test_correlator_files_inference_security_with_the_other_ai_threats(
        self,
    ) -> None:
        correlator = ThreatCorrelator()
        assert correlator._map_phase_to_threat_category("inference_security") == (
            correlator._map_phase_to_threat_category("prompt_injection")
        )
