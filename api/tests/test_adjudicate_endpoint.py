"""US-107: POST /v1/scans/{scan_id}/findings/{finding_index}/adjudicate."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from api import gates
from api.models import PlanTier
from api.services.credit_service import credit_service
from api.services.fp_adjudicator import fp_adjudicator

VERDICT_A = {
    "classification": "benign_dual_use",
    "confidence": 0.9,
    "rationale": "Config-literal eval, no taint path.",
    "_usage": {"input_tokens_est": 500, "output_tokens_est": 60},
}

VERDICT_B = {
    "classification": "suspicious",
    "confidence": 0.6,
    "rationale": "Second look: dynamic source.",
    "_usage": {"input_tokens_est": 500, "output_tokens_est": 70},
}


def _submit_scan_with_findings(client, auth_headers, sample_scan_request) -> str:
    resp = client.post("/v1/scan", json=sample_scan_request, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["scan_id"]


def _adjudicate(client, auth_headers, scan_id, index=0):
    return client.post(
        f"/v1/scans/{scan_id}/findings/{index}/adjudicate", headers=auth_headers
    )


@pytest.fixture
def pro_context():
    """User passes the LLM gate as PRO; adjudicator + metering mocked."""

    async def fake_plan(user_id):
        return PlanTier.PRO

    recorded = []

    async def fake_record(**kwargs):
        recorded.append(kwargs)
        return 100

    with patch.object(gates, "get_user_plan", fake_plan), patch.object(
        credit_service, "record_llm_usage", side_effect=None
    ) as mock_record:
        mock_record.side_effect = fake_record
        yield recorded


class TestAdjudicateEndpoint:
    def test_unauthenticated_401(self, client, sample_scan_request, auth_headers):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)
        resp = client.post(f"/v1/scans/{scan_id}/findings/0/adjudicate")
        assert resp.status_code in (401, 403)

    def test_free_exhausted_402(self, client, auth_headers, sample_scan_request):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def fake_plan(user_id):
            return PlanTier.FREE

        async def fake_allowance(user_id, credits_required=1):
            return {
                "allowed": False,
                "reason": "allowance_exhausted",
                "balance": 0,
                "credits_required": credits_required,
                "reset_date": "2026-07-01T00:00:00",
                "upgrade_url": "https://www.sigilsec.ai/pricing",
            }

        with patch.object(gates, "get_user_plan", fake_plan), patch.object(
            credit_service, "check_llm_allowance", fake_allowance
        ):
            resp = _adjudicate(client, auth_headers, scan_id)

        assert resp.status_code == 402
        assert resp.json()["detail"]["reason"] == "allowance_exhausted"

    def test_happy_path_persists_verdict(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def fake_adjudicate(finding, code_context):
            return dict(VERDICT_A)

        with patch.object(fp_adjudicator, "adjudicate", fake_adjudicate):
            resp = _adjudicate(client, auth_headers, scan_id)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["adjudication"]["classification"] == "benign_dual_use"
        assert "_usage" not in body["adjudication"]

        # persisted on the finding
        detail = client.get(f"/v1/scans/{scan_id}", headers=auth_headers)
        assert detail.status_code == 200, detail.text
        target = detail.json()["findings_json"][0]
        assert target["adjudication"]["classification"] == "benign_dual_use"
        assert target["adjudication"]["model"]

        # metered
        assert len(pro_context) == 1
        assert pro_context[0]["feature"] == "fp_adjudication"

    def test_idempotent_overwrite(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def first(finding, code_context):
            return dict(VERDICT_A)

        async def second(finding, code_context):
            return dict(VERDICT_B)

        with patch.object(fp_adjudicator, "adjudicate", first):
            r1 = _adjudicate(client, auth_headers, scan_id)
        with patch.object(fp_adjudicator, "adjudicate", second):
            r2 = _adjudicate(client, auth_headers, scan_id)

        assert r1.status_code == r2.status_code == 200
        assert r2.json()["adjudication"]["classification"] == "suspicious"

        detail = client.get(f"/v1/scans/{scan_id}", headers=auth_headers)
        assert detail.status_code == 200, detail.text
        target = detail.json()["findings_json"][0]
        assert target["adjudication"]["classification"] == "suspicious"

    def test_refusal_maps_to_422(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        from api.services.llm_service import LLMRefusalError

        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def refuse(finding, code_context):
            raise LLMRefusalError("claude-opus-4-8", "cyber")

        with patch.object(fp_adjudicator, "adjudicate", refuse):
            resp = _adjudicate(client, auth_headers, scan_id)

        assert resp.status_code == 422
        assert resp.json()["detail"]["reason"] == "llm_refusal"
        assert resp.json()["detail"]["category"] == "cyber"
        assert len(pro_context) == 0  # refusals are not metered

    def test_unknown_scan_404(self, client, auth_headers, pro_context):
        resp = _adjudicate(client, auth_headers, "nonexistent-scan-id")
        assert resp.status_code == 404

    def test_finding_index_out_of_range_404(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)
        resp = _adjudicate(client, auth_headers, scan_id, index=9999)
        assert resp.status_code == 404
