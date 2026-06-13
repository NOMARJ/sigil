"""US-107 + async adjudication: POST/GET
/v1/scans/{scan_id}/findings/{finding_index}/adjudicate.

Adjudication is async: POST schedules a background Fable-5 job and returns 202
with a `pending` marker; the verdict/error is persisted on the finding and read
back via GET. Starlette's TestClient runs background tasks synchronously before
the POST returns, so by the time `client.post(...)` returns the job has already
run and a GET poll returns the terminal state.
"""

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


def _adjudicate(client, auth_headers, scan_id, index=0, force=False):
    url = f"/v1/scans/{scan_id}/findings/{index}/adjudicate"
    if force:
        url += "?force=true"
    return client.post(url, headers=auth_headers)


def _poll(client, auth_headers, scan_id, index=0):
    return client.get(
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

    with (
        patch.object(gates, "get_user_plan", fake_plan),
        patch.object(
            credit_service, "record_llm_usage", side_effect=None
        ) as mock_record,
    ):
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

        with (
            patch.object(gates, "get_user_plan", fake_plan),
            patch.object(credit_service, "check_llm_allowance", fake_allowance),
        ):
            resp = _adjudicate(client, auth_headers, scan_id)

        assert resp.status_code == 402
        assert resp.json()["detail"]["reason"] == "allowance_exhausted"

    def test_schedules_then_completes(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def fake_adjudicate(finding, code_context):
            return dict(VERDICT_A)

        with patch.object(fp_adjudicator, "adjudicate", fake_adjudicate):
            resp = _adjudicate(client, auth_headers, scan_id)
            # 202 + pending marker is returned to the caller immediately...
            assert resp.status_code == 202, resp.text
            assert resp.json()["status"] == "pending"
            assert resp.json()["adjudication"]["status"] == "pending"
            # ...and the background job has already run by now (TestClient).
            poll = _poll(client, auth_headers, scan_id)

        assert poll.status_code == 200, poll.text
        body = poll.json()
        assert body["status"] == "complete"
        assert body["adjudication"]["classification"] == "benign_dual_use"
        assert "_usage" not in body["adjudication"]

        # persisted on the finding
        detail = client.get(f"/v1/scans/{scan_id}", headers=auth_headers)
        target = detail.json()["findings_json"][0]
        assert target["adjudication"]["classification"] == "benign_dual_use"
        assert target["adjudication"]["model"]

        # metered exactly once
        assert len(pro_context) == 1
        assert pro_context[0]["feature"] == "fp_adjudication"

    def test_completed_not_rerun_without_force(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)
        calls = []

        async def first(finding, code_context):
            calls.append("A")
            return dict(VERDICT_A)

        with patch.object(fp_adjudicator, "adjudicate", first):
            _adjudicate(client, auth_headers, scan_id)  # completes -> A

        async def second(finding, code_context):
            calls.append("B")
            return dict(VERDICT_B)

        # Re-POST without force: already complete -> 200 with existing verdict,
        # adjudicator NOT invoked again.
        with patch.object(fp_adjudicator, "adjudicate", second):
            r2 = _adjudicate(client, auth_headers, scan_id)

        assert r2.status_code == 200
        assert r2.json()["adjudication"]["classification"] == "benign_dual_use"
        assert calls == ["A"]  # second never ran

    def test_force_reruns(self, client, auth_headers, sample_scan_request, pro_context):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def first(finding, code_context):
            return dict(VERDICT_A)

        async def second(finding, code_context):
            return dict(VERDICT_B)

        with patch.object(fp_adjudicator, "adjudicate", first):
            _adjudicate(client, auth_headers, scan_id)
        with patch.object(fp_adjudicator, "adjudicate", second):
            r = _adjudicate(client, auth_headers, scan_id, force=True)
            assert r.status_code == 202
            poll = _poll(client, auth_headers, scan_id)

        assert poll.json()["adjudication"]["classification"] == "suspicious"

    def test_refusal_persists_error_state(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        from api.services.llm_service import LLMRefusalError

        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def refuse(finding, code_context):
            raise LLMRefusalError("claude-opus-4-8", "cyber")

        with patch.object(fp_adjudicator, "adjudicate", refuse):
            resp = _adjudicate(client, auth_headers, scan_id)
            assert resp.status_code == 202
            poll = _poll(client, auth_headers, scan_id)

        assert poll.status_code == 200
        body = poll.json()
        assert body["status"] == "error"
        assert body["adjudication"]["reason"] == "llm_refusal"
        assert body["adjudication"]["category"] == "cyber"
        assert len(pro_context) == 0  # refusals are not metered

    def test_llm_error_persists_error_state(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)

        async def boom(finding, code_context):
            raise RuntimeError("upstream exploded")

        with patch.object(fp_adjudicator, "adjudicate", boom):
            _adjudicate(client, auth_headers, scan_id)
            poll = _poll(client, auth_headers, scan_id)

        assert poll.status_code == 200
        assert poll.json()["status"] == "error"
        assert poll.json()["adjudication"]["reason"] == "llm_error"
        assert len(pro_context) == 0  # failed verdicts are not metered

    def test_poll_before_request_404(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)
        resp = _poll(client, auth_headers, scan_id)
        assert resp.status_code == 404

    def test_unknown_scan_404(self, client, auth_headers, pro_context):
        resp = _adjudicate(client, auth_headers, "nonexistent-scan-id")
        assert resp.status_code == 404

    def test_finding_index_out_of_range_404(
        self, client, auth_headers, sample_scan_request, pro_context
    ):
        scan_id = _submit_scan_with_findings(client, auth_headers, sample_scan_request)
        resp = _adjudicate(client, auth_headers, scan_id, index=9999)
        assert resp.status_code == 404
