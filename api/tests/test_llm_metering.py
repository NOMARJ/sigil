"""US-104: LLM usage metering — free teaser allowance + Pro fair-use.

DB calls are mocked at the service-method level; no live MSSQL.
"""

from unittest.mock import AsyncMock

import pyodbc
import pytest

from api.models import PlanTier
import os  # noqa: F401  (env override exercised via monkeypatch)
from api.services.credit_service import (
    CREDIT_RATES,
    CreditService,
    InsufficientCreditsError,
    monthly_allowance,
)

CURRENT_IDS = {"claude-haiku-4-5", "claude-opus-4-8", "claude-fable-5"}


class TestCreditRates:
    def test_rates_cover_exactly_current_models(self):
        assert set(CREDIT_RATES.keys()) == CURRENT_IDS

    def test_no_retired_or_foreign_models(self):
        for model in CREDIT_RATES:
            assert "claude-3-" not in model
            assert "gpt" not in model

    def test_rates_follow_pricing_order(self):
        assert (
            CREDIT_RATES["claude-haiku-4-5"]
            < CREDIT_RATES["claude-opus-4-8"]
            < CREDIT_RATES["claude-fable-5"]
        )

    @pytest.mark.asyncio
    async def test_calculate_token_cost_fable(self):
        service = CreditService()
        cost = await service.calculate_token_cost("claude-fable-5", 1000)
        assert cost == CREDIT_RATES["claude-fable-5"]


class TestMonthlyAllowance:
    def test_free_default(self, monkeypatch):
        monkeypatch.delenv("LLM_FREE_MONTHLY_CREDITS", raising=False)
        assert monthly_allowance(PlanTier.FREE) == 50

    def test_free_env_override(self, monkeypatch):
        monkeypatch.setenv("LLM_FREE_MONTHLY_CREDITS", "120")
        assert monthly_allowance(PlanTier.FREE) == 120

    def test_pro_unaffected_by_free_override(self, monkeypatch):
        monkeypatch.setenv("LLM_FREE_MONTHLY_CREDITS", "120")
        assert monthly_allowance(PlanTier.PRO) == 5000


class TestCheckLlmAllowance:
    @pytest.mark.asyncio
    async def test_allowed_with_balance(self, monkeypatch):
        service = CreditService()

        async def fake_balance(user_id):
            return 42

        monkeypatch.setattr(service, "get_balance", fake_balance)
        result = await service.check_llm_allowance("u1", credits_required=4)

        assert result["allowed"] is True
        assert result["balance"] == 42

    @pytest.mark.asyncio
    async def test_denial_is_structured(self, monkeypatch):
        service = CreditService()

        async def fake_balance(user_id):
            return 2

        async def fake_analytics(user_id):
            return {"reset_date": "2026-07-01T00:00:00", "balance": 2}

        monkeypatch.setattr(service, "get_balance", fake_balance)
        monkeypatch.setattr(service, "get_usage_analytics", fake_analytics)
        result = await service.check_llm_allowance("u1", credits_required=4)

        assert result["allowed"] is False
        assert result["reason"] == "allowance_exhausted"
        assert result["balance"] == 2
        assert result["credits_required"] == 4
        assert result["reset_date"] == "2026-07-01T00:00:00"
        assert result["upgrade_url"].startswith("https://")


class TestRecordLlmUsage:
    @pytest.mark.asyncio
    async def test_records_via_deduct_credits(self, monkeypatch):
        service = CreditService()
        captured = {}

        async def fake_deduct(user_id, amount, transaction_type, **kwargs):
            captured.update(
                user_id=user_id,
                amount=amount,
                transaction_type=transaction_type,
                **kwargs,
            )
            return 96

        monkeypatch.setattr(service, "deduct_credits", fake_deduct)
        new_balance = await service.record_llm_usage(
            user_id="u1",
            model="claude-fable-5",
            input_tokens=600,
            output_tokens=400,
            feature="investigate",
        )

        assert new_balance == 96
        assert captured["user_id"] == "u1"
        assert captured["model_used"] == "claude-fable-5"
        assert captured["tokens_used"] == 1000
        assert captured["transaction_type"] == "investigate"
        assert captured["amount"] == CREDIT_RATES["claude-fable-5"]
        assert captured["metadata"]["feature"] == "investigate"
        assert captured["metadata"]["input_tokens"] == 600
        assert captured["metadata"]["output_tokens"] == 400

    @pytest.mark.asyncio
    async def test_unknown_feature_maps_to_scan(self, monkeypatch):
        service = CreditService()
        captured = {}

        async def fake_deduct(user_id, amount, transaction_type, **kwargs):
            captured["transaction_type"] = transaction_type
            return 1

        monkeypatch.setattr(service, "deduct_credits", fake_deduct)
        await service.record_llm_usage(
            user_id="u1",
            model="claude-haiku-4-5",
            input_tokens=100,
            output_tokens=100,
            feature="fp_adjudication",
        )
        assert captured["transaction_type"] == "scan"


class TestDeductCreditsErrorHandling:
    """Regression for the prod metering crash: the deduct except clause caught
    `db.DatabaseError`, but `db` is an MssqlClient instance with no such
    attribute — so any DB error from sp_DeductCredits raised AttributeError
    ('MssqlClient' object has no attribute 'DatabaseError') and masked the
    real failure. The clause must catch the driver error (pyodbc.Error).
    """

    @pytest.mark.asyncio
    async def test_insufficient_credits_maps_cleanly(self, monkeypatch):
        service = CreditService()
        err = pyodbc.Error("42000", "[SQL Server]Insufficient credits")
        monkeypatch.setattr(
            "api.services.credit_service.db.execute_procedure",
            AsyncMock(side_effect=err),
        )
        with pytest.raises(InsufficientCreditsError):
            await service.deduct_credits("u1", 5, "scan")

    @pytest.mark.asyncio
    async def test_driver_error_is_not_masked_by_attributeerror(self, monkeypatch):
        service = CreditService()
        err = pyodbc.ProgrammingError(
            "42000", "Could not find stored procedure 'sp_DeductCredits'."
        )
        monkeypatch.setattr(
            "api.services.credit_service.db.execute_procedure",
            AsyncMock(side_effect=err),
        )
        # Must surface as a credit error, never AttributeError.
        with pytest.raises(Exception) as exc:
            await service.deduct_credits("u1", 5, "scan")
        assert not isinstance(exc.value, AttributeError)
