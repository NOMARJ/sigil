"""US-102: Model router registry refresh — retire claude-3 tiers."""

import pytest

from api.llm_config import llm_config
from api.services.model_router import ModelRouter, model_router
from api.utils.complexity_scorer import TaskComplexity, complexity_scorer

CURRENT_IDS = {"claude-haiku-4-5", "claude-opus-4-8", "claude-fable-5"}


class TestRegistry:
    def test_registry_contains_exactly_current_ids(self):
        assert set(ModelRouter.MODELS.keys()) == CURRENT_IDS

    def test_no_retired_claude_3_entries(self):
        for key, info in ModelRouter.MODELS.items():
            assert "claude-3" not in key
            assert "claude-3" not in info["api_name"]

    def test_api_names_are_exact_aliases_no_date_suffix(self):
        for key, info in ModelRouter.MODELS.items():
            assert info["api_name"] == key

    def test_credit_multipliers_follow_pricing_order(self):
        # $1/$5 haiku < $5/$25 opus < $10/$50 fable per MTok
        m = ModelRouter.MODELS
        assert (
            m["claude-haiku-4-5"]["credit_multiplier"]
            < m["claude-opus-4-8"]["credit_multiplier"]
            < m["claude-fable-5"]["credit_multiplier"]
        )


class TestScorerAlignment:
    def test_recommend_model_simple_routes_to_fast(self):
        assert complexity_scorer.recommend_model(TaskComplexity.SIMPLE) == llm_config.fast_model

    def test_recommend_model_moderate_routes_to_default(self):
        assert complexity_scorer.recommend_model(TaskComplexity.MODERATE) == llm_config.model

    def test_recommend_model_complex_routes_to_deep(self):
        assert complexity_scorer.recommend_model(TaskComplexity.COMPLEX) == llm_config.deep_model

    def test_estimate_credits_keys_match_registry(self):
        credits = complexity_scorer.estimate_credits(TaskComplexity.MODERATE, "investigate")
        assert set(credits.keys()) == CURRENT_IDS

    def test_cost_comparison_savings_vs_deep_model(self):
        comparison = complexity_scorer.get_cost_comparison(
            TaskComplexity.SIMPLE, "investigate", llm_config.fast_model
        )
        assert comparison["recommended_model"] == llm_config.fast_model
        assert comparison["potential_savings"] > 0


class TestDowngrade:
    @pytest.mark.asyncio
    async def test_downgrade_prefers_default_then_fast(self):
        cost_comparison = {
            "alternatives": {
                "claude-opus-4-8": {"cost": 8},
                "claude-haiku-4-5": {"cost": 4},
            }
        }
        result = await model_router._attempt_downgrade(
            user_balance=8, cost_comparison=cost_comparison
        )
        assert result == {"model": "claude-opus-4-8", "cost": 8}

    @pytest.mark.asyncio
    async def test_downgrade_lands_on_fast_model_when_broke(self):
        cost_comparison = {
            "alternatives": {
                "claude-opus-4-8": {"cost": 8},
                "claude-haiku-4-5": {"cost": 4},
            }
        }
        result = await model_router._attempt_downgrade(
            user_balance=4, cost_comparison=cost_comparison
        )
        assert result == {"model": "claude-haiku-4-5", "cost": 4}


class TestErrorFallback:
    @pytest.mark.asyncio
    async def test_error_fallback_selects_fast_model(self, monkeypatch):
        def boom(**kwargs):
            raise RuntimeError("scorer down")

        monkeypatch.setattr(
            "api.services.model_router.complexity_scorer.score_task", boom
        )
        routing = await model_router.route_request(user_id="u1", task_type="chat")
        assert routing["reason"] == "error_fallback"
        assert routing["selected_model"] == llm_config.fast_model
        assert "claude-3" not in routing["selected_model"]
