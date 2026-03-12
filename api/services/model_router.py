"""
Model Router Service
Intelligently routes requests to the optimal LLM model based on complexity
"""

from __future__ import annotations

import logging
from typing import Dict, Optional, Any, Tuple
from datetime import datetime

from ..utils.complexity_scorer import complexity_scorer
from ..services.credit_service import credit_service
from ..database import db
from ..exceptions import InsufficientCreditsError

logger = logging.getLogger(__name__)


class ModelRouter:
    """Routes LLM requests to optimal models based on complexity and cost"""

    # Model configurations
    MODELS = {
        "claude-3-haiku": {
            "name": "Claude 3 Haiku",
            "description": "Fast and efficient for simple tasks",
            "max_tokens": 4096,
            "credit_multiplier": 1,
            "strengths": ["speed", "cost", "simple_analysis"],
            "api_name": "claude-3-haiku-20240307"
        },
        "claude-3-sonnet": {
            "name": "Claude 3 Sonnet", 
            "description": "Balanced performance for most tasks",
            "max_tokens": 4096,
            "credit_multiplier": 2,
            "strengths": ["balance", "accuracy", "complex_reasoning"],
            "api_name": "claude-3-sonnet-20240229"
        },
        "claude-3-opus": {
            "name": "Claude 3 Opus",
            "description": "Maximum capability for critical analysis",
            "max_tokens": 4096,
            "credit_multiplier": 5,
            "strengths": ["deep_analysis", "nuance", "critical_thinking"],
            "api_name": "claude-3-opus-20240229"
        }
    }

    async def route_request(
        self,
        user_id: str,
        task_type: str,
        query: Optional[str] = None,
        context: Optional[Dict] = None,
        model_override: Optional[str] = None,
        preview_only: bool = False
    ) -> Dict[str, Any]:
        """
        Route a request to the optimal model.
        
        Args:
            user_id: User ID for credit tracking
            task_type: Type of task (investigate, chat, etc.)
            query: User query or request
            context: Additional context for scoring
            model_override: User-specified model override
            preview_only: Only return routing info without executing
            
        Returns:
            Routing decision with model selection and cost info
        """
        try:
            # Add override to context if specified
            if model_override:
                if context is None:
                    context = {}
                context["model_override"] = model_override
            
            # Score task complexity
            complexity, confidence, factors = complexity_scorer.score_task(
                task_type=task_type,
                query=query,
                context=context
            )
            
            # Get recommended model
            if model_override and model_override in self.MODELS:
                selected_model = model_override
                reason = "user_override"
            else:
                selected_model = complexity_scorer.recommend_model(complexity)
                reason = "complexity_analysis"
            
            # Get cost information
            cost_comparison = complexity_scorer.get_cost_comparison(
                complexity=complexity,
                task_type=task_type,
                recommended_model=selected_model
            )
            
            # Check user credits
            required_credits = cost_comparison["recommended_cost"]
            user_balance = await credit_service.get_balance(user_id)
            
            # Build routing decision
            routing = {
                "selected_model": selected_model,
                "model_info": self.MODELS[selected_model],
                "complexity": complexity.value,
                "confidence": confidence,
                "reason": reason,
                "credits_required": required_credits,
                "user_balance": user_balance,
                "has_sufficient_credits": user_balance >= required_credits,
                "cost_comparison": cost_comparison,
                "analysis_factors": factors,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Log routing decision
            if not preview_only:
                await self._log_routing_decision(
                    user_id=user_id,
                    task_type=task_type,
                    routing=routing
                )
            
            # If insufficient credits, try to downgrade
            if not routing["has_sufficient_credits"] and not model_override:
                downgrade = await self._attempt_downgrade(
                    user_balance=user_balance,
                    cost_comparison=cost_comparison
                )
                
                if downgrade:
                    routing["downgraded"] = True
                    routing["original_model"] = selected_model
                    routing["selected_model"] = downgrade["model"]
                    routing["credits_required"] = downgrade["cost"]
                    routing["has_sufficient_credits"] = True
                    routing["downgrade_reason"] = "insufficient_credits"
            
            logger.info(
                f"Routed {task_type} to {routing['selected_model']} "
                f"(complexity: {complexity.value}, credits: {required_credits})"
            )
            
            return routing
            
        except Exception as e:
            logger.error(f"Model routing failed: {e}")
            # Fallback to Haiku on error
            return {
                "selected_model": "claude-3-haiku",
                "model_info": self.MODELS["claude-3-haiku"],
                "complexity": "unknown",
                "confidence": 0.0,
                "reason": "error_fallback",
                "credits_required": 2,
                "error": str(e)
            }

    async def get_model_for_request(
        self,
        user_id: str,
        task_type: str,
        query: Optional[str] = None,
        context: Optional[Dict] = None,
        model_override: Optional[str] = None
    ) -> Tuple[str, int]:
        """
        Get the model and credit cost for a request.
        
        Args:
            user_id: User ID
            task_type: Task type
            query: User query
            context: Additional context
            model_override: Model override
            
        Returns:
            Tuple of (model_name, credit_cost)
            
        Raises:
            InsufficientCreditsError: If user lacks credits
        """
        routing = await self.route_request(
            user_id=user_id,
            task_type=task_type,
            query=query,
            context=context,
            model_override=model_override,
            preview_only=False
        )
        
        if not routing.get("has_sufficient_credits"):
            raise InsufficientCreditsError(
                f"Need {routing['credits_required']} credits, "
                f"have {routing['user_balance']}"
            )
        
        return routing["selected_model"], routing["credits_required"]

    async def preview_routing(
        self,
        task_type: str,
        query: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Preview routing without user context or credit checks.
        
        Args:
            task_type: Task type
            query: User query
            context: Additional context
            
        Returns:
            Routing preview with all model options
        """
        # Score complexity
        complexity, confidence, factors = complexity_scorer.score_task(
            task_type=task_type,
            query=query,
            context=context
        )
        
        # Get recommended model
        recommended = complexity_scorer.recommend_model(complexity)
        
        # Get costs for all models
        all_costs = complexity_scorer.estimate_credits(complexity, task_type)
        
        # Build preview
        preview = {
            "complexity": complexity.value,
            "confidence": confidence,
            "recommended_model": recommended,
            "model_options": []
        }
        
        for model_key, model_info in self.MODELS.items():
            option = {
                "model": model_key,
                "name": model_info["name"],
                "description": model_info["description"],
                "credits": all_costs.get(model_key, 2),
                "is_recommended": model_key == recommended,
                "strengths": model_info["strengths"]
            }
            
            # Add relative cost
            if model_key == recommended:
                option["cost_label"] = "Recommended"
            elif all_costs[model_key] < all_costs[recommended]:
                savings = all_costs[recommended] - all_costs[model_key]
                option["cost_label"] = f"Save {savings} credits"
            else:
                extra = all_costs[model_key] - all_costs[recommended]
                option["cost_label"] = f"+{extra} credits"
            
            preview["model_options"].append(option)
        
        # Sort by credits (cheapest first)
        preview["model_options"].sort(key=lambda x: x["credits"])
        
        # Add analysis factors
        preview["analysis_factors"] = factors
        
        return preview

    async def get_usage_statistics(
        self,
        user_id: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get model routing statistics.
        
        Args:
            user_id: Optional user ID for user-specific stats
            days: Number of days to look back
            
        Returns:
            Usage statistics and savings
        """
        try:
            # Build query
            query = """
                SELECT 
                    model_selected,
                    COUNT(*) as count,
                    AVG(credits_used) as avg_credits,
                    SUM(credits_used) as total_credits,
                    AVG(confidence) as avg_confidence
                FROM model_routing_log
                WHERE timestamp > DATEADD(day, -:days, GETDATE())
            """
            params = {"days": days}
            
            if user_id:
                query += " AND user_id = :user_id"
                params["user_id"] = user_id
            
            query += " GROUP BY model_selected"
            
            results = await db.fetch_all(query, params)
            
            # Calculate statistics
            stats = {
                "period_days": days,
                "model_usage": {},
                "total_requests": 0,
                "total_credits": 0,
                "average_confidence": 0.0,
                "estimated_savings": 0
            }
            
            total_confidence = 0.0
            
            for row in results:
                model = row["model_selected"]
                stats["model_usage"][model] = {
                    "requests": row["count"],
                    "average_credits": round(row["avg_credits"], 1),
                    "total_credits": row["total_credits"],
                    "percentage": 0  # Will calculate after
                }
                
                stats["total_requests"] += row["count"]
                stats["total_credits"] += row["total_credits"]
                total_confidence += row["avg_confidence"] * row["count"]
                
                # Estimate savings vs always using Opus
                opus_cost = row["count"] * 10  # Assume 10 credits average for Opus
                actual_cost = row["total_credits"]
                stats["estimated_savings"] += max(0, opus_cost - actual_cost)
            
            # Calculate percentages and average confidence
            if stats["total_requests"] > 0:
                for model in stats["model_usage"]:
                    stats["model_usage"][model]["percentage"] = round(
                        stats["model_usage"][model]["requests"] / 
                        stats["total_requests"] * 100,
                        1
                    )
                
                stats["average_confidence"] = round(
                    total_confidence / stats["total_requests"], 2
                )
            
            # Calculate savings percentage
            potential_opus_cost = stats["total_requests"] * 10
            if potential_opus_cost > 0:
                stats["savings_percentage"] = round(
                    stats["estimated_savings"] / potential_opus_cost * 100,
                    1
                )
            else:
                stats["savings_percentage"] = 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get usage statistics: {e}")
            return {
                "error": str(e),
                "period_days": days,
                "model_usage": {},
                "total_requests": 0,
                "total_credits": 0
            }

    async def _attempt_downgrade(
        self,
        user_balance: int,
        cost_comparison: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to downgrade to a cheaper model if possible.
        
        Args:
            user_balance: User's credit balance
            cost_comparison: Cost comparison data
            
        Returns:
            Downgrade option if available, None otherwise
        """
        # Check alternatives in order of preference
        model_preference = ["claude-3-sonnet", "claude-3-haiku"]
        
        for model in model_preference:
            if model in cost_comparison["alternatives"]:
                alt = cost_comparison["alternatives"][model]
                if alt["cost"] <= user_balance:
                    return {
                        "model": model,
                        "cost": alt["cost"]
                    }
        
        return None

    async def _log_routing_decision(
        self,
        user_id: str,
        task_type: str,
        routing: Dict[str, Any]
    ) -> None:
        """Log routing decision for analytics"""
        try:
            await db.execute(
                """
                INSERT INTO model_routing_log (
                    user_id, task_type, model_selected,
                    complexity, confidence, credits_required,
                    reason, timestamp
                ) VALUES (
                    :user_id, :task_type, :model_selected,
                    :complexity, :confidence, :credits_required,
                    :reason, :timestamp
                )
                """,
                {
                    "user_id": user_id,
                    "task_type": task_type,
                    "model_selected": routing["selected_model"],
                    "complexity": routing["complexity"],
                    "confidence": routing["confidence"],
                    "credits_required": routing["credits_required"],
                    "reason": routing["reason"],
                    "timestamp": datetime.utcnow()
                }
            )
        except Exception as e:
            # Don't fail the request if logging fails
            logger.warning(f"Failed to log routing decision: {e}")


# Global router instance
model_router = ModelRouter()