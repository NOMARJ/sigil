"""
Complexity Scorer Utility
Analyzes task complexity to determine optimal model selection
"""

from __future__ import annotations

import re
import logging
from typing import Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class TaskComplexity(Enum):
    """Task complexity levels"""
    SIMPLE = "simple"      # Use Haiku
    MODERATE = "moderate"  # Use Sonnet
    COMPLEX = "complex"    # Use Opus


class ComplexityScorer:
    """Scores task complexity for model routing"""

    # Keywords indicating simple tasks
    SIMPLE_KEYWORDS = [
        "is this safe",
        "what is",
        "explain",
        "describe",
        "list",
        "show",
        "tell me",
        "how many",
        "yes or no",
        "true or false",
        "quick check",
        "brief",
        "summary",
        "basic"
    ]

    # Keywords indicating complex tasks
    COMPLEX_KEYWORDS = [
        "trace",
        "attack chain",
        "deep dive",
        "exhaustive",
        "comprehensive",
        "analyze all",
        "full investigation",
        "root cause",
        "exploit chain",
        "kill chain",
        "advanced",
        "detailed analysis",
        "complete audit"
    ]

    # Patterns requiring deep analysis
    COMPLEX_PATTERNS = [
        r"how.*exploit",
        r"trace.*attack",
        r"analyze.*flow",
        r"investigate.*thoroughly",
        r"deep.*analysis",
        r"comprehensive.*review",
        r"full.*audit"
    ]

    # Task types and their default complexity
    TASK_COMPLEXITY_MAP = {
        "investigate": {
            "quick": TaskComplexity.SIMPLE,
            "thorough": TaskComplexity.MODERATE,
            "exhaustive": TaskComplexity.COMPLEX
        },
        "false_positive": TaskComplexity.SIMPLE,
        "remediation": TaskComplexity.MODERATE,
        "chat": TaskComplexity.SIMPLE,  # Default, will analyze content
        "compliance": TaskComplexity.MODERATE,
        "attack_chain": TaskComplexity.COMPLEX,
        "version_comparison": TaskComplexity.MODERATE,
        "context_expansion": TaskComplexity.MODERATE,
        "bulk_investigation": TaskComplexity.COMPLEX
    }

    def score_task(
        self,
        task_type: str,
        query: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Tuple[TaskComplexity, float, Dict[str, any]]:
        """
        Score task complexity based on type and content.
        
        Args:
            task_type: Type of task (investigate, chat, etc.)
            query: User query or request text
            context: Additional context (findings count, etc.)
            
        Returns:
            Tuple of (complexity level, confidence score 0-1, analysis details)
        """
        score = 0.0
        factors = {
            "task_type": task_type,
            "keywords_found": [],
            "patterns_matched": [],
            "context_factors": []
        }
        
        # Base score from task type
        if task_type in self.TASK_COMPLEXITY_MAP:
            if isinstance(self.TASK_COMPLEXITY_MAP[task_type], dict):
                # Sub-type routing (e.g., investigate depth)
                subtype = context.get("depth") if context else None
                if subtype and subtype in self.TASK_COMPLEXITY_MAP[task_type]:
                    base_complexity = self.TASK_COMPLEXITY_MAP[task_type][subtype]
                else:
                    base_complexity = TaskComplexity.MODERATE
            else:
                base_complexity = self.TASK_COMPLEXITY_MAP[task_type]
                
            # Convert to score
            if base_complexity == TaskComplexity.SIMPLE:
                score = 0.2
            elif base_complexity == TaskComplexity.MODERATE:
                score = 0.5
            else:  # COMPLEX
                score = 0.8
        
        # Analyze query content if provided
        if query:
            query_lower = query.lower()
            
            # Check for simple keywords (reduce score)
            for keyword in self.SIMPLE_KEYWORDS:
                if keyword in query_lower:
                    score -= 0.1
                    factors["keywords_found"].append(f"simple:{keyword}")
            
            # Check for complex keywords (increase score)
            for keyword in self.COMPLEX_KEYWORDS:
                if keyword in query_lower:
                    score += 0.2
                    factors["keywords_found"].append(f"complex:{keyword}")
            
            # Check complex patterns
            for pattern in self.COMPLEX_PATTERNS:
                if re.search(pattern, query_lower):
                    score += 0.15
                    factors["patterns_matched"].append(pattern)
            
            # Length analysis
            word_count = len(query.split())
            if word_count < 10:
                score -= 0.05
                factors["context_factors"].append("short_query")
            elif word_count > 50:
                score += 0.1
                factors["context_factors"].append("long_query")
            
            # Question complexity
            question_words = ["why", "how", "analyze", "investigate", "trace"]
            complex_questions = sum(1 for word in question_words if word in query_lower)
            if complex_questions >= 2:
                score += 0.1
                factors["context_factors"].append("multiple_questions")
        
        # Context-based adjustments
        if context:
            # Many findings to analyze
            findings_count = context.get("findings_count", 0)
            if findings_count > 20:
                score += 0.1
                factors["context_factors"].append(f"many_findings:{findings_count}")
            
            # Multiple files involved
            files_count = context.get("files_count", 0)
            if files_count > 10:
                score += 0.05
                factors["context_factors"].append(f"many_files:{files_count}")
            
            # High severity findings
            critical_count = context.get("critical_findings", 0)
            if critical_count > 0:
                score += 0.1
                factors["context_factors"].append(f"critical_findings:{critical_count}")
            
            # User requested specific model
            if context.get("model_override"):
                factors["context_factors"].append(f"user_override:{context['model_override']}")
        
        # Normalize score to 0-1 range
        score = max(0.0, min(1.0, score))
        
        # Determine complexity level
        if score < 0.33:
            complexity = TaskComplexity.SIMPLE
        elif score < 0.66:
            complexity = TaskComplexity.MODERATE
        else:
            complexity = TaskComplexity.COMPLEX
        
        # Calculate confidence (how certain we are about the scoring)
        confidence = self._calculate_confidence(factors)
        
        logger.info(
            f"Task scored: {task_type} -> {complexity.value} "
            f"(score: {score:.2f}, confidence: {confidence:.2f})"
        )
        
        return complexity, confidence, factors

    def _calculate_confidence(self, factors: Dict) -> float:
        """Calculate confidence in the complexity scoring"""
        confidence = 0.5  # Base confidence
        
        # More signals = higher confidence
        total_signals = (
            len(factors.get("keywords_found", [])) +
            len(factors.get("patterns_matched", [])) +
            len(factors.get("context_factors", []))
        )
        
        if total_signals == 0:
            confidence = 0.3  # Low confidence with no signals
        elif total_signals < 3:
            confidence = 0.5
        elif total_signals < 6:
            confidence = 0.7
        else:
            confidence = 0.9
        
        # User override = maximum confidence
        if any("user_override" in f for f in factors.get("context_factors", [])):
            confidence = 1.0
        
        return confidence

    def recommend_model(
        self,
        complexity: TaskComplexity,
        allow_downgrade: bool = True
    ) -> str:
        """
        Recommend the optimal model based on complexity.
        
        Args:
            complexity: Task complexity level
            allow_downgrade: Whether to allow using cheaper model if available
            
        Returns:
            Model name (claude-3-haiku, claude-3-sonnet, claude-3-opus)
        """
        model_map = {
            TaskComplexity.SIMPLE: "claude-3-haiku",
            TaskComplexity.MODERATE: "claude-3-sonnet", 
            TaskComplexity.COMPLEX: "claude-3-opus"
        }
        
        recommended = model_map[complexity]
        
        # Could add logic here to check model availability
        # and downgrade if necessary
        
        return recommended

    def estimate_credits(
        self,
        complexity: TaskComplexity,
        task_type: str
    ) -> Dict[str, int]:
        """
        Estimate credit costs for different models.
        
        Args:
            complexity: Task complexity level
            task_type: Type of task
            
        Returns:
            Dict of model -> estimated credits
        """
        # Base costs by task type
        base_costs = {
            "investigate": {"haiku": 4, "sonnet": 8, "opus": 24},
            "false_positive": {"haiku": 4, "sonnet": 6, "opus": 12},
            "remediation": {"haiku": 4, "sonnet": 6, "opus": 12},
            "chat": {"haiku": 2, "sonnet": 4, "opus": 10},
            "compliance": {"haiku": 3, "sonnet": 5, "opus": 10},
            "attack_chain": {"haiku": 6, "sonnet": 8, "opus": 16},
            "version_comparison": {"haiku": 4, "sonnet": 6, "opus": 12},
            "context_expansion": {"haiku": 2, "sonnet": 4, "opus": 8}
        }
        
        costs = base_costs.get(task_type, {"haiku": 2, "sonnet": 4, "opus": 10})
        
        return {
            "claude-3-haiku": costs["haiku"],
            "claude-3-sonnet": costs["sonnet"],
            "claude-3-opus": costs["opus"]
        }

    def get_cost_comparison(
        self,
        complexity: TaskComplexity,
        task_type: str,
        recommended_model: str
    ) -> Dict[str, any]:
        """
        Get cost comparison between models.
        
        Args:
            complexity: Task complexity level  
            task_type: Type of task
            recommended_model: The recommended model
            
        Returns:
            Cost comparison with savings information
        """
        credits = self.estimate_credits(complexity, task_type)
        
        recommended_cost = credits[recommended_model]
        
        comparison = {
            "recommended_model": recommended_model,
            "recommended_cost": recommended_cost,
            "alternatives": {},
            "potential_savings": 0
        }
        
        for model, cost in credits.items():
            if model != recommended_model:
                comparison["alternatives"][model] = {
                    "cost": cost,
                    "difference": cost - recommended_cost,
                    "percent_difference": round(
                        ((cost - recommended_cost) / recommended_cost * 100) 
                        if recommended_cost > 0 else 0,
                        1
                    )
                }
        
        # Calculate potential savings vs always using Opus
        opus_cost = credits["claude-3-opus"]
        comparison["potential_savings"] = max(0, opus_cost - recommended_cost)
        comparison["savings_percent"] = round(
            (comparison["potential_savings"] / opus_cost * 100) 
            if opus_cost > 0 else 0,
            1
        )
        
        return comparison


# Global scorer instance
complexity_scorer = ComplexityScorer()