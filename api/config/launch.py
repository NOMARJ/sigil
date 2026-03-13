"""
Sigil Pro Launch Configuration

Controls feature rollout for constrained launch approach.
Only core features are enabled initially, advanced features held for v2.
"""

from __future__ import annotations

import os
from typing import Dict, Set
from enum import Enum
from dataclasses import dataclass


class LaunchPhase(Enum):
    """Launch phases for feature rollout."""

    CONSTRAINED = "constrained"  # 4 core features only
    BETA_EXPANSION = "beta"  # Add 2-3 more features
    FULL_ROLLOUT = "full"  # All features enabled


class ProFeature(Enum):
    """All Pro features in the system."""

    # CORE FEATURES (Constrained Launch)
    FINDING_INVESTIGATION = "finding_investigation"  # US-001
    FALSE_POSITIVE_VERIFICATION = "false_positive_verification"  # US-002
    INTERACTIVE_CHAT = "interactive_chat"  # US-004
    CREDIT_SYSTEM = "credit_system"  # Core monetization

    # BETA FEATURES (Post-Launch)
    SESSION_MANAGEMENT = "session_management"  # US-009
    SMART_MODEL_ROUTING = "smart_model_routing"  # US-010

    # ADVANCED FEATURES (v2)
    REMEDIATION_GENERATION = "remediation_generation"  # US-003 - Liability risk
    ATTACK_CHAIN_ANALYSIS = "attack_chain_analysis"  # US-005 - Trust risk
    VERSION_COMPARISON = "version_comparison"  # US-006 - Operational complexity
    DYNAMIC_CONTEXT = "dynamic_context"  # US-007 - Not implemented
    COMPLIANCE_MAPPING = "compliance_mapping"  # US-008 - Enterprise complexity
    BULK_INVESTIGATION = "bulk_investigation"  # US-011 - Operational complexity
    FEEDBACK_LEARNING = "feedback_learning"  # US-012 - Accuracy not proven


@dataclass
class FeatureConfig:
    """Configuration for a specific feature."""

    enabled: bool
    description: str
    credit_cost: int
    user_visible: bool = True  # Show in UI
    requires_beta_access: bool = False


class LaunchConfig:
    """Manages feature availability based on launch phase."""

    def __init__(self):
        self._current_phase = self._get_launch_phase()
        self._feature_configs = self._initialize_features()

    def _get_launch_phase(self) -> LaunchPhase:
        """Get current launch phase from environment."""
        phase_str = os.getenv("SIGIL_LAUNCH_PHASE", "constrained").lower()
        try:
            return LaunchPhase(phase_str)
        except ValueError:
            return LaunchPhase.CONSTRAINED

    def _initialize_features(self) -> Dict[ProFeature, FeatureConfig]:
        """Initialize feature configurations based on launch phase."""

        # Core features always enabled
        core_features = {
            ProFeature.FINDING_INVESTIGATION: FeatureConfig(
                enabled=True,
                description="Deep-dive analysis of specific security findings",
                credit_cost=4,  # Quick analysis default
            ),
            ProFeature.FALSE_POSITIVE_VERIFICATION: FeatureConfig(
                enabled=True,
                description="AI-powered verification of false positives",
                credit_cost=4,
            ),
            ProFeature.INTERACTIVE_CHAT: FeatureConfig(
                enabled=True,
                description="Ask questions about your scan results",
                credit_cost=2,  # Per message
            ),
            ProFeature.CREDIT_SYSTEM: FeatureConfig(
                enabled=True,
                description="Transparent usage tracking and cost control",
                credit_cost=0,
            ),
        }

        # Beta features (phase 2)
        beta_features = {
            ProFeature.SESSION_MANAGEMENT: FeatureConfig(
                enabled=self._current_phase
                in [LaunchPhase.BETA_EXPANSION, LaunchPhase.FULL_ROLLOUT],
                description="Save and resume investigation sessions",
                credit_cost=0,
                requires_beta_access=True,
            ),
            ProFeature.SMART_MODEL_ROUTING: FeatureConfig(
                enabled=self._current_phase
                in [LaunchPhase.BETA_EXPANSION, LaunchPhase.FULL_ROLLOUT],
                description="Automatic model selection for cost optimization",
                credit_cost=0,
                user_visible=False,  # Background feature
            ),
        }

        # Advanced features (v2)
        advanced_features = {
            ProFeature.REMEDIATION_GENERATION: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="AI-generated secure code fixes",
                credit_cost=6,
                user_visible=False,  # Hidden until v2
            ),
            ProFeature.ATTACK_CHAIN_ANALYSIS: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="Trace attack chains through code",
                credit_cost=12,
                user_visible=False,
            ),
            ProFeature.VERSION_COMPARISON: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="Compare security between versions",
                credit_cost=8,
                user_visible=False,
            ),
            ProFeature.DYNAMIC_CONTEXT: FeatureConfig(
                enabled=False,  # Not implemented
                description="Expand analysis context dynamically",
                credit_cost=4,
                user_visible=False,
            ),
            ProFeature.COMPLIANCE_MAPPING: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="Map findings to compliance frameworks",
                credit_cost=3,
                user_visible=False,
            ),
            ProFeature.BULK_INVESTIGATION: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="Investigate similar findings in bulk",
                credit_cost=10,
                user_visible=False,
            ),
            ProFeature.FEEDBACK_LEARNING: FeatureConfig(
                enabled=self._current_phase == LaunchPhase.FULL_ROLLOUT,
                description="Learn from user feedback to improve accuracy",
                credit_cost=0,
                user_visible=False,
            ),
        }

        return {**core_features, **beta_features, **advanced_features}

    def is_feature_enabled(self, feature: ProFeature) -> bool:
        """Check if a feature is enabled."""
        return self._feature_configs.get(feature, FeatureConfig(False, "", 0)).enabled

    def is_feature_visible(self, feature: ProFeature) -> bool:
        """Check if a feature should be visible in UI."""
        config = self._feature_configs.get(feature)
        return config is not None and config.enabled and config.user_visible

    def get_enabled_features(self) -> Set[ProFeature]:
        """Get all currently enabled features."""
        return {
            feature
            for feature, config in self._feature_configs.items()
            if config.enabled
        }

    def get_visible_features(self) -> Set[ProFeature]:
        """Get all features that should be visible in UI."""
        return {
            feature
            for feature, config in self._feature_configs.items()
            if config.enabled and config.user_visible
        }

    def get_feature_cost(self, feature: ProFeature) -> int:
        """Get credit cost for a feature."""
        config = self._feature_configs.get(feature)
        return config.credit_cost if config else 0

    def get_feature_description(self, feature: ProFeature) -> str:
        """Get description for a feature."""
        config = self._feature_configs.get(feature)
        return config.description if config else ""

    def get_constrained_launch_features(self) -> Dict[str, str]:
        """Get features available in constrained launch with descriptions."""
        constrained_features = {}

        for feature in [
            ProFeature.FINDING_INVESTIGATION,
            ProFeature.FALSE_POSITIVE_VERIFICATION,
            ProFeature.INTERACTIVE_CHAT,
            ProFeature.CREDIT_SYSTEM,
        ]:
            if self.is_feature_visible(feature):
                constrained_features[feature.value] = self.get_feature_description(
                    feature
                )

        return constrained_features

    @property
    def launch_phase(self) -> LaunchPhase:
        """Get current launch phase."""
        return self._current_phase

    @property
    def launch_message(self) -> str:
        """Get launch phase description for users."""
        messages = {
            LaunchPhase.CONSTRAINED: "Core interactive AI features available",
            LaunchPhase.BETA_EXPANSION: "Extended Pro features in beta",
            LaunchPhase.FULL_ROLLOUT: "All Pro features available",
        }
        return messages.get(self._current_phase, "Features available")


# Global launch configuration instance
launch_config = LaunchConfig()


def get_launch_config() -> LaunchConfig:
    """Get the global launch configuration."""
    return launch_config


def require_feature(feature: ProFeature):
    """Decorator to require a specific feature to be enabled."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            if not launch_config.is_feature_enabled(feature):
                from fastapi import HTTPException, status

                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Feature '{feature.value}' is not available",
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator
