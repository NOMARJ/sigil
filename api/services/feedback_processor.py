"""
Feedback Processing Service
Processes user feedback to learn suppression rules and improve accuracy
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import re
from uuid import uuid4

from api.model_types.suppression_rules import (
    FeedbackType,
    SuppressionScope,
    SuppressionRule,
    UserFeedback,
    AccuracyMetrics,
)
from api.models import Finding
from ..services.credit_service import CreditService
from ..services.claude_service import ClaudeService
from ..utils.logger import get_logger

logger = get_logger(__name__)


class FeedbackProcessor:
    """Processes user feedback to learn and improve detection accuracy"""

    def __init__(self):
        self.credit_service = CreditService()
        self.claude_service = ClaudeService()

    async def process_feedback(
        self,
        user_id: str,
        finding: Finding,
        feedback_type: FeedbackType,
        confidence: float = 1.0,
        reason: Optional[str] = None,
        share_with_team: bool = False,
        team_id: Optional[str] = None,
    ) -> UserFeedback:
        """
        Process user feedback on a finding

        Args:
            user_id: User providing feedback
            finding: The finding being evaluated
            feedback_type: Type of feedback (true/false positive/uncertain)
            confidence: User confidence in feedback (0-1)
            reason: Optional explanation
            share_with_team: Share feedback with team
            team_id: Team to share with

        Returns:
            Created feedback record
        """
        try:
            # Create feedback record
            feedback = UserFeedback(
                feedback_id=str(uuid4()),
                user_id=user_id,
                finding_id=finding.id,
                scan_id=finding.scan_id,
                feedback_type=feedback_type,
                confidence=confidence,
                reason=reason,
                pattern_type=finding.pattern_type,
                rule_name=finding.rule,
                file_path=finding.file_path,
                line_number=finding.line_number,
                severity=finding.severity,
                share_with_team=share_with_team,
                team_id=team_id,
            )

            # Store feedback in database
            await self._store_feedback(feedback)

            # Check if we should create/update suppression rule
            if feedback_type in [
                FeedbackType.FALSE_POSITIVE,
                FeedbackType.TRUE_POSITIVE,
            ]:
                await self._process_suppression_rules(feedback, finding)

            # Update aggregated metrics
            await self._update_aggregations(feedback)

            logger.info(
                f"Processed feedback {feedback.feedback_id} for finding {finding.id}"
            )
            return feedback

        except Exception as e:
            logger.error(f"Failed to process feedback: {e}")
            raise

    async def _store_feedback(self, feedback: UserFeedback) -> None:
        """Store feedback in database"""
        # query = """
        #     INSERT INTO user_feedback (
        #         feedback_id, user_id, finding_id, scan_id,
        #         feedback_type, confidence, reason,
        #         pattern_type, rule_name, file_path, line_number,
        #         severity, created_at, share_with_team, team_id
        #     ) VALUES (
        #         :feedback_id, :user_id, :finding_id, :scan_id,
        #         :feedback_type, :confidence, :reason,
        #         :pattern_type, :rule_name, :file_path, :line_number,
        #         :severity, :created_at, :share_with_team, :team_id
        #     )
        # """

        # params = {
        #     'feedback_id': feedback.feedback_id,
        #     'user_id': feedback.user_id,
        #     'finding_id': feedback.finding_id,
        #     'scan_id': feedback.scan_id,
        #     'feedback_type': feedback.feedback_type.value,
        #     'confidence': feedback.confidence,
        #     'reason': feedback.reason,
        #     'pattern_type': feedback.pattern_type,
        #     'rule_name': feedback.rule_name,
        #     'file_path': feedback.file_path,
        #     'line_number': feedback.line_number,
        #     'severity': feedback.severity,
        #     'created_at': feedback.created_at,
        #     'share_with_team': feedback.share_with_team,
        #     'team_id': feedback.team_id
        # }

        # Execute query (implementation depends on database client)
        # await self.db.execute(query, params)
        logger.info(f"Stored feedback {feedback.feedback_id}")

    async def _process_suppression_rules(
        self, feedback: UserFeedback, finding: Finding
    ) -> Optional[SuppressionRule]:
        """
        Create or update suppression rules based on feedback

        Args:
            feedback: User feedback
            finding: Original finding

        Returns:
            Created/updated suppression rule if applicable
        """
        try:
            # Check for existing rule
            existing_rule = await self._find_existing_rule(
                user_id=feedback.user_id,
                pattern_type=feedback.pattern_type,
                rule_name=feedback.rule_name,
                file_pattern=feedback.file_path,
            )

            if existing_rule:
                # Update existing rule
                return await self._update_rule(existing_rule, feedback)
            else:
                # Create new rule if confidence is high enough
                if feedback.confidence >= 0.8:
                    return await self._create_rule(feedback, finding)

            return None

        except Exception as e:
            logger.error(f"Failed to process suppression rules: {e}")
            return None

    async def _create_rule(
        self, feedback: UserFeedback, finding: Finding
    ) -> SuppressionRule:
        """Create new suppression rule from feedback"""

        # Determine suppression scope
        scope = SuppressionScope.PERSONAL
        if feedback.share_with_team and feedback.team_id:
            scope = SuppressionScope.TEAM

        # Calculate confidence adjustment
        confidence_adjustment = 0.0
        suppress_completely = False

        if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            confidence_adjustment = -0.5  # Reduce confidence for similar findings
            if feedback.confidence >= 0.95:
                suppress_completely = True  # Very confident false positive
        elif feedback.feedback_type == FeedbackType.TRUE_POSITIVE:
            confidence_adjustment = 0.2  # Increase confidence slightly

        # Create file pattern regex
        file_pattern = self._create_file_pattern(feedback.file_path)

        # Extract evidence pattern if available
        evidence_pattern = None
        if finding.evidence:
            evidence_pattern = self._create_evidence_pattern(finding.evidence)

        rule = SuppressionRule(
            rule_id=str(uuid4()),
            user_id=feedback.user_id,
            team_id=feedback.team_id if scope == SuppressionScope.TEAM else None,
            pattern_type=feedback.pattern_type,
            rule_name=feedback.rule_name,
            file_pattern=file_pattern,
            evidence_pattern=evidence_pattern,
            scope=scope,
            confidence_adjustment=confidence_adjustment,
            suppress_completely=suppress_completely,
            original_finding_id=feedback.finding_id,
            original_feedback=feedback.feedback_type,
            reason=feedback.reason,
            effectiveness_score=feedback.confidence,
        )

        # Store rule in database
        await self._store_rule(rule)

        logger.info(f"Created suppression rule {rule.rule_id}")
        return rule

    async def _update_rule(
        self, existing_rule: SuppressionRule, feedback: UserFeedback
    ) -> SuppressionRule:
        """Update existing suppression rule with new feedback"""

        # Increment feedback count
        existing_rule.feedback_count += 1
        existing_rule.updated_at = datetime.utcnow()

        # Adjust confidence based on feedback consistency
        if feedback.feedback_type == existing_rule.original_feedback:
            # Consistent feedback strengthens the rule
            existing_rule.effectiveness_score = min(
                1.0, existing_rule.effectiveness_score + 0.1
            )

            # Make adjustment stronger if consistent
            if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
                existing_rule.confidence_adjustment = max(
                    -1.0, existing_rule.confidence_adjustment - 0.1
                )
        else:
            # Contradictory feedback weakens the rule
            existing_rule.effectiveness_score = max(
                0.0, existing_rule.effectiveness_score - 0.2
            )
            existing_rule.times_overridden += 1

            # Deactivate rule if effectiveness too low
            if existing_rule.effectiveness_score < 0.3:
                existing_rule.active = False

        # Update rule in database
        await self._update_rule_in_db(existing_rule)

        logger.info(f"Updated suppression rule {existing_rule.rule_id}")
        return existing_rule

    def _create_file_pattern(self, file_path: str) -> str:
        """Create regex pattern for file path matching"""
        # Escape special regex characters
        escaped = re.escape(file_path)

        # Replace test/spec indicators with pattern
        patterns = [
            (r"\.test\.", r"\.(test|spec)\."),
            (r"\.spec\.", r"\.(test|spec)\."),
            (r"/tests?/", r"/tests?/"),
            (r"/specs?/", r"/(tests?|specs?)/"),
            (r"__tests__", r"__(tests?|specs?)__"),
        ]

        for old, new in patterns:
            escaped = re.sub(old, new, escaped, flags=re.IGNORECASE)

        return escaped

    def _create_evidence_pattern(self, evidence: str) -> str:
        """Create regex pattern for evidence matching"""
        # Extract key patterns from evidence
        if len(evidence) > 100:
            # For long evidence, extract key portions
            words = evidence.split()[:10]  # First 10 words
            pattern = r"\s*".join(re.escape(word) for word in words)
            return pattern + r".*"
        else:
            # For short evidence, match more precisely
            return re.escape(evidence)

    async def apply_suppression_rules(
        self, findings: List[Finding], user_id: str, team_id: Optional[str] = None
    ) -> List[Finding]:
        """
        Apply suppression rules to a list of findings

        Args:
            findings: List of findings to process
            user_id: User requesting the scan
            team_id: Optional team ID for team rules

        Returns:
            Filtered/adjusted findings list
        """
        try:
            # Get applicable rules
            rules = await self._get_applicable_rules(user_id, team_id)

            if not rules:
                return findings

            processed_findings = []

            for finding in findings:
                suppressed = False
                confidence_adjustment = 0.0

                for rule in rules:
                    if self._rule_matches_finding(rule, finding):
                        # Track rule application
                        await self._track_rule_application(rule.rule_id)

                        if rule.suppress_completely and rule.active:
                            suppressed = True
                            logger.debug(
                                f"Suppressed finding {finding.id} by rule {rule.rule_id}"
                            )
                            break
                        elif rule.active:
                            confidence_adjustment += rule.confidence_adjustment

                if not suppressed:
                    # Apply confidence adjustment
                    if confidence_adjustment != 0:
                        finding.confidence = max(
                            0.0, min(1.0, finding.confidence + confidence_adjustment)
                        )
                        finding.metadata = finding.metadata or {}
                        finding.metadata["confidence_adjusted"] = True
                        finding.metadata["adjustment"] = confidence_adjustment

                    processed_findings.append(finding)

            logger.info(
                f"Applied suppression rules: {len(findings)} -> {len(processed_findings)} findings"
            )
            return processed_findings

        except Exception as e:
            logger.error(f"Failed to apply suppression rules: {e}")
            return findings  # Return original on error

    def _rule_matches_finding(self, rule: SuppressionRule, finding: Finding) -> bool:
        """Check if a rule matches a finding"""
        # Check pattern type and rule name
        if rule.pattern_type != finding.pattern_type:
            return False
        if rule.rule_name != finding.rule:
            return False

        # Check file pattern if specified
        if rule.file_pattern:
            if not re.search(rule.file_pattern, finding.file_path):
                return False

        # Check evidence pattern if specified
        if rule.evidence_pattern and finding.evidence:
            if not re.search(rule.evidence_pattern, finding.evidence):
                return False

        return True

    async def get_accuracy_metrics(
        self,
        user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        time_period: str = "30d",
    ) -> AccuracyMetrics:
        """
        Get accuracy metrics for feedback learning

        Args:
            user_id: Optional user ID for user-specific metrics
            team_id: Optional team ID for team metrics
            time_period: Time period for metrics (e.g., "30d", "7d")

        Returns:
            Accuracy metrics
        """
        try:
            # Calculate date range
            days = int(time_period.rstrip("d"))
            start_date = datetime.utcnow() - timedelta(days=days)

            # Get feedback statistics
            stats = await self._get_feedback_stats(user_id, team_id, start_date)

            # Calculate metrics
            total_feedback = stats["total_feedback"]
            tp_count = stats["true_positive_count"]
            fp_count = stats["false_positive_count"]
            # uncertain_count = stats['uncertain_count']  # Reserved for future use

            # Calculate rates
            tpr = tp_count / total_feedback if total_feedback > 0 else 0
            fpr = fp_count / total_feedback if total_feedback > 0 else 0

            # Calculate precision/recall/f1
            precision = (
                tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
            )
            recall = tpr  # Same as TPR in this context
            f1_score = (
                2 * (precision * recall) / (precision + recall)
                if (precision + recall) > 0
                else 0
            )

            # Get pattern-specific accuracy
            pattern_accuracy = await self._get_pattern_accuracy(
                user_id, team_id, start_date
            )

            # Get suppression effectiveness
            suppression_stats = await self._get_suppression_stats(
                user_id, team_id, start_date
            )

            # Determine trend
            trend = self._calculate_trend(stats, time_period)

            metrics = AccuracyMetrics(
                user_id=user_id,
                team_id=team_id,
                time_period=time_period,
                total_findings=stats["total_findings"],
                total_feedback=total_feedback,
                feedback_rate=total_feedback / stats["total_findings"]
                if stats["total_findings"] > 0
                else 0,
                true_positive_rate=tpr,
                false_positive_rate=fpr,
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                pattern_accuracy=pattern_accuracy,
                suppression_rules_created=suppression_stats["rules_created"],
                suppressions_applied=suppression_stats["suppressions_applied"],
                suppressions_overridden=suppression_stats["suppressions_overridden"],
                learning_effectiveness=suppression_stats["effectiveness"],
                accuracy_trend=trend["accuracy_trend"],
                improvement_rate=trend["improvement_rate"],
            )

            logger.info(f"Generated accuracy metrics for period {time_period}")
            return metrics

        except Exception as e:
            logger.error(f"Failed to get accuracy metrics: {e}")
            # Return empty metrics on error
            return AccuracyMetrics(
                user_id=user_id, team_id=team_id, time_period=time_period
            )

    async def _get_feedback_stats(
        self, user_id: Optional[str], team_id: Optional[str], start_date: datetime
    ) -> Dict[str, Any]:
        """Get feedback statistics from database"""
        # Mock implementation - replace with actual database query
        return {
            "total_findings": 1000,
            "total_feedback": 150,
            "true_positive_count": 100,
            "false_positive_count": 40,
            "uncertain_count": 10,
        }

    async def _get_pattern_accuracy(
        self, user_id: Optional[str], team_id: Optional[str], start_date: datetime
    ) -> Dict[str, Dict[str, float]]:
        """Get pattern-specific accuracy metrics"""
        # Mock implementation - replace with actual database query
        return {
            "SQL_INJECTION": {"precision": 0.95, "recall": 0.88, "f1_score": 0.91},
            "XSS": {"precision": 0.82, "recall": 0.75, "f1_score": 0.78},
        }

    async def _get_suppression_stats(
        self, user_id: Optional[str], team_id: Optional[str], start_date: datetime
    ) -> Dict[str, Any]:
        """Get suppression rule statistics"""
        # Mock implementation - replace with actual database query
        return {
            "rules_created": 12,
            "suppressions_applied": 45,
            "suppressions_overridden": 3,
            "effectiveness": 0.85,
        }

    def _calculate_trend(
        self, stats: Dict[str, Any], time_period: str
    ) -> Dict[str, Any]:
        """Calculate accuracy trend"""
        # Mock implementation - would compare with previous period
        return {"accuracy_trend": "improving", "improvement_rate": 0.05}

    async def _find_existing_rule(
        self, user_id: str, pattern_type: str, rule_name: str, file_pattern: str
    ) -> Optional[SuppressionRule]:
        """Find existing suppression rule"""
        # Mock implementation - replace with database query
        return None

    async def _store_rule(self, rule: SuppressionRule) -> None:
        """Store suppression rule in database"""
        # Mock implementation - replace with database insert
        logger.info(f"Would store rule {rule.rule_id}")

    async def _update_rule_in_db(self, rule: SuppressionRule) -> None:
        """Update suppression rule in database"""
        # Mock implementation - replace with database update
        logger.info(f"Would update rule {rule.rule_id}")

    async def _get_applicable_rules(
        self, user_id: str, team_id: Optional[str]
    ) -> List[SuppressionRule]:
        """Get applicable suppression rules for user/team"""
        # Mock implementation - replace with database query
        return []

    async def _track_rule_application(self, rule_id: str) -> None:
        """Track that a rule was applied"""
        # Mock implementation - update times_applied counter
        logger.debug(f"Applied rule {rule_id}")

    async def _update_aggregations(self, feedback: UserFeedback) -> None:
        """Update aggregated feedback statistics"""
        # Mock implementation - update aggregation tables
        logger.debug(f"Updated aggregations for feedback {feedback.feedback_id}")
