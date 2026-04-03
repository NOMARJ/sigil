"""
Test feedback learning and suppression rules
"""

import pytest
from uuid import uuid4

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model_types.suppression_rules import FeedbackType
from models import Finding
from services.feedback_processor import FeedbackProcessor


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing"""
    return Finding(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        pattern_type="OBFUSCATION",
        rule="test_file_pattern",
        severity="LOW",
        confidence=0.8,
        file_path="/tests/test_security.py",
        line_number=42,
        evidence="eval('test_code')",
        description="Eval detected in test file",
        recommendation="Review if eval is necessary",
    )


@pytest.fixture
def feedback_processor():
    """Create feedback processor instance"""
    return FeedbackProcessor()


@pytest.mark.asyncio
async def test_mark_test_file_as_false_positive(feedback_processor, sample_finding):
    """Test: Marking test file pattern as safe suppresses similar findings"""

    # User marks the finding as false positive with high confidence
    user_id = str(uuid4())
    feedback = await feedback_processor.process_feedback(
        user_id=user_id,
        finding=sample_finding,
        feedback_type=FeedbackType.FALSE_POSITIVE,
        confidence=0.95,  # High confidence
        reason="This is a test file, eval is safe here",
        share_with_team=False,
    )

    # Verify feedback was created
    assert feedback is not None
    assert feedback.feedback_type == FeedbackType.FALSE_POSITIVE
    assert feedback.confidence == 0.95
    assert feedback.file_path == "/tests/test_security.py"

    # Create similar findings that should be suppressed
    similar_findings = [
        Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="OBFUSCATION",
            rule="test_file_pattern",
            severity="LOW",
            confidence=0.8,
            file_path="/tests/test_utils.py",  # Another test file
            line_number=10,
            evidence="eval('another_test')",
        ),
        Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="OBFUSCATION",
            rule="test_file_pattern",
            severity="LOW",
            confidence=0.8,
            file_path="/spec/spec_security.py",  # Spec file
            line_number=20,
            evidence="eval('spec_code')",
        ),
        Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="OBFUSCATION",
            rule="test_file_pattern",
            severity="LOW",
            confidence=0.8,
            file_path="/src/main.py",  # NOT a test file
            line_number=30,
            evidence="eval('production_code')",
        ),
    ]

    # Apply suppression rules
    filtered_findings = await feedback_processor.apply_suppression_rules(
        findings=similar_findings, user_id=user_id
    )

    # Test files should be suppressed, but production file should remain
    assert len(filtered_findings) == 1
    assert filtered_findings[0].file_path == "/src/main.py"

    print(
        "✅ Test passed: Marking test file pattern as safe suppresses similar test files"
    )


@pytest.mark.asyncio
async def test_confidence_adjustment_for_false_positive(
    feedback_processor, sample_finding
):
    """Test that false positive feedback adjusts confidence for similar findings"""

    user_id = str(uuid4())

    # Mark as false positive with moderate confidence
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=sample_finding,
        feedback_type=FeedbackType.FALSE_POSITIVE,
        confidence=0.7,  # Not high enough to completely suppress
        reason="Likely safe in this context",
    )

    # Create a similar finding
    similar_finding = Finding(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        pattern_type="OBFUSCATION",
        rule="test_file_pattern",
        severity="LOW",
        confidence=0.8,
        file_path="/tests/another_test.py",
        line_number=50,
        evidence="eval('test')",
    )

    # Apply suppression rules
    filtered_findings = await feedback_processor.apply_suppression_rules(
        findings=[similar_finding], user_id=user_id
    )

    # Finding should still exist but with reduced confidence
    assert len(filtered_findings) == 1
    assert filtered_findings[0].confidence < 0.8  # Confidence reduced
    assert filtered_findings[0].metadata.get("confidence_adjusted") is True

    print("✅ Test passed: False positive feedback adjusts confidence")


@pytest.mark.asyncio
async def test_true_positive_increases_confidence(feedback_processor):
    """Test that true positive feedback increases confidence for similar findings"""

    user_id = str(uuid4())

    # Create a critical finding
    critical_finding = Finding(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        pattern_type="BACKDOOR",
        rule="reverse_shell",
        severity="CRITICAL",
        confidence=0.6,
        file_path="/src/utils.py",
        line_number=100,
        evidence="subprocess.call(['nc', '-e', '/bin/sh'])",
    )

    # Mark as true positive
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=critical_finding,
        feedback_type=FeedbackType.TRUE_POSITIVE,
        confidence=1.0,
        reason="This is definitely a backdoor!",
    )

    # Create a similar finding
    similar_finding = Finding(
        id=str(uuid4()),
        scan_id=str(uuid4()),
        pattern_type="BACKDOOR",
        rule="reverse_shell",
        severity="CRITICAL",
        confidence=0.6,
        file_path="/src/helper.py",
        line_number=200,
        evidence="subprocess.call(['nc', '-lvp'])",
    )

    # Apply suppression rules (which also handle confidence boosts)
    filtered_findings = await feedback_processor.apply_suppression_rules(
        findings=[similar_finding], user_id=user_id
    )

    # Finding should have increased confidence
    assert len(filtered_findings) == 1
    assert filtered_findings[0].confidence > 0.6  # Confidence increased

    print("✅ Test passed: True positive feedback increases confidence")


@pytest.mark.asyncio
async def test_team_suppression_rule(feedback_processor, sample_finding):
    """Test that team suppression rules apply to team members"""

    team_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    # User 1 creates a team suppression rule
    await feedback_processor.process_feedback(
        user_id=user1_id,
        finding=sample_finding,
        feedback_type=FeedbackType.FALSE_POSITIVE,
        confidence=0.95,
        reason="Our team uses eval in tests, it's safe",
        share_with_team=True,
        team_id=team_id,
    )

    # User 2 (team member) scans similar code
    team_member_findings = [
        Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="OBFUSCATION",
            rule="test_file_pattern",
            severity="LOW",
            confidence=0.8,
            file_path="/tests/team_test.py",
            line_number=60,
            evidence="eval('team_test')",
        )
    ]

    # Apply suppression rules for team member
    filtered_findings = await feedback_processor.apply_suppression_rules(
        findings=team_member_findings, user_id=user2_id, team_id=team_id
    )

    # Team suppression should apply
    assert len(filtered_findings) == 0  # Suppressed by team rule

    print("✅ Test passed: Team suppression rules apply to team members")


@pytest.mark.asyncio
async def test_accuracy_metrics(feedback_processor):
    """Test accuracy metrics calculation"""

    user_id = str(uuid4())

    # Simulate multiple feedback entries
    findings = [
        Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="SQL_INJECTION",
            rule="sql_concat",
            severity="HIGH",
            confidence=0.8,
            file_path=f"/src/db_{i}.py",
            line_number=i * 10,
            evidence=f"query = 'SELECT * FROM users WHERE id=' + str({i})",
        )
        for i in range(5)
    ]

    # Submit varied feedback
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=findings[0],
        feedback_type=FeedbackType.TRUE_POSITIVE,
        confidence=0.9,
    )
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=findings[1],
        feedback_type=FeedbackType.TRUE_POSITIVE,
        confidence=0.85,
    )
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=findings[2],
        feedback_type=FeedbackType.FALSE_POSITIVE,
        confidence=0.8,
    )
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=findings[3],
        feedback_type=FeedbackType.FALSE_POSITIVE,
        confidence=0.75,
    )
    await feedback_processor.process_feedback(
        user_id=user_id,
        finding=findings[4],
        feedback_type=FeedbackType.UNCERTAIN,
        confidence=0.5,
    )

    # Get accuracy metrics
    metrics = await feedback_processor.get_accuracy_metrics(
        user_id=user_id, time_period="30d"
    )

    # Verify metrics structure
    assert metrics.total_feedback > 0
    assert 0 <= metrics.true_positive_rate <= 1
    assert 0 <= metrics.false_positive_rate <= 1
    assert 0 <= metrics.precision <= 1
    assert 0 <= metrics.f1_score <= 1
    assert metrics.accuracy_trend in ["improving", "stable", "worsening"]

    print("✅ Test passed: Accuracy metrics calculated correctly")


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        processor = FeedbackProcessor()

        # Create sample finding
        finding = Finding(
            id=str(uuid4()),
            scan_id=str(uuid4()),
            pattern_type="OBFUSCATION",
            rule="test_file_pattern",
            severity="LOW",
            confidence=0.8,
            file_path="/tests/test_security.py",
            line_number=42,
            evidence="eval('test_code')",
            description="Eval detected in test file",
            recommendation="Review if eval is necessary",
        )

        print("Testing feedback learning system...")
        print("-" * 50)

        await test_mark_test_file_as_false_positive(processor, finding)
        await test_confidence_adjustment_for_false_positive(processor, finding)
        await test_true_positive_increases_confidence(processor)
        await test_team_suppression_rule(processor, finding)
        await test_accuracy_metrics(processor)

        print("-" * 50)
        print("All tests passed! ✅")

    asyncio.run(run_tests())
