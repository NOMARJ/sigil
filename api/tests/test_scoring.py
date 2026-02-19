"""
Sigil API — Risk Scoring Tests

Tests the risk scoring engine including per-finding scoring, aggregate
score calculation, and verdict threshold mapping.
"""

from __future__ import annotations


from api.models import Finding, ScanPhase, Severity, Verdict
from api.services.scoring import (
    PHASE_WEIGHTS,
    SEVERITY_SCORES,
    aggregate_score,
    compute_verdict,
    score_finding,
    score_to_verdict,
)


class TestScoreToVerdict:
    """Test the numeric score to verdict mapping."""

    def test_zero_is_clean(self) -> None:
        """Score of 0 should map to CLEAN."""
        assert score_to_verdict(0.0) == Verdict.CLEAN

    def test_negative_is_clean(self) -> None:
        """Negative scores should still map to CLEAN."""
        assert score_to_verdict(-5.0) == Verdict.CLEAN

    def test_low_risk_range(self) -> None:
        """Scores 1-9 should map to LOW_RISK."""
        assert score_to_verdict(1.0) == Verdict.LOW_RISK
        assert score_to_verdict(5.0) == Verdict.LOW_RISK
        assert score_to_verdict(9.99) == Verdict.LOW_RISK

    def test_medium_risk_range(self) -> None:
        """Scores 10-24 should map to MEDIUM_RISK."""
        assert score_to_verdict(10.0) == Verdict.MEDIUM_RISK
        assert score_to_verdict(15.0) == Verdict.MEDIUM_RISK
        assert score_to_verdict(24.99) == Verdict.MEDIUM_RISK

    def test_high_risk_range(self) -> None:
        """Scores 25-49 should map to HIGH_RISK."""
        assert score_to_verdict(25.0) == Verdict.HIGH_RISK
        assert score_to_verdict(35.0) == Verdict.HIGH_RISK
        assert score_to_verdict(49.99) == Verdict.HIGH_RISK

    def test_critical_range(self) -> None:
        """Scores 50+ should map to CRITICAL."""
        assert score_to_verdict(50.0) == Verdict.CRITICAL
        assert score_to_verdict(100.0) == Verdict.CRITICAL
        assert score_to_verdict(999.0) == Verdict.CRITICAL

    def test_boundary_values(self) -> None:
        """Test exact boundary values between verdict ranges."""
        assert score_to_verdict(0) == Verdict.CLEAN
        assert score_to_verdict(0.01) == Verdict.LOW_RISK
        assert score_to_verdict(9.99) == Verdict.LOW_RISK
        assert score_to_verdict(10.0) == Verdict.MEDIUM_RISK
        assert score_to_verdict(24.99) == Verdict.MEDIUM_RISK
        assert score_to_verdict(25.0) == Verdict.HIGH_RISK
        assert score_to_verdict(49.99) == Verdict.HIGH_RISK
        assert score_to_verdict(50.0) == Verdict.CRITICAL


class TestScoreFinding:
    """Test individual finding score calculation."""

    def test_install_hook_critical(self) -> None:
        """CRITICAL install hook finding: 5.0 * 10.0 * 1.0 = 50.0."""
        finding = Finding(
            phase=ScanPhase.INSTALL_HOOKS,
            rule="install-npm-postinstall",
            severity=Severity.CRITICAL,
            file="package.json",
            line=5,
            weight=1.0,
        )
        assert score_finding(finding) == 50.0

    def test_code_pattern_high(self) -> None:
        """HIGH code pattern finding: 3.0 * 5.0 * 1.0 = 15.0."""
        finding = Finding(
            phase=ScanPhase.CODE_PATTERNS,
            rule="code-eval",
            severity=Severity.HIGH,
            file="index.js",
            line=10,
            weight=1.0,
        )
        assert score_finding(finding) == 15.0

    def test_credential_medium(self) -> None:
        """MEDIUM credential finding: 2.0 * 2.0 * 1.0 = 4.0."""
        finding = Finding(
            phase=ScanPhase.CREDENTIALS,
            rule="cred-env-access",
            severity=Severity.MEDIUM,
            file="config.py",
            line=3,
            weight=1.0,
        )
        assert score_finding(finding) == 4.0

    def test_provenance_low(self) -> None:
        """LOW provenance finding: 1.0 * 2.0 * 1.0 = 2.0."""
        finding = Finding(
            phase=ScanPhase.PROVENANCE,
            rule="prov-hidden-file",
            severity=Severity.LOW,
            file=".hidden",
            line=0,
            weight=1.0,
        )
        assert score_finding(finding) == 2.0

    def test_info_severity_zero_score(self) -> None:
        """INFO severity findings should contribute zero score."""
        finding = Finding(
            phase=ScanPhase.PROVENANCE,
            rule="info-test",
            severity=Severity.INFO,
            file="readme.md",
            line=0,
            weight=1.0,
        )
        assert score_finding(finding) == 0.0

    def test_weight_multiplier(self) -> None:
        """Custom weight should multiply the score."""
        finding = Finding(
            phase=ScanPhase.INSTALL_HOOKS,
            rule="install-pip-setup-exec",
            severity=Severity.CRITICAL,
            file="setup.py",
            line=10,
            weight=1.2,
        )
        # 5.0 * 10.0 * 1.2 = 60.0
        assert score_finding(finding) == 60.0

    def test_network_exfil_high(self) -> None:
        """HIGH network/exfil finding: 3.0 * 3.0 * 1.0 = 9.0."""
        finding = Finding(
            phase=ScanPhase.NETWORK_EXFIL,
            rule="net-webhook",
            severity=Severity.HIGH,
            file="exfil.py",
            line=5,
            weight=1.0,
        )
        assert score_finding(finding) == 9.0

    def test_obfuscation_high(self) -> None:
        """HIGH obfuscation finding: 3.0 * 5.0 * 1.0 = 15.0."""
        finding = Finding(
            phase=ScanPhase.OBFUSCATION,
            rule="obf-base64-decode",
            severity=Severity.HIGH,
            file="loader.py",
            line=7,
            weight=1.0,
        )
        assert score_finding(finding) == 15.0


class TestAggregateScore:
    """Test aggregate score calculation across multiple findings."""

    def test_empty_findings(self) -> None:
        """No findings should produce a score of zero."""
        assert aggregate_score([]) == 0.0

    def test_single_finding(self) -> None:
        """Single finding score should equal the individual finding score."""
        findings = [
            Finding(
                phase=ScanPhase.CODE_PATTERNS,
                rule="code-eval",
                severity=Severity.HIGH,
                file="test.py",
                weight=1.0,
            ),
        ]
        assert aggregate_score(findings) == 15.0

    def test_multiple_findings_sum(self) -> None:
        """Multiple findings should sum their individual scores."""
        findings = [
            Finding(
                phase=ScanPhase.INSTALL_HOOKS,
                rule="install-npm-postinstall",
                severity=Severity.CRITICAL,
                file="package.json",
                weight=1.0,
            ),
            Finding(
                phase=ScanPhase.CODE_PATTERNS,
                rule="code-eval",
                severity=Severity.HIGH,
                file="index.js",
                weight=1.0,
            ),
        ]
        # 50.0 + 15.0 = 65.0
        assert aggregate_score(findings) == 65.0

    def test_mixed_severity_findings(self) -> None:
        """Findings with different severities should score correctly."""
        findings = [
            Finding(
                phase=ScanPhase.CREDENTIALS,
                rule="cred-env-access",
                severity=Severity.MEDIUM,
                file="config.py",
                weight=1.0,
            ),
            Finding(
                phase=ScanPhase.CREDENTIALS,
                rule="cred-ssh-private",
                severity=Severity.CRITICAL,
                file="id_rsa",
                weight=1.0,
            ),
        ]
        # MEDIUM: 2.0 * 2.0 = 4.0
        # CRITICAL: 5.0 * 2.0 = 10.0
        # Total: 14.0
        assert aggregate_score(findings) == 14.0


class TestComputeVerdict:
    """Test the convenience compute_verdict function."""

    def test_clean_verdict(self) -> None:
        """No findings should produce (0.0, CLEAN)."""
        score, verdict = compute_verdict([])
        assert score == 0.0
        assert verdict == Verdict.CLEAN

    def test_critical_verdict(self) -> None:
        """A critical install hook finding alone should trigger CRITICAL."""
        findings = [
            Finding(
                phase=ScanPhase.INSTALL_HOOKS,
                rule="install-npm-postinstall",
                severity=Severity.CRITICAL,
                file="package.json",
                weight=1.0,
            ),
        ]
        score, verdict = compute_verdict(findings)
        assert score == 50.0
        assert verdict == Verdict.CRITICAL

    def test_verdict_matches_score(self) -> None:
        """The returned verdict should be consistent with the returned score."""
        findings = [
            Finding(
                phase=ScanPhase.NETWORK_EXFIL,
                rule="net-webhook",
                severity=Severity.MEDIUM,
                file="notify.py",
                weight=1.0,
            ),
        ]
        score, verdict = compute_verdict(findings)
        assert verdict == score_to_verdict(score)


class TestPhaseWeights:
    """Verify phase weight values match the PRD specification."""

    def test_install_hooks_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.INSTALL_HOOKS] == 10.0

    def test_code_patterns_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.CODE_PATTERNS] == 5.0

    def test_network_exfil_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.NETWORK_EXFIL] == 3.0

    def test_credentials_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.CREDENTIALS] == 2.0

    def test_obfuscation_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.OBFUSCATION] == 5.0

    def test_provenance_weight(self) -> None:
        assert PHASE_WEIGHTS[ScanPhase.PROVENANCE] == 2.0


class TestSeverityScores:
    """Verify severity base scores."""

    def test_info_score(self) -> None:
        assert SEVERITY_SCORES[Severity.INFO] == 0.0

    def test_low_score(self) -> None:
        assert SEVERITY_SCORES[Severity.LOW] == 1.0

    def test_medium_score(self) -> None:
        assert SEVERITY_SCORES[Severity.MEDIUM] == 2.0

    def test_high_score(self) -> None:
        assert SEVERITY_SCORES[Severity.HIGH] == 3.0

    def test_critical_score(self) -> None:
        assert SEVERITY_SCORES[Severity.CRITICAL] == 5.0
