"""
Sigil API — Risk Scoring Engine

Computes weighted risk scores per scan phase and derives an aggregate verdict.

Phase weights (from the Sigil PRD):
    Install Hooks  — 10x (Critical)
    Code Patterns  — 5x  (High)
    Network / Exfil — 3x  (High)
    Credentials    — 2x  (Medium)
    Obfuscation    — 5x  (High)
    Provenance     — 1-3x (Low, variable)

Verdict thresholds:
    0        → CLEAN
    1  – 9   → LOW_RISK
    10 – 24  → MEDIUM_RISK
    25 – 49  → HIGH_RISK
    50+      → CRITICAL
"""

from __future__ import annotations

from api.models import Finding, ScanPhase, Severity, Verdict


# ---------------------------------------------------------------------------
# Phase weight multipliers
# ---------------------------------------------------------------------------

PHASE_WEIGHTS: dict[ScanPhase, float] = {
    ScanPhase.INSTALL_HOOKS: 10.0,
    ScanPhase.CODE_PATTERNS: 5.0,
    ScanPhase.NETWORK_EXFIL: 3.0,
    ScanPhase.CREDENTIALS: 2.0,
    ScanPhase.OBFUSCATION: 5.0,
    ScanPhase.PROVENANCE: 2.0,  # Default mid-range for provenance (1-3x)
    ScanPhase.PROMPT_INJECTION: 10.0,  # Critical — the key differentiator vs VirusTotal
    ScanPhase.SKILL_SECURITY: 5.0,  # High — tool poisoning, shell execution
}

# ---------------------------------------------------------------------------
# Severity base scores — each finding contributes a base score before the
# phase weight multiplier is applied.
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.0,
    Severity.HIGH: 3.0,
    Severity.CRITICAL: 5.0,
}


def score_finding(finding: Finding) -> float:
    """Compute the weighted score for a single finding.

    ``score = base_severity * phase_weight * finding.weight``
    """
    base = SEVERITY_SCORES.get(finding.severity, 1.0)
    phase_w = PHASE_WEIGHTS.get(finding.phase, 1.0)
    return base * phase_w * finding.weight


def aggregate_score(findings: list[Finding]) -> float:
    """Sum the weighted scores of all findings and return the total."""
    return sum(score_finding(f) for f in findings)


def score_to_verdict(score: float) -> Verdict:
    """Map a numeric risk score to a ``Verdict`` enum value.

    Thresholds per the Sigil PRD:
        0        → CLEAN
        1  – 9   → LOW_RISK
        10 – 24  → MEDIUM_RISK
        25 – 49  → HIGH_RISK
        50+      → CRITICAL
    """
    if score <= 0:
        return Verdict.CLEAN
    if score < 10:
        return Verdict.LOW_RISK
    if score < 25:
        return Verdict.MEDIUM_RISK
    if score < 50:
        return Verdict.HIGH_RISK
    return Verdict.CRITICAL


def compute_verdict(findings: list[Finding]) -> tuple[float, Verdict]:
    """Convenience helper — returns ``(risk_score, verdict)``."""
    score = aggregate_score(findings)
    return score, score_to_verdict(score)
