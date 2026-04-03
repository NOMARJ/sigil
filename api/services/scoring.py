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

Risk classification thresholds:
    0  – 9   → LOW_RISK
    10 – 24  → MEDIUM_RISK
    25 – 49  → HIGH_RISK
    50+      → CRITICAL_RISK
"""

from __future__ import annotations

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from api.models import Finding, ScanPhase, Severity, Verdict
except ImportError:
    from models import Finding, ScanPhase, Severity, Verdict


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


def get_context_weight(file_path: str) -> float:
    """Get the weight multiplier based on file context.

    Test files are less risky than production code.
    Documentation files are even less risky.
    node_modules are vendor code and typically less concerning.
    """
    file_path_lower = file_path.lower()

    # node_modules are vendor code - very low weight
    if "node_modules/" in file_path_lower or "/node_modules/" in file_path_lower:
        return 0.1

    # Documentation files - low weight
    if any(
        doc in file_path_lower
        for doc in [
            "readme",
            "doc/",
            "/doc/",
            "docs/",
            "/docs/",
            ".md",
            ".rst",
            ".txt",
            "changelog",
            "contributing",
        ]
    ):
        return 0.2

    # Test files - reduced weight
    if any(
        test in file_path_lower
        for test in [
            "test/",
            "/test/",
            "tests/",
            "/tests/",
            "spec/",
            "/spec/",
            "test.",
            ".test.",
            "spec.",
            ".spec.",
            "__test__",
            "__tests__",
            "test_",
            "_test.py",
        ]
    ):
        return 0.3

    # Production code - full weight
    return 1.0


def score_finding(finding: Finding) -> float:
    """Compute the weighted score for a single finding.

    ``score = base_severity * phase_weight * finding.weight * context_weight``
    """
    base = SEVERITY_SCORES.get(finding.severity, 1.0)
    phase_w = PHASE_WEIGHTS.get(finding.phase, 1.0)
    context_w = get_context_weight(finding.file)
    return base * phase_w * finding.weight * context_w


def aggregate_score(findings: list[Finding]) -> float:
    """Sum the weighted scores of all findings and return the total."""
    return sum(score_finding(f) for f in findings)


def score_to_verdict(score: float) -> Verdict:
    """Map a numeric risk score to a ``Verdict`` enum value.

    Risk classification thresholds:
        0  – 9   → LOW_RISK
        10 – 24  → MEDIUM_RISK
        25 – 49  → HIGH_RISK
        50+      → CRITICAL_RISK
    """
    if score < 10:
        return Verdict.LOW_RISK
    if score < 25:
        return Verdict.MEDIUM_RISK
    if score < 50:
        return Verdict.HIGH_RISK
    return Verdict.CRITICAL_RISK


def compute_verdict(findings: list[Finding]) -> tuple[float, Verdict]:
    """Convenience helper — returns ``(risk_score, verdict)``."""
    score = aggregate_score(findings)
    return score, score_to_verdict(score)
