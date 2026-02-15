use super::{Finding, Phase, Severity, Verdict};

/// Phase weight multipliers matching the Sigil scan specification:
///
/// - InstallHooks:  10x (Critical)
/// - CodePatterns:   5x (High)
/// - NetworkExfil:   3x (High)
/// - Credentials:    2x (Medium)
/// - Obfuscation:    5x (High)
/// - Provenance:   1-3x (Low, varies per finding)
pub fn phase_weight(phase: Phase) -> u32 {
    match phase {
        Phase::InstallHooks => 10,
        Phase::CodePatterns => 5,
        Phase::NetworkExfil => 3,
        Phase::Credentials => 2,
        Phase::Obfuscation => 5,
        // Provenance uses per-finding weights (1-3), so default to 1 here.
        // Individual findings carry their own weight field.
        Phase::Provenance => 1,
    }
}

/// Severity base score: used in combination with phase weight.
fn severity_score(severity: Severity) -> u32 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 5,
    }
}

/// Calculate the aggregate risk score from a list of findings.
///
/// Each finding contributes: `severity_score * finding.weight`
///
/// The weight on each finding already reflects the phase multiplier
/// (set at creation time in the phases module).
pub fn calculate_score(findings: &[Finding]) -> u32 {
    findings
        .iter()
        .map(|f| severity_score(f.severity) * f.weight)
        .sum()
}

/// Determine the overall verdict from findings and the aggregate score.
///
/// Thresholds (aligned with the bash CLI and API):
/// - **Clean**: no findings at all
/// - **LowRisk**: score 1-9
/// - **MediumRisk**: score 10-24
/// - **HighRisk**: score 25-49
/// - **Critical**: score >= 50, or any single Critical-severity finding
///   from the InstallHooks phase (immediate escalation)
pub fn determine_verdict(findings: &[Finding], score: u32) -> Verdict {
    if findings.is_empty() {
        return Verdict::Clean;
    }

    // Immediate escalation: any Critical finding in InstallHooks
    let has_critical_install = findings.iter().any(|f| {
        f.phase == Phase::InstallHooks && f.severity == Severity::Critical
    });

    if has_critical_install || score >= 50 {
        return Verdict::Critical;
    }

    if score >= 25 {
        return Verdict::HighRisk;
    }

    if score >= 10 {
        return Verdict::MediumRisk;
    }

    Verdict::LowRisk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_finding(phase: Phase, severity: Severity, weight: u32) -> Finding {
        Finding {
            phase,
            rule: "TEST-000".to_string(),
            severity,
            file: "test.py".to_string(),
            line: Some(1),
            snippet: "test".to_string(),
            weight,
        }
    }

    #[test]
    fn test_clean_verdict() {
        let findings: Vec<Finding> = vec![];
        let score = calculate_score(&findings);
        assert_eq!(score, 0);
        assert_eq!(determine_verdict(&findings, score), Verdict::Clean);
    }

    #[test]
    fn test_low_risk_verdict() {
        let findings = vec![
            dummy_finding(Phase::Provenance, Severity::Low, 1),
            dummy_finding(Phase::Provenance, Severity::Low, 1),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score, 2);
        assert_eq!(determine_verdict(&findings, score), Verdict::LowRisk);
    }

    #[test]
    fn test_medium_risk_verdict() {
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            dummy_finding(Phase::NetworkExfil, Severity::Medium, 3),
        ];
        let score = calculate_score(&findings);
        // 3*5 + 2*3 = 15 + 6 = 21
        assert_eq!(score, 21);
        assert_eq!(determine_verdict(&findings, score), Verdict::MediumRisk);
    }

    #[test]
    fn test_high_risk_verdict() {
        // Score needs to be in range 25-49 for HighRisk
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            dummy_finding(Phase::NetworkExfil, Severity::Medium, 3),
            dummy_finding(Phase::Credentials, Severity::Medium, 2),
        ];
        let score = calculate_score(&findings);
        // 3*5 + 2*3 + 2*2 = 15+6+4 = 25
        assert_eq!(score, 25);
        assert_eq!(determine_verdict(&findings, score), Verdict::HighRisk);
    }

    #[test]
    fn test_critical_install_hook_escalation() {
        let findings = vec![
            dummy_finding(Phase::InstallHooks, Severity::Critical, 10),
        ];
        let score = calculate_score(&findings);
        // Critical install hook always escalates to Critical verdict
        assert_eq!(determine_verdict(&findings, score), Verdict::Critical);
    }

    #[test]
    fn test_critical_by_score() {
        // Score >= 50 triggers Critical verdict
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::Critical, 5),
            dummy_finding(Phase::Obfuscation, Severity::Critical, 5),
        ];
        let score = calculate_score(&findings);
        // 5*5 + 5*5 = 25+25 = 50
        assert_eq!(score, 50);
        assert!(score >= 50);
        assert_eq!(determine_verdict(&findings, score), Verdict::Critical);
    }
}
