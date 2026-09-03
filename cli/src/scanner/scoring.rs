use std::collections::{HashMap, HashSet};

use super::{Evidence, Finding, Phase, Severity, Verdict};

/// Phase weight multipliers matching the Sigil scan specification:
///
/// - InstallHooks:  10x (Critical)
/// - CodePatterns:   5x (High)
/// - NetworkExfil:   3x (High)
/// - Credentials:    2x (Medium)
/// - Obfuscation:    5x (High)
/// - Provenance:   1-3x (Low, varies per finding)
#[allow(dead_code)]
pub fn phase_weight(phase: Phase) -> u32 {
    phase.default_weight()
}

/// How many findings from the same `(rule, file)` pair may contribute to the
/// aggregate score.
///
/// The score is a sum, so before this cap a single file could dominate the
/// verdict by repetition alone: `idna`'s Unicode mapping table matched
/// `OBFUSC-CHAIN-008` 1,723 times and drove a 19,140-point HIGH RISK verdict
/// on a package whose only sin is shipping the IDNA data it exists to
/// implement. The 1,724th combining mark in one file is not new evidence
/// about whether to trust the package — it is the same observation restated.
///
/// Three is where restating stops adding information. On the 20-package clean
/// control set the cap (with the pack changes that shipped beside it) takes
/// `idna` from 19,140 to 155 and `urllib3` from 4,448 to 547. Replaying the
/// recorded findings of those same scans at caps of 1, 2, 3 and 5 gives the
/// same verdict for every package at 2, 3 and 5; only a cap of 1 moves any
/// package, and replaying 60 recorded malicious `ai-skills` scans the same way
/// shows a cap of 1 dropping two of them below the HIGH score threshold. Three
/// keeps the volume gradient a reader expects while removing the runaway.
///
/// Every finding is still reported and still counted in `findings_count` —
/// only its contribution to the score saturates.
pub const PER_RULE_FILE_SCORE_CAP: usize = 3;

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
/// Each finding contributes `severity_score * finding.weight`, except that at
/// most [`PER_RULE_FILE_SCORE_CAP`] findings from the same `(rule, file)` pair
/// are counted — see that constant for why.
///
/// The weight on each finding already reflects the phase multiplier
/// (set at creation time in the phases module).
pub fn calculate_score(findings: &[Finding]) -> u32 {
    let mut counted: HashMap<(&str, &str), usize> = HashMap::new();
    let mut score = 0u32;
    for f in findings {
        let seen = counted
            .entry((f.rule.as_str(), f.file.as_str()))
            .or_insert(0);
        *seen += 1;
        if *seen <= PER_RULE_FILE_SCORE_CAP {
            score = score.saturating_add(severity_score(f.severity) * f.weight);
        }
    }
    score
}

/// Determine the overall risk classification from findings and the aggregate score.
///
/// Thresholds:
/// - **LowRisk**: score 0-9
/// - **MediumRisk**: score 10-24
/// - **HighRisk**: score >= 25, unless critical evidence is present
/// - **CriticalRisk**: critical evidence, as defined below
///
/// Critical is evidence-gated, not score-only. A large pile of medium/low
/// heuristics can raise the aggregate risk, but it must not claim "almost
/// certainly malicious" unless at least one rule actually emitted Critical.
///
/// Not every Critical rule earns that claim by itself. A rule marked
/// `"evidence": "corroborate"` in its pack (see
/// [`crate::corpus::schema::Evidence`]) reports at Critical and contributes
/// its full weight to the score, but only gates the verdict when a *second,
/// different* corroborating rule also fired: `requests` ships expired test
/// certificates and `dotenv` documents a private key in its README, and one
/// `CRED-006` line in either is not evidence that the package is malicious.
/// Two independent corroborating Criticals is a different claim from one.
pub fn determine_verdict(findings: &[Finding], score: u32) -> Verdict {
    let mut standalone_critical = false;
    let mut corroborating: HashSet<&str> = HashSet::new();
    for f in findings.iter().filter(|f| f.severity == Severity::Critical) {
        match f.evidence {
            Evidence::Standalone => standalone_critical = true,
            Evidence::Corroborate => {
                corroborating.insert(f.rule.as_str());
            }
        }
    }

    if standalone_critical || corroborating.len() >= 2 {
        return Verdict::CriticalRisk;
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
        finding_in(phase, severity, weight, "TEST-000", "test.py")
    }

    fn finding_in(
        phase: Phase,
        severity: Severity,
        weight: u32,
        rule: &str,
        file: &str,
    ) -> Finding {
        Finding {
            phase,
            rule: rule.to_string(),
            severity,
            file: file.to_string(),
            line: Some(1),
            snippet: "test".to_string(),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Evidence::Standalone,
        }
    }

    fn corroborating(rule: &str, file: &str) -> Finding {
        let mut f = finding_in(Phase::Credentials, Severity::Critical, 2, rule, file);
        f.evidence = Evidence::Corroborate;
        f
    }

    #[test]
    fn test_low_risk_no_findings() {
        let findings: Vec<Finding> = vec![];
        let score = calculate_score(&findings);
        assert_eq!(score, 0);
        assert_eq!(determine_verdict(&findings, score), Verdict::LowRisk);
    }

    #[test]
    fn test_low_risk_verdict() {
        let findings = vec![
            finding_in(Phase::Provenance, Severity::Low, 1, "PROV-001", "a.py"),
            finding_in(Phase::Provenance, Severity::Low, 1, "PROV-001", "b.py"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score, 2);
        assert_eq!(determine_verdict(&findings, score), Verdict::LowRisk);
    }

    #[test]
    fn test_medium_risk_verdict() {
        let findings = vec![
            dummy_finding(Phase::CodePatterns, Severity::High, 5),
            finding_in(Phase::NetworkExfil, Severity::Medium, 3, "NET-001", "n.py"),
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
            finding_in(Phase::NetworkExfil, Severity::Medium, 3, "NET-001", "n.py"),
            finding_in(Phase::Credentials, Severity::Medium, 2, "CRED-001", "c.py"),
        ];
        let score = calculate_score(&findings);
        // 3*5 + 2*3 + 2*2 = 15+6+4 = 25
        assert_eq!(score, 25);
        assert_eq!(determine_verdict(&findings, score), Verdict::HighRisk);
    }

    #[test]
    fn test_critical_risk_install_hook_escalation() {
        let findings = vec![dummy_finding(Phase::InstallHooks, Severity::Critical, 10)];
        let score = calculate_score(&findings);
        // Critical install hook always escalates to CriticalRisk
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn test_critical_risk_by_score() {
        // Two standalone Criticals: still CriticalRisk, and the score is the
        // plain sum because they come from different rules and files.
        let findings = vec![
            finding_in(
                Phase::CodePatterns,
                Severity::Critical,
                5,
                "CODE-001",
                "a.js",
            ),
            finding_in(
                Phase::Obfuscation,
                Severity::Critical,
                5,
                "OBFUSC-001",
                "b.js",
            ),
        ];
        let score = calculate_score(&findings);
        // 5*5 + 5*5 = 25+25 = 50
        assert_eq!(score, 50);
        assert!(score >= 50);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn test_medium_low_volume_does_not_become_critical() {
        // Spread over distinct files so the per-(rule, file) cap does not
        // apply: this test is about volume never *escalating* to Critical.
        let findings: Vec<Finding> = (0..20)
            .map(|i| {
                finding_in(
                    Phase::NetworkExfil,
                    Severity::Medium,
                    3,
                    "NET-001",
                    &format!("n{i}.py"),
                )
            })
            .chain((0..20).map(|i| {
                finding_in(
                    Phase::Provenance,
                    Severity::Low,
                    1,
                    "PROV-001",
                    &format!("p{i}.py"),
                )
            }))
            .collect();
        let score = calculate_score(&findings);
        assert_eq!(score, 140);
        assert_eq!(determine_verdict(&findings, score), Verdict::HighRisk);
    }

    // -- per-(rule, file) contribution cap ---------------------------------

    #[test]
    fn score_saturates_after_three_hits_of_one_rule_in_one_file() {
        let many: Vec<Finding> = (0..1723)
            .map(|_| {
                finding_in(
                    Phase::Obfuscation,
                    Severity::Medium,
                    5,
                    "OBFUSC-X",
                    "data.py",
                )
            })
            .collect();
        // 3 counted * (2 * 5) rather than 1723 * 10.
        assert_eq!(calculate_score(&many), 30);
        assert_eq!(many.len(), 1723, "every finding is still reported");
    }

    #[test]
    fn cap_is_per_file_not_per_rule() {
        let spread: Vec<Finding> = (0..4)
            .map(|i| {
                finding_in(
                    Phase::Obfuscation,
                    Severity::Medium,
                    5,
                    "OBFUSC-X",
                    &format!("f{i}.py"),
                )
            })
            .collect();
        // Four distinct files, all under the cap: 4 * 10.
        assert_eq!(calculate_score(&spread), 40);
    }

    #[test]
    fn cap_is_per_rule_not_per_file() {
        let mixed = vec![
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-X", "f.py"),
            finding_in(Phase::Obfuscation, Severity::Medium, 5, "OBFUSC-Y", "f.py"),
        ];
        // OBFUSC-X capped at 3, OBFUSC-Y counted once: (3 + 1) * 10.
        assert_eq!(calculate_score(&mixed), 40);
    }

    #[test]
    fn capped_findings_are_still_reported_and_still_gate_critical() {
        let mut f = finding_in(
            Phase::InstallHooks,
            Severity::Critical,
            10,
            "INSTALL-003",
            "s.py",
        );
        f.evidence = Evidence::Standalone;
        let findings: Vec<Finding> = (0..10).map(|_| f.clone()).collect();
        let score = calculate_score(&findings);
        assert_eq!(score, 3 * 50);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    // -- evidence-gated Critical -------------------------------------------

    #[test]
    fn one_standalone_critical_gates_the_verdict() {
        let findings = vec![finding_in(
            Phase::InstallHooks,
            Severity::Critical,
            10,
            "INSTALL-003",
            "setup.py",
        )];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn two_corroborating_criticals_from_the_same_rule_do_not_gate() {
        // `requests` ships four test certificates: four CRED-006 hits, one
        // rule. That is one observation repeated, not two independent ones.
        let findings = vec![
            corroborating("CRED-006", "tests/certs/a.key"),
            corroborating("CRED-006", "tests/certs/b.key"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(
            determine_verdict(&findings, score),
            Verdict::MediumRisk,
            "score 20 falls through to the score thresholds"
        );
    }

    #[test]
    fn two_corroborating_criticals_from_different_rules_gate() {
        let findings = vec![
            corroborating("CRED-006", "a.key"),
            corroborating("INSTALL-001", "setup.py"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }

    #[test]
    fn corroborate_only_criticals_still_raise_the_score() {
        let one = vec![corroborating("CRED-006", "a.key")];
        // 5 * 2 = 10, which is MediumRisk on its own.
        assert_eq!(calculate_score(&one), 10);
        assert_eq!(
            determine_verdict(&one, calculate_score(&one)),
            Verdict::MediumRisk
        );

        // And a corroborating Critical pushes an otherwise-High set no higher.
        let mut mixed = vec![
            finding_in(Phase::CodePatterns, Severity::High, 5, "CODE-001", "a.js"),
            finding_in(Phase::CodePatterns, Severity::High, 5, "CODE-002", "b.js"),
        ];
        mixed.push(corroborating("CRED-006", "a.key"));
        let score = calculate_score(&mixed);
        assert_eq!(score, 15 + 15 + 10);
        assert_eq!(determine_verdict(&mixed, score), Verdict::HighRisk);
    }

    #[test]
    fn a_standalone_critical_beside_a_corroborating_one_still_gates() {
        let findings = vec![
            corroborating("CRED-006", "a.key"),
            finding_in(
                Phase::InstallHooks,
                Severity::Critical,
                10,
                "INSTALL-003",
                "s.py",
            ),
        ];
        let score = calculate_score(&findings);
        assert_eq!(determine_verdict(&findings, score), Verdict::CriticalRisk);
    }
}
