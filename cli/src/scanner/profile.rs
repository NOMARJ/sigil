//! Scan profile: the letter grade, recommendation, behaviour profile and key
//! risks derived from a finished result.
//!
//! Everything here is a *presentation* of the score and verdict that
//! `scoring.rs` already computed. Nothing in this module changes a score,
//! a verdict, or an exit code: the grade is a one-character rendering of the
//! verdict thresholds documented in the README, the behaviour profile is a
//! lookup from rule id to the capability the rule evidences, and the key
//! risks are the top findings by severity. A reader who only sees the grade
//! and the profile should be able to answer "what does this thing *do*?"
//! without reading every finding — that is the whole point.

use super::{Finding, ScanResult, Severity, Verdict};

/// Everything the summary layer says about a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProfile {
    /// `A` through `F`. See [`grade`] for the mapping.
    pub grade: &'static str,
    /// The one-line recommendation for this grade.
    pub recommendation: &'static str,
    /// Sorted, de-duplicated capabilities the findings evidence, e.g.
    /// `executes_shell`, `network_outbound`, `installs_persistence`.
    pub behaviors: Vec<String>,
    /// The top findings by severity, one line each, de-duplicated by rule.
    pub key_risks: Vec<String>,
}

/// Maximum number of key risks reported.
pub const KEY_RISK_LIMIT: usize = 5;

/// Letter grade for a verdict.
///
/// The grade never disagrees with the verdict; it only splits `LOW RISK` into
/// `A` (no findings at all) and `B` (low-severity observations only), which
/// is the distinction a badge or a registry listing wants to make:
///
/// | Grade | Verdict | Meaning |
/// |---|---|---|
/// | A | LOW RISK, score 0 | no findings |
/// | B | LOW RISK, score 1–9 | low-severity observations only |
/// | C | MEDIUM RISK | suspicious patterns, review before approving |
/// | D | HIGH RISK | dangerous patterns, sandbox until reviewed |
/// | F | CRITICAL RISK | strong malicious indicators |
pub fn grade(verdict: Verdict, score: u32) -> &'static str {
    match verdict {
        Verdict::CriticalRisk => "F",
        Verdict::HighRisk => "D",
        Verdict::MediumRisk => "C",
        Verdict::LowRisk if score == 0 => "A",
        Verdict::LowRisk => "B",
    }
}

/// The recommendation that goes with a grade.
///
/// Phrased in Sigil's terms: a clean scan is a reason to *approve*, not a
/// guarantee of safety, which is the line the README and the disclaimer
/// already hold.
pub fn recommendation(grade: &str) -> &'static str {
    match grade {
        "A" => "No known malicious patterns detected — review, then approve.",
        "B" => "Low-severity observations only — review them, then approve.",
        "C" => "Suspicious patterns — review each finding before approving.",
        "D" => "Dangerous patterns — do not run outside a sandbox until reviewed.",
        _ => "Strong malicious indicators — do not install or execute this code.",
    }
}

/// The capability a rule evidences, from its id.
///
/// Rule ids are prefixed by family (`CODE-`, `NET-`, `CRED-`, ...) with a
/// handful of ids inside a family that mean something more specific than the
/// family default (`CODE-004` is deserialization, not dynamic execution).
/// Findings the corpus did not produce — OSV advisories, ledger drift — are
/// mapped by their own id shapes.
pub fn behavior_for(rule_id: &str) -> Option<&'static str> {
    // Specific ids first, so a family default cannot shadow them.
    let specific = match rule_id {
        "CODE-004" | "CODE-005" | "CODE-006" => Some("unsafe_deserialization"),
        "CODE-007" | "CODE-013" | "CODE-014" | "CODE-015" => Some("executes_shell"),
        "CODE-010" | "CODE-011" | "CODE-012" => Some("dynamic_import"),
        "NET-006" | "NET-007" => Some("exfiltration_endpoint"),
        "NET-008" | "NET-009" => Some("raw_sockets"),
        "NET-010" => Some("dns_lookup"),
        "NET-011" => Some("encodes_before_send"),
        "CRED-004" | "CRED-006" | "CRED-007" | "CRED-008" | "CRED-009" | "CRED-010"
        | "CRED-011" => Some("hardcoded_secrets"),
        "PROV-DOWNGRADE" | "PROV-IDENTITY-CHANGE" | "PROV-REPO-MISMATCH" => {
            Some("provenance_drift")
        }
        _ => None,
    };
    if specific.is_some() {
        return specific;
    }

    let families: &[(&str, &str)] = &[
        ("CODE-MCP-", "mcp_tooling"),
        ("CODE-", "dynamic_execution"),
        ("NET-SSRF-", "targets_internal_network"),
        ("NET-MCP-", "mcp_transport"),
        ("NET-", "network_outbound"),
        ("CRED-", "reads_credentials"),
        ("OBFUSC-", "uses_obfuscation"),
        ("UNICODE-", "invisible_unicode"),
        ("INSTALL-MCP-", "mcp_registration"),
        ("INSTALL-", "install_time_execution"),
        ("PROMPT-", "prompt_injection"),
        ("MANIP-", "manipulates_agent"),
        ("SKILL-", "manifest_risk"),
        ("INFER-", "inference_tampering"),
        ("RSHELL-", "reverse_shell"),
        ("SUPPLY-", "supply_chain_manipulation"),
        ("PERSIST-", "installs_persistence"),
        ("EXFIL-", "exfiltrates_data"),
        ("TYPOSQUAT-", "typosquat_dependency"),
        ("HYGIENE-", "publish_hygiene"),
        ("PROV-", "provenance_anomaly"),
        ("KNOWNGOOD-DRIFT", "modified_known_release"),
        ("RUGPULL-", "post_approval_drift"),
        ("ARCHIVE-BOMB", "decompression_bomb"),
        // OSV advisory ids.
        ("MAL-", "known_malicious_package"),
        ("GHSA-", "known_vulnerable_dependency"),
        ("CVE-", "known_vulnerable_dependency"),
        ("PYSEC-", "known_vulnerable_dependency"),
        ("RUSTSEC-", "known_vulnerable_dependency"),
        ("OSV-", "known_vulnerable_dependency"),
        ("GO-", "known_vulnerable_dependency"),
    ];
    families
        .iter()
        .find(|(prefix, _)| rule_id.starts_with(prefix))
        .map(|(_, behavior)| *behavior)
}

/// Sorted, de-duplicated behaviours across a finding set.
pub fn behaviors(findings: &[Finding]) -> Vec<String> {
    let mut out: Vec<String> = findings
        .iter()
        .filter_map(|f| behavior_for(&f.rule))
        .map(str::to_string)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The title of a finding: the rule description that prefixes every
/// corpus-produced snippet, or the whole snippet when there is no prefix
/// (an OSV advisory summary, say).
pub fn title_of(finding: &Finding) -> String {
    if let Some(meta) = crate::corpus::compiled::corpus().rule_meta(&finding.rule) {
        return meta.title.clone();
    }
    builtin_title(&finding.rule)
        .map(str::to_string)
        .unwrap_or_else(|| finding.snippet.clone())
}

/// Titles for findings produced by Rust code rather than a pack.
fn builtin_title(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "RUGPULL-001" => Some("Approved content changed after approval (rug-pull)"),
        "KNOWNGOOD-DRIFT-001" => Some("Modified copy of a published release"),
        "ARCHIVE-BOMB-001" => Some("Archive expansion exceeded the extraction cap"),
        "UNICODE-001" => Some("Bidirectional override characters in source"),
        "UNICODE-002" => Some("Zero-width characters in source"),
        "UNICODE-003" => Some("Invisible characters inside an identifier or token"),
        "PROV-DOWNGRADE" => Some("Package version downgraded against the ledger baseline"),
        "PROV-IDENTITY-CHANGE" => Some("Package publisher identity changed"),
        "PROV-REPO-MISMATCH" => Some("Package repository does not match the registry record"),
        "EXFIL-CHAIN-001" => Some("Credential read flows into an outbound network send"),
        _ => None,
    }
}

/// The top findings by severity then weight, one per rule, at most
/// [`KEY_RISK_LIMIT`].
pub fn key_risks(findings: &[Finding]) -> Vec<String> {
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.weight.cmp(&a.weight))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for f in ranked {
        if f.severity < Severity::Medium {
            break;
        }
        if seen.contains(&f.rule.as_str()) {
            continue;
        }
        seen.push(&f.rule);
        let location = match f.line {
            Some(line) => format!("{}:{}", f.file, line),
            None => f.file.clone(),
        };
        out.push(format!(
            "{}: {} ({}) — {}",
            f.severity,
            title_of(f),
            f.rule,
            location
        ));
        if out.len() >= KEY_RISK_LIMIT {
            break;
        }
    }
    out
}

/// Build the profile for a result. Suppressed findings do not contribute:
/// they are excluded from score and verdict, so they are excluded here too.
pub fn build(result: &ScanResult) -> ScanProfile {
    let grade = grade(result.verdict, result.score);
    ScanProfile {
        grade,
        recommendation: recommendation(grade),
        behaviors: behaviors(&result.findings),
        key_risks: key_risks(&result.findings),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Phase;

    fn f(rule: &str, severity: Severity, weight: u32) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: "a.py".to_string(),
            line: Some(3),
            snippet: format!("{} title: matched line", rule),
            weight,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
        }
    }

    #[test]
    fn grade_follows_the_verdict_thresholds() {
        assert_eq!(grade(Verdict::LowRisk, 0), "A");
        assert_eq!(grade(Verdict::LowRisk, 1), "B");
        assert_eq!(grade(Verdict::LowRisk, 9), "B");
        assert_eq!(grade(Verdict::MediumRisk, 10), "C");
        assert_eq!(grade(Verdict::HighRisk, 25), "D");
        assert_eq!(grade(Verdict::CriticalRisk, 5), "F");
    }

    #[test]
    fn every_grade_has_a_recommendation() {
        for g in ["A", "B", "C", "D", "F"] {
            assert!(!recommendation(g).is_empty());
        }
    }

    #[test]
    fn specific_ids_beat_family_defaults() {
        assert_eq!(behavior_for("CODE-001"), Some("dynamic_execution"));
        assert_eq!(behavior_for("CODE-004"), Some("unsafe_deserialization"));
        assert_eq!(behavior_for("CODE-014"), Some("executes_shell"));
        assert_eq!(behavior_for("CODE-MCP-001"), Some("mcp_tooling"));
        assert_eq!(behavior_for("NET-001"), Some("network_outbound"));
        assert_eq!(behavior_for("NET-007"), Some("exfiltration_endpoint"));
        assert_eq!(behavior_for("CRED-001"), Some("reads_credentials"));
        assert_eq!(behavior_for("CRED-004"), Some("hardcoded_secrets"));
        assert_eq!(
            behavior_for("GHSA-1234-abcd-ef56"),
            Some("known_vulnerable_dependency")
        );
        assert_eq!(behavior_for("MAL-2024-1"), Some("known_malicious_package"));
        assert_eq!(behavior_for("PROV-001"), Some("provenance_anomaly"));
        assert_eq!(behavior_for("PROV-DOWNGRADE"), Some("provenance_drift"));
        assert_eq!(behavior_for("TOTALLY-UNKNOWN"), None);
    }

    #[test]
    fn behaviors_are_sorted_and_unique() {
        let findings = vec![
            f("NET-001", Severity::Medium, 3),
            f("NET-004", Severity::Medium, 3),
            f("CODE-014", Severity::High, 5),
            f("CRED-004", Severity::Critical, 2),
        ];
        assert_eq!(
            behaviors(&findings),
            vec!["executes_shell", "hardcoded_secrets", "network_outbound"]
        );
    }

    #[test]
    fn key_risks_rank_by_severity_dedupe_by_rule_and_cap() {
        let mut findings = vec![
            f("NET-001", Severity::Medium, 3),
            f("NET-001", Severity::Medium, 3),
            f("CODE-001", Severity::High, 5),
            f("CRED-004", Severity::Critical, 2),
            f("PROV-001", Severity::Low, 1),
        ];
        for i in 0..10 {
            findings.push(f(&format!("X-{i}"), Severity::High, 5));
        }
        let risks = key_risks(&findings);
        assert_eq!(risks.len(), KEY_RISK_LIMIT);
        assert!(risks[0].starts_with("CRITICAL: "), "{:?}", risks);
        assert!(risks[0].contains("(CRED-004)"));
        // Low findings never make the list, and duplicates collapse.
        assert!(risks.iter().all(|r| !r.contains("PROV-001")));
        assert_eq!(risks.iter().filter(|r| r.contains("(NET-001)")).count(), 0);
    }

    #[test]
    fn title_falls_back_to_the_snippet_for_unknown_rules() {
        let fnd = f("GHSA-zzzz", Severity::High, 1);
        assert_eq!(title_of(&fnd), fnd.snippet);
        let known = f("CODE-001", Severity::High, 5);
        assert_eq!(title_of(&known), "eval() call — arbitrary code execution"); // sigil:ignore CODE-001 -- rule title in a test expectation
    }

    #[test]
    fn build_uses_only_active_findings() {
        let result = ScanResult {
            findings: vec![f("CODE-014", Severity::High, 5)],
            score: 15,
            verdict: Verdict::MediumRisk,
            files_scanned: 1,
            duration_ms: 1,
            suppressed_findings: vec![f("NET-001", Severity::Medium, 3)],
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            suppressed_by: Some("ledger".to_string()),
            scanner: None,
        };
        let p = build(&result);
        assert_eq!(p.grade, "C");
        assert_eq!(p.behaviors, vec!["executes_shell"]);
        assert_eq!(p.key_risks.len(), 1);
    }
}
