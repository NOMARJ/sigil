//! What a scan could not fully inspect.
//!
//! Sigil does not pass over content silently. A file it could not read, a
//! directory it could not list, an oversized file of which only the two ends
//! were scanned, a file whose analysis ran out of time, an archive it could
//! not open fully or at all, and a reference `--follow-refs` could not fetch
//! each leave a finding. This module names those findings, so
//! `--fail-on-incomplete` (or `fail_on_incomplete: true` in a scan policy)
//! can fail closed on them: for preemptive use, "nothing found in the part we
//! could read" is not a pass.
//!
//! Binary files are not on the list. The content phases skip them by design,
//! and the structural checks (`scanner::artifacts`, `scanner::bytecode`)
//! inspect executables, archives and bytecode instead.

use super::{Finding, Phase, Severity};

/// A file that could not be read or listed, or was read only in part.
pub const RULE_PARTIAL: &str = "PROV-INCOMPLETE-001";

/// A reference `--follow-refs` could not fetch (`transitive`).
pub const RULE_UNFETCHED_REF: &str = "REF-002";

/// Rules whose finding means part of the target was not fully inspected.
pub const INCOMPLETE_RULES: &[&str] = &[
    RULE_PARTIAL,
    super::budget::BUDGET_RULE_ID,
    super::artifacts::RULE_ARCHIVE_INCOMPLETE,
    super::artifacts::RULE_ARCHIVE_ENCRYPTED,
    RULE_UNFETCHED_REF,
];

/// Is this rule one of the coverage rules?
pub fn is_coverage_rule(rule: &str) -> bool {
    INCOMPLETE_RULES.contains(&rule)
}

/// The findings that record incomplete coverage.
pub fn incomplete(findings: &[Finding]) -> impl Iterator<Item = &Finding> {
    findings.iter().filter(|f| is_coverage_rule(&f.rule))
}

/// Was any part of the target not fully inspected?
pub fn is_incomplete(findings: &[Finding]) -> bool {
    incomplete(findings).next().is_some()
}

/// The Low observation for a file that could not be read or listed, or was
/// read only in part. Low: it does not move the verdict, because a large
/// data file is not a risk in itself. It is a fact the gate can act on.
pub fn partial_finding(rel_path: &str, what: String) -> Finding {
    Finding {
        phase: Phase::Provenance,
        rule: RULE_PARTIAL.to_string(),
        severity: Severity::Low,
        file: rel_path.to_string(),
        line: None,
        snippet: format!("Not fully inspected: {what}"),
        weight: 0,
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: None,
        evidence: crate::corpus::schema::Evidence::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str) -> Finding {
        let mut f = partial_finding("a.py", "x".into());
        f.rule = rule.to_string();
        f
    }

    #[test]
    fn coverage_rules_are_recognised() {
        for rule in INCOMPLETE_RULES {
            assert!(is_incomplete(&[finding(rule)]), "{rule}");
        }
        assert!(!is_incomplete(&[finding("CODE-001"), finding("PROV-001")]));
        assert!(!is_incomplete(&[]));
    }

    #[test]
    fn the_partial_finding_is_a_low_observation() {
        let f = partial_finding("big.js", "only the ends".into());
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.weight, 0);
        assert_eq!(f.file, "big.js");
        assert!(f.snippet.contains("only the ends"));
    }
}
