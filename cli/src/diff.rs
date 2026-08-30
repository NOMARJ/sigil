//! Scan result diffing — compare two scan results to identify new and resolved findings.

use crate::scanner::{Finding, ScanResult, Verdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanDiff {
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub unchanged_findings: Vec<Finding>,
    pub score_delta: i64,
    pub previous_verdict: Verdict,
    pub current_verdict: Verdict,
    pub summary: String,
    /// New findings attributable to rules that did not exist when the
    /// baseline was taken.
    ///
    /// These are a subset of `new_findings`. They are *not* evidence that the
    /// scanned code got worse — the corpus got bigger. Reporting them as code
    /// regressions is what makes a diff gate untrustworthy, so they are
    /// separated out. Empty when the baseline predates corpus provenance or
    /// when the corpus is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_from_new_rules: Vec<Finding>,
    /// Set when the two scans ran different detection corpora.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_changed: Option<String>,
}

/// Compare two scan results and produce a diff.
pub fn diff_scans(previous: &ScanResult, current: &ScanResult) -> ScanDiff {
    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();
    let mut unchanged_findings = Vec::new();

    // Match findings by (rule, file, line) tuple
    for finding in &current.findings {
        let exists_in_previous = previous
            .findings
            .iter()
            .any(|f| f.rule == finding.rule && f.file == finding.file && f.line == finding.line);
        if exists_in_previous {
            unchanged_findings.push(finding.clone());
        } else {
            new_findings.push(finding.clone());
        }
    }

    for finding in &previous.findings {
        let exists_in_current = current
            .findings
            .iter()
            .any(|f| f.rule == finding.rule && f.file == finding.file && f.line == finding.line);
        if !exists_in_current {
            resolved_findings.push(finding.clone());
        }
    }

    // Attribute new findings to rules that did not exist in the baseline.
    //
    // Only possible when the baseline recorded its rule set. An older
    // baseline leaves this empty and the diff reads exactly as it did before.
    let (corpus_changed, new_from_new_rules) =
        match (previous.scanner.as_ref(), current.scanner.as_ref()) {
            (Some(prev), Some(cur)) if prev.corpus_digest != cur.corpus_digest => {
                let baseline_rules: std::collections::HashSet<&str> =
                    prev.rule_ids.iter().map(|s| s.as_str()).collect();
                // An empty baseline rule list means "unknown", not "no rules";
                // attributing every finding to a new rule then would be wrong.
                let attributable = !baseline_rules.is_empty();
                let from_new_rules: Vec<Finding> = if attributable {
                    new_findings
                        .iter()
                        .filter(|f| !baseline_rules.contains(f.rule.as_str()))
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                let note = format!(
                    "corpus changed ({} → {} rules; {} → {})",
                    prev.corpus_rule_count,
                    cur.corpus_rule_count,
                    short_digest(&prev.corpus_digest),
                    short_digest(&cur.corpus_digest),
                );
                (Some(note), from_new_rules)
            }
            _ => (None, Vec::new()),
        };

    let score_delta = current.score as i64 - previous.score as i64;
    let mut summary = format!(
        "{} new, {} resolved, {} unchanged (score: {} → {}, {}{})",
        new_findings.len(),
        resolved_findings.len(),
        unchanged_findings.len(),
        previous.score,
        current.score,
        if score_delta >= 0 { "+" } else { "" },
        score_delta,
    );
    if !new_from_new_rules.is_empty() {
        summary.push_str(&format!(
            " — {} of the new findings come from rules added since the baseline, not from code changes",
            new_from_new_rules.len()
        ));
    } else if corpus_changed.is_some() {
        summary.push_str(" — note: the detection corpus changed since the baseline");
    }

    ScanDiff {
        new_findings,
        resolved_findings,
        unchanged_findings,
        score_delta,
        previous_verdict: previous.verdict,
        current_verdict: current.verdict,
        summary,
        new_from_new_rules,
        corpus_changed,
    }
}

/// Shorten a `sha256:…` digest for display.
fn short_digest(d: &str) -> String {
    let hex = d.strip_prefix("sha256:").unwrap_or(d);
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Phase, ScannerInfo, Severity};

    fn finding(rule: &str, file: &str, line: usize) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity: Severity::High,
            file: file.to_string(),
            line: Some(line),
            snippet: format!("{rule} hit"),
            weight: 5,
            kev: false,
            epss: 0.0,
        }
    }

    fn result(findings: Vec<Finding>, scanner: Option<ScannerInfo>) -> ScanResult {
        let score = crate::scanner::scoring::calculate_score(&findings);
        let verdict = crate::scanner::scoring::determine_verdict(&findings, score);
        ScanResult {
            findings,
            score,
            verdict,
            files_scanned: 1,
            duration_ms: 1,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
            scanner,
        }
    }

    fn info(digest: &str, rules: &[&str]) -> ScannerInfo {
        ScannerInfo {
            engine_version: "1.3.6".to_string(),
            corpus_digest: format!("sha256:{digest}"),
            corpus_rule_count: rules.len(),
            rule_ids: rules.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The core of §6: when the corpus grows, a finding from a rule that did
    /// not exist in the baseline is not a code regression.
    #[test]
    fn new_findings_from_added_rules_are_separated_out() {
        let prev = result(vec![], Some(info("aaa", &["CODE-001"])));
        let cur = result(
            vec![
                finding("CODE-001", "a.js", 1),
                finding("CODE-999", "a.js", 2),
            ],
            Some(info("bbb", &["CODE-001", "CODE-999"])),
        );

        let d = diff_scans(&prev, &cur);
        assert_eq!(d.new_findings.len(), 2);
        assert_eq!(d.new_from_new_rules.len(), 1);
        assert_eq!(d.new_from_new_rules[0].rule, "CODE-999");
        assert!(d.corpus_changed.is_some());
        assert!(
            d.summary.contains("not from code changes"),
            "summary should say why: {}",
            d.summary
        );
    }

    /// Same corpus on both sides: every new finding really is a code change.
    #[test]
    fn unchanged_corpus_attributes_nothing_to_rules() {
        let prev = result(vec![], Some(info("aaa", &["CODE-001"])));
        let cur = result(
            vec![finding("CODE-001", "a.js", 1)],
            Some(info("aaa", &["CODE-001"])),
        );
        let d = diff_scans(&prev, &cur);
        assert_eq!(d.new_findings.len(), 1);
        assert!(d.new_from_new_rules.is_empty());
        assert!(d.corpus_changed.is_none());
    }

    /// A baseline written before corpus provenance existed must still diff,
    /// and must not claim anything it cannot know.
    #[test]
    fn baseline_without_provenance_degrades_gracefully() {
        let prev = result(vec![], None);
        let cur = result(
            vec![finding("CODE-999", "a.js", 1)],
            Some(info("bbb", &["CODE-999"])),
        );
        let d = diff_scans(&prev, &cur);
        assert_eq!(d.new_findings.len(), 1);
        assert!(d.new_from_new_rules.is_empty());
        assert!(d.corpus_changed.is_none());
    }

    /// An empty baseline rule list means "unknown", not "no rules existed" —
    /// attributing every finding to a new rule would be wrong.
    #[test]
    fn empty_baseline_rule_list_is_treated_as_unknown() {
        let prev = result(vec![], Some(info("aaa", &[])));
        let cur = result(
            vec![finding("CODE-001", "a.js", 1)],
            Some(info("bbb", &["CODE-001"])),
        );
        let d = diff_scans(&prev, &cur);
        assert!(d.corpus_changed.is_some());
        assert!(
            d.new_from_new_rules.is_empty(),
            "must not attribute findings when the baseline rule set is unknown"
        );
    }

    #[test]
    fn resolved_and_unchanged_still_work() {
        let prev = result(
            vec![
                finding("CODE-001", "a.js", 1),
                finding("CODE-002", "b.js", 3),
            ],
            Some(info("aaa", &["CODE-001", "CODE-002"])),
        );
        let cur = result(
            vec![finding("CODE-001", "a.js", 1)],
            Some(info("aaa", &["CODE-001", "CODE-002"])),
        );
        let d = diff_scans(&prev, &cur);
        assert_eq!(d.unchanged_findings.len(), 1);
        assert_eq!(d.resolved_findings.len(), 1);
        assert_eq!(d.resolved_findings[0].rule, "CODE-002");
        assert!(d.new_findings.is_empty());
    }
}
