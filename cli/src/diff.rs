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

    // Match findings by content-anchored fingerprint, falling back to the
    // old (rule, file, line) tuple when either side predates fingerprints.
    //
    // The line number is deliberately not part of the fingerprint: keying on
    // it made every finding below an inserted line report as new *and*
    // resolved in the same diff, for a change that touched neither.
    for finding in &current.findings {
        if same_finding_in(&previous.findings, finding) {
            unchanged_findings.push(finding.clone());
        } else {
            new_findings.push(finding.clone());
        }
    }

    for finding in &previous.findings {
        if !same_finding_in(&current.findings, finding) {
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

/// Parse a baseline scan report.
///
/// Accepts both shapes that exist in the wild:
///
/// - a serialized [`ScanResult`], with `score` and `verdict` at the top level;
/// - the `--format json` document, where those live under `summary` and
///   `verdict` is the human string (`"HIGH RISK"`).
///
/// The second is what `sigil scan -f json > baseline.json` actually writes,
/// and it did not previously deserialize — `sigil diff --baseline` rejected
/// the scanner's own output with "missing field `score`". Fixing that is
/// what makes the fingerprint and corpus-provenance work reachable from the
/// command line.
pub fn parse_baseline(data: &str) -> Result<ScanResult, String> {
    if let Ok(result) = serde_json::from_str::<ScanResult>(data) {
        return Ok(result);
    }

    let doc: serde_json::Value =
        serde_json::from_str(data).map_err(|e| format!("not valid JSON: {e}"))?;

    let findings: Vec<Finding> = serde_json::from_value(
        doc.get("findings")
            .cloned()
            .ok_or_else(|| "no `findings` array in baseline".to_string())?,
    )
    .map_err(|e| format!("could not read `findings`: {e}"))?;

    let summary = doc.get("summary");
    let score = summary
        .and_then(|s| s.get("score"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        // A baseline with findings but no recorded score can still be
        // diffed; recomputing is better than refusing.
        .unwrap_or_else(|| crate::scanner::scoring::calculate_score(&findings));

    let verdict = summary
        .and_then(|s| s.get("verdict"))
        .and_then(|v| v.as_str())
        .and_then(verdict_from_display)
        .unwrap_or_else(|| crate::scanner::scoring::determine_verdict(&findings, score));

    let scanner = doc
        .get("scanner")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    Ok(ScanResult {
        findings,
        score,
        verdict,
        files_scanned: summary
            .and_then(|s| s.get("files_scanned"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
        duration_ms: summary
            .and_then(|s| s.get("duration_ms"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        suppressed_findings: doc
            .get("suppressed_findings")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
        inline_suppressed: Vec::new(),
        inline_suppressions: Vec::new(),
        suppressed_by: doc
            .get("suppressed_by")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        scanner,
    })
}

/// Invert `Verdict`'s `Display`.
fn verdict_from_display(s: &str) -> Option<Verdict> {
    match s.trim().to_ascii_uppercase().as_str() {
        "LOW RISK" => Some(Verdict::LowRisk),
        "MEDIUM RISK" => Some(Verdict::MediumRisk),
        "HIGH RISK" => Some(Verdict::HighRisk),
        "CRITICAL RISK" => Some(Verdict::CriticalRisk),
        _ => None,
    }
}

/// Is `needle` present in `haystack`?
///
/// Uses the content-anchored fingerprint when both findings carry one, so a
/// finding that merely moved to a different line stays the same finding.
/// Falls back to `(rule, file, line)` when either side has no fingerprint —
/// a baseline captured before fingerprints existed still diffs, exactly as
/// it used to.
fn same_finding_in(haystack: &[Finding], needle: &Finding) -> bool {
    haystack.iter().any(|f| {
        if !f.fingerprint.is_empty() && !needle.fingerprint.is_empty() {
            f.fingerprint == needle.fingerprint
        } else {
            f.rule == needle.rule && f.file == needle.file && f.line == needle.line
        }
    })
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
            fingerprint: String::new(),
            locator: None,
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
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
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

    /// `sigil scan -f json > baseline.json` writes score and verdict under
    /// "summary", not at the top level. That document previously failed to
    /// deserialize, so `sigil diff --baseline` rejected the scanner's own
    /// output with "missing field `score`".
    #[test]
    fn parses_the_format_json_document_shape() {
        let doc = r#"{
            "findings": [
                {"phase":"CodePatterns","rule":"CODE-001","severity":"High",
                 "file":"a.js","line":3,"snippet":"sample rule hit: token-a",
                 "weight":5,"fingerprint":"abc123"}
            ],
            "scanner": {"engine_version":"1.3.6","corpus_digest":"sha256:aa",
                        "corpus_rule_count":1,"rule_ids":["CODE-001"]},
            "summary": {"files_scanned":1,"findings_count":1,
                        "suppressed_count":0,"score":15,
                        "verdict":"MEDIUM RISK","duration_ms":7}
        }"#;
        let r = parse_baseline(doc).expect("should parse the --format json shape");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.score, 15);
        assert_eq!(r.verdict, Verdict::MediumRisk);
        assert_eq!(r.files_scanned, 1);
        assert_eq!(r.scanner.expect("scanner block").corpus_digest, "sha256:aa");
    }

    /// The serialized ScanResult shape must keep working.
    #[test]
    fn parses_the_scan_result_shape() {
        let prev = result(
            vec![finding("CODE-001", "a.js", 1)],
            Some(info("aaa", &["CODE-001"])),
        );
        let json = serde_json::to_string(&prev).expect("serialize");
        let r = parse_baseline(&json).expect("should parse a ScanResult");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.score, prev.score);
        assert_eq!(r.verdict, prev.verdict);
    }

    #[test]
    fn rejects_junk_with_a_useful_message() {
        assert!(parse_baseline("not json").is_err());
        let err = parse_baseline("{}").unwrap_err();
        assert!(err.contains("findings"), "unhelpful error: {err}");
    }

    /// Line drift must not churn the diff. This is the end-to-end form of the
    /// fingerprint property.
    #[test]
    fn line_drift_alone_produces_no_diff() {
        let mut before = vec![finding("CODE-001", "a.js", 3)];
        let mut after = vec![finding("CODE-001", "a.js", 28)];
        crate::scanner::assign_fingerprints(&mut before);
        crate::scanner::assign_fingerprints(&mut after);

        let d = diff_scans(
            &result(before, Some(info("aaa", &["CODE-001"]))),
            &result(after, Some(info("aaa", &["CODE-001"]))),
        );
        assert!(d.new_findings.is_empty(), "{:?}", d.new_findings);
        assert!(d.resolved_findings.is_empty(), "{:?}", d.resolved_findings);
        assert_eq!(d.unchanged_findings.len(), 1);
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
