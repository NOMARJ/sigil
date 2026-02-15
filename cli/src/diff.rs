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

    let score_delta = current.score as i64 - previous.score as i64;
    let summary = format!(
        "{} new, {} resolved, {} unchanged (score: {} → {}, {}{})",
        new_findings.len(),
        resolved_findings.len(),
        unchanged_findings.len(),
        previous.score,
        current.score,
        if score_delta >= 0 { "+" } else { "" },
        score_delta,
    );

    ScanDiff {
        new_findings,
        resolved_findings,
        unchanged_findings,
        score_delta,
        previous_verdict: previous.verdict,
        current_verdict: current.verdict,
        summary,
    }
}
