use colored::Colorize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::corpus::compiled::corpus;
use crate::quarantine::QuarantineEntry;
use crate::scanner::profile::{self, ScanProfile};
use crate::scanner::{Finding, Phase, ScanResult, Severity, Verdict};

/// Return the path to the disclaimer-shown marker file (~/.sigil/.disclaimer_shown).
fn disclaimer_marker_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join(".disclaimer_shown")
}

/// Check whether the user has suppressed disclaimers via config.
fn disclaimer_suppressed() -> bool {
    let config_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("config");
    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        return contents.lines().any(|l| l.trim() == "disclaimer=false");
    }
    false
}

// ---------------------------------------------------------------------------
// Verdict display
// ---------------------------------------------------------------------------

/// Print the final verdict with color coding and ASCII art (text format only;
/// JSON output goes through `print_scan_result_json`).
pub fn print_verdict(verdict: &Verdict, grade: &str) {
    println!();
    let line = "=".repeat(60);
    let grade_line = format!("  Grade: {}", grade);

    match verdict {
        Verdict::LowRisk => {
            println!("{}", line.green());
            println!(
                "{}",
                "  LOW RISK -- No known malicious patterns detected"
                    .green()
                    .bold()
            );
            println!("{}", line.green());
        }
        Verdict::MediumRisk => {
            println!("{}", line.yellow());
            println!(
                "{}",
                "  MEDIUM RISK -- Suspicious patterns detected"
                    .yellow()
                    .bold()
            );
            println!("{}", line.yellow());
        }
        Verdict::HighRisk => {
            println!("{}", line.red());
            println!(
                "{}",
                "  HIGH RISK -- Dangerous patterns found; review before use"
                    .red()
                    .bold()
            );
            println!("{}", line.red());
        }
        Verdict::CriticalRisk => {
            println!("{}", line.red().bold());
            println!(
                "{}",
                "  CRITICAL RISK -- Strong malicious indicators found"
                    .red()
                    .bold()
            );
            println!(
                "{}",
                "  DO NOT install or execute this code until reviewed."
                    .red()
                    .bold()
            );
            println!("{}", line.red().bold());
        }
    }
    match verdict {
        Verdict::LowRisk => println!("{}", grade_line.green()),
        Verdict::MediumRisk => println!("{}", grade_line.yellow()),
        Verdict::HighRisk | Verdict::CriticalRisk => println!("{}", grade_line.red()),
    }
    println!();

    // Honest false-positive framing on non-clean verdicts. Measured on the
    // clean control set (evaluation_results/honest_detection_eval.md), the
    // static phases over-trigger on benign idioms — network calls, base64,
    // env reads — so a flagged verdict on legitimate code is common and the
    // user's next step should be review + ledger approval, not alarm.
    if matches!(verdict, Verdict::MediumRisk | Verdict::HighRisk) {
        println!(
            "{}",
            "  These patterns also appear in legitimate code (network calls,".dimmed()
        );
        println!(
            "{}",
            "  base64, env access). If you trust this package after review:".dimmed()
        );
        println!("{}", "    sigil scan <path> -f json > scan.json".dimmed());
        println!(
            "{}",
            "    sigil explain scan.json   why a finding fired".dimmed()
        );
        println!(
            "{}",
            "    sigil approve <id>        trust it — suppresses these findings".dimmed()
        );
        println!();
    }

    // Disclaimer: long form on first run, short on subsequent (configurable)
    if !disclaimer_suppressed() {
        let marker = disclaimer_marker_path();
        if !marker.exists() {
            // First-run: show long disclaimer
            println!(
                "{}",
                "  Note: Sigil scans detect known malicious patterns through static analysis."
                    .dimmed()
            );
            println!(
                "{}",
                "  A low risk result does not guarantee the absence of all threats.".dimmed()
            );
            println!(
                "{}",
                "  Always review code before use. See sigilsec.ai/terms for full terms.".dimmed()
            );
            // Mark first-run complete
            if let Some(parent) = marker.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&marker, "");
        } else {
            // Subsequent runs: short disclaimer
            println!(
                "{}",
                "  \u{2139} Scan results are not a guarantee of safety. Review code before use."
                    .dimmed()
            );
        }
    }

    println!();
}

// ---------------------------------------------------------------------------
// Findings display
// ---------------------------------------------------------------------------

/// Print findings grouped by scan phase (text format only; JSON output goes
/// through `print_scan_result_json`).
pub fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{} No findings.", "  [*]".green());
        return;
    }

    // Group findings by phase
    let mut by_phase: HashMap<String, Vec<&Finding>> = HashMap::new();
    for finding in findings {
        by_phase
            .entry(format!("{}", finding.phase))
            .or_default()
            .push(finding);
    }

    // Print in phase order. Every Phase variant must be listed here or its
    // findings are grouped but never printed.
    let phase_order = [
        Phase::InstallHooks,
        Phase::CodePatterns,
        Phase::NetworkExfil,
        Phase::Credentials,
        Phase::Obfuscation,
        Phase::Provenance,
        Phase::PromptInjection,
        Phase::SkillSecurity,
        Phase::InferenceSecurity,
    ];

    for phase in &phase_order {
        let key = format!("{}", phase);
        if let Some(phase_findings) = by_phase.get(&key) {
            println!();
            println!(
                "  {} {} ({} finding{})",
                ">>".bold(),
                key.bold(),
                phase_findings.len(),
                if phase_findings.len() == 1 { "" } else { "s" }
            );
            println!("  {}", "-".repeat(56));

            for finding in phase_findings {
                let severity_str = format_severity(finding.severity);
                let location = match finding.line {
                    Some(line) => format!("{}:{}", finding.file, line),
                    None => finding.file.clone(),
                };

                println!(
                    "  {} [{}] {} ",
                    severity_str,
                    finding.rule.dimmed(),
                    location.bold()
                );
                println!("       {}", finding.snippet.dimmed());
                // Remediation is printed only where it changes what the reader
                // does next: the High and Critical findings that gate the
                // exit code. Every finding carries it in JSON/SARIF/HTML.
                if finding.severity >= Severity::High {
                    if let Some(fix) = corpus()
                        .rule_meta(&finding.rule)
                        .and_then(|m| m.remediation.as_deref())
                    {
                        println!("       {} {}", "fix:".cyan(), fix.dimmed());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scan profile (grade, behaviours, key risks)
// ---------------------------------------------------------------------------

/// Print the behaviour profile and key risks (text format only).
pub fn print_profile(result: &ScanResult) {
    let p = profile::build(result);
    if p.behaviors.is_empty() && p.key_risks.is_empty() {
        return;
    }
    println!();
    if !p.behaviors.is_empty() {
        println!(
            "  {} {}",
            "Behaviour profile:".bold(),
            p.behaviors.join(", ")
        );
    }
    if !p.key_risks.is_empty() {
        println!("  {}", "Key risks:".bold());
        for risk in &p.key_risks {
            println!("    {} {}", ">".red(), risk);
        }
    }
}

/// A finding as a JSON object, enriched with the rule's descriptive metadata.
///
/// `Finding` itself stays minimal — it is part of the cache and the `diff`
/// baseline contract — so the title, remediation, references and tags are
/// resolved from the active corpus at output time and added as extra keys.
/// Findings the corpus did not produce get a `title` and nothing else.
pub fn finding_json(f: &Finding) -> serde_json::Value {
    let mut value = serde_json::to_value(f).unwrap_or_else(|_| serde_json::json!({}));
    if let serde_json::Value::Object(ref mut obj) = value {
        obj.insert("title".to_string(), serde_json::json!(profile::title_of(f)));
        if let Some(meta) = corpus().rule_meta(&f.rule) {
            if let Some(fix) = &meta.remediation {
                obj.insert("remediation".to_string(), serde_json::json!(fix));
            }
            if !meta.references.is_empty() {
                obj.insert("references".to_string(), serde_json::json!(meta.references));
            }
            if !meta.tags.is_empty() {
                obj.insert("tags".to_string(), serde_json::json!(meta.tags));
            }
        }
        if let Some(behavior) = profile::behavior_for(&f.rule) {
            obj.insert("behavior".to_string(), serde_json::json!(behavior));
        }
    }
    value
}

/// The `profile` object of the JSON document.
fn profile_json(p: &ScanProfile) -> serde_json::Value {
    serde_json::json!({
        "behaviors": p.behaviors,
        "key_risks": p.key_risks,
    })
}

/// Format a severity label with appropriate color.
fn format_severity(severity: Severity) -> String {
    match severity {
        Severity::Low => format!("{}", "LOW     ".dimmed()),
        Severity::Medium => format!("{}", "MEDIUM  ".yellow()),
        Severity::High => format!("{}", "HIGH    ".red()),
        Severity::Critical => format!("{}", "CRITICAL".red().bold()),
    }
}

// ---------------------------------------------------------------------------
// Scan summary
// ---------------------------------------------------------------------------

/// Print the complete scan result as a single JSON document on stdout.
///
/// This is the entire `--format json` contract for scan commands: one
/// parseable object holding the summary scalars and the findings array.
/// The "summary" object must hold scalars only: scripts/run_eval.py and
/// `sigil explain` locate the findings array by the first `[` in stdout,
/// so no other array may precede "findings" in the serialized output
/// (serde_json orders keys alphabetically).
pub fn print_scan_result_json(result: &ScanResult) {
    let doc = scan_result_document(result);
    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
}

/// The `--format json` document for a scan result. See
/// [`print_scan_result_json`] for the ordering contract it must keep.
pub fn scan_result_document(result: &ScanResult) -> serde_json::Value {
    let p = profile::build(result);
    let findings: Vec<serde_json::Value> = result.findings.iter().map(finding_json).collect();
    let mut doc = serde_json::json!({
        "findings": findings,
        // "profile" sorts after "findings" and before "scanner"/"summary",
        // so the findings array is still the first `[` on stdout.
        "profile": profile_json(&p),
        "summary": {
            "files_scanned": result.files_scanned,
            "findings_count": result.findings.len(),
            "suppressed_count": result.suppressed_findings.len(),
            "inline_suppressed_count": result.inline_suppressed.len(),
            "score": result.score,
            "verdict": format!("{}", result.verdict),
            "grade": p.grade,
            "recommendation": p.recommendation,
            "duration_ms": result.duration_ms,
            "platform": result.platform,
        },
    });
    if let Some(by) = &result.suppressed_by {
        let suppressed: Vec<serde_json::Value> = result
            .suppressed_findings
            .iter()
            .map(finding_json)
            .collect();
        doc["suppressed_by"] = serde_json::json!(by);
        doc["suppressed_findings"] = serde_json::json!(suppressed);
    }
    if !result.inline_suppressed.is_empty() {
        // "inline_suppressed" also sorts after "findings".
        let silenced: Vec<serde_json::Value> = result
            .inline_suppressed
            .iter()
            .zip(result.inline_suppressions.iter())
            .map(|(f, note)| {
                let mut v = finding_json(f);
                v["suppressed_by"] = serde_json::json!(format!("inline: {note}"));
                v
            })
            .collect();
        doc["inline_suppressed"] = serde_json::json!(silenced);
    }
    // Corpus provenance, so `sigil diff` can separate a code change from a
    // rules change. The key must sort *after* "findings": serde_json orders
    // keys alphabetically and consumers locate the findings array by the
    // first `[` in stdout, so a key like "engine" or "corpus" would break
    // them. "scanner" sorts after "findings" and before "summary".
    if let Some(info) = &result.scanner {
        doc["scanner"] = serde_json::json!(info);
    }
    doc
}

/// Print a summary with scan statistics (text format only; JSON output goes
/// through `print_scan_result_json`).
pub fn print_scan_summary(result: &ScanResult) {
    println!();
    println!(
        "  {} Scan complete in {}ms",
        "sigil".bold().cyan(),
        result.duration_ms
    );
    println!("  {} files scanned", result.files_scanned);
    if !result.platform.is_empty() {
        println!("  Platform: {}", result.platform);
    }
    println!("  {} findings", result.findings.len());
    println!("  Risk score: {}", format_score(result.score));
    println!(
        "  Grade: {}",
        profile::grade(result.verdict, result.score).bold()
    );

    // Count by severity
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    for f in &result.findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }

    if result.findings.is_empty() {
        return;
    }

    println!(
        "  Breakdown: {} critical, {} high, {} medium, {} low",
        if critical > 0 {
            format!("{}", critical).red().bold().to_string()
        } else {
            "0".to_string()
        },
        if high > 0 {
            format!("{}", high).red().to_string()
        } else {
            "0".to_string()
        },
        if medium > 0 {
            format!("{}", medium).yellow().to_string()
        } else {
            "0".to_string()
        },
        low
    );
}

/// Format the numeric score with color (thresholds: 0/10/25/50).
fn format_score(score: u32) -> String {
    if score == 0 {
        format!("{}", "0".green().bold())
    } else if score < 10 {
        format!("{}", score.to_string().cyan().bold())
    } else if score < 25 {
        format!("{}", score.to_string().yellow().bold())
    } else {
        format!("{}", score.to_string().red().bold())
    }
}

// ---------------------------------------------------------------------------
// Quarantine list display
// ---------------------------------------------------------------------------

/// Print a list of quarantine entries.
pub fn print_quarantine_list(entries: &[QuarantineEntry], detailed: bool, format: &str) {
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(entries).unwrap_or_default()
        );
        return;
    }

    println!();
    println!(
        "  {} Quarantined items ({})",
        "sigil".bold().cyan(),
        entries.len()
    );
    println!("  {}", "-".repeat(60));

    for entry in entries {
        let status_str = match &entry.status {
            crate::quarantine::QuarantineStatus::Pending => "PENDING".yellow().to_string(),
            crate::quarantine::QuarantineStatus::Approved => "APPROVED".green().to_string(),
            crate::quarantine::QuarantineStatus::Rejected => "REJECTED".red().to_string(),
        };

        println!(
            "  {} [{}] {} ({})",
            status_str,
            entry.id.dimmed(),
            entry.source.bold(),
            entry.source_type
        );

        if detailed {
            println!("       Path:    {}", entry.path.display());
            println!(
                "       Created: {}",
                entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "       Updated: {}",
                entry.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if let Some(ref reason) = entry.reason {
                println!("       Reason:  {}", reason);
            }
            if let Some(score) = entry.scan_score {
                println!("       Score:   {}", format_score(score));
            }
            println!();
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF output (Static Analysis Results Interchange Format 2.1.0)
// ---------------------------------------------------------------------------

/// Print scan results in SARIF 2.1.0 JSON format.
///
/// SARIF is the OASIS standard for static analysis tool output. This format
/// is consumed by GitHub Code Scanning, VS Code SARIF Viewer, and other
/// security tooling.
pub fn print_scan_sarif(result: &ScanResult, target: &str) {
    // Rule descriptors cover suppressed findings too: a result that names a
    // rule the driver never declared is invalid SARIF.
    let all_findings: Vec<Finding> = result
        .findings
        .iter()
        .chain(result.inline_suppressed.iter())
        .cloned()
        .collect();
    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| sarif_result(f, None))
        .chain(
            result
                .inline_suppressed
                .iter()
                .zip(result.inline_suppressions.iter())
                .map(|(f, note)| sarif_result(f, Some(note.as_str()))),
        )
        .collect();
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sigil",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/nomark/sigil",
                    "rules": generate_rules(&all_findings)
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "riskScore": result.score,
                    "verdict": format!("{:?}", result.verdict),
                    "grade": profile::grade(result.verdict, result.score),
                    "behaviors": profile::behaviors(&result.findings),
                    "filesScanned": result.files_scanned,
                    "durationMs": result.duration_ms
                }
            }],
            "artifacts": [{
                "location": {
                    "uri": target,
                    "uriBaseId": "%SRCROOT%"
                }
            }]
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

/// One SARIF result.
///
/// A finding silenced by an inline marker is still reported, with a
/// `suppressions` entry of kind `inSource` carrying the reviewer's reason —
/// that is how GitHub Code Scanning learns an alert was dismissed in the
/// code rather than silently missing from the run.
fn sarif_result(f: &Finding, suppressed_note: Option<&str>) -> serde_json::Value {
    let mut r = serde_json::json!({
        "ruleId": f.rule,
        "level": severity_to_sarif_level(f.severity),
        "message": {
            "text": f.snippet.clone()
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.file.clone(),
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": f.line.unwrap_or(1),
                    "startColumn": 1
                }
            }
        }],
        // GitHub Code Scanning tracks an alert across commits by
        // its partialFingerprints. Without them it re-raises every
        // alert whenever a line number drifts, which is how a
        // scanner earns a reputation for noise.
        "partialFingerprints": {
            "sigilFingerprint/v1": f.fingerprint.clone()
        },
        "properties": {
            "phase": format!("{:?}", f.phase),
            "weight": f.weight,
            "locator": f.locator.clone(),
            "behavior": profile::behavior_for(&f.rule)
        }
    });
    if let Some(note) = suppressed_note {
        r["suppressions"] = serde_json::json!([{
            "kind": "inSource",
            "justification": note
        }]);
    }
    r
}

/// Map a Severity to the SARIF level string.
fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High => "error",
        Severity::Critical => "error",
    }
}

/// Generate SARIF rule descriptors from findings, deduplicating by rule ID.
fn generate_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut seen = HashSet::new();
    findings
        .iter()
        .filter_map(|f| {
            if seen.insert(f.rule.clone()) {
                let mut rule = serde_json::json!({
                    "id": f.rule,
                    "shortDescription": {
                        "text": profile::title_of(f).chars().take(100).collect::<String>()
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(f.severity)
                    },
                    "properties": {
                        "phase": format!("{:?}", f.phase)
                    }
                });
                if let Some(meta) = corpus().rule_meta(&f.rule) {
                    rule["fullDescription"] = serde_json::json!({ "text": meta.title });
                    if let Some(fix) = &meta.remediation {
                        // GitHub Code Scanning renders `help` on the alert page;
                        // this is where a reviewer learns what to do about it.
                        rule["help"] = serde_json::json!({ "text": fix, "markdown": fix });
                    }
                    if !meta.tags.is_empty() {
                        rule["properties"]["tags"] = serde_json::json!(meta.tags);
                    }
                    if !meta.references.is_empty() {
                        rule["properties"]["references"] = serde_json::json!(meta.references);
                    }
                }
                Some(rule)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod json_contract_tests {
    use super::*;
    use crate::scanner::{Phase, ScannerInfo};

    fn finding(rule: &str, severity: Severity) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: "a.py".to_string(),
            line: Some(2),
            snippet: "x: y".to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: "abc".to_string(),
            locator: None,
            evidence: Default::default(),
        }
    }

    fn result() -> ScanResult {
        ScanResult {
            findings: vec![finding("CODE-001", Severity::High)],
            score: 15,
            verdict: Verdict::MediumRisk,
            files_scanned: 1,
            duration_ms: 3,
            suppressed_findings: vec![finding("NET-001", Severity::Medium)],
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            suppressed_by: Some("ledger:x@1#abc approved 2026-01-01".to_string()),
            scanner: Some(ScannerInfo {
                engine_version: "0.0.0".to_string(),
                corpus_digest: "sha256:0".to_string(),
                corpus_rule_count: 1,
                rule_ids: vec!["CODE-001".to_string()],
            }),
            platform: String::new(),
        }
    }

    /// `scripts/run_eval.py` and `sigil explain` locate the findings array by
    /// the first `[` on stdout, and `sigil diff` reads `summary` scalars. The
    /// profile and the enriched finding keys must not move either.
    #[test]
    fn findings_array_is_still_the_first_array_in_the_document() {
        let text = serde_json::to_string(&scan_result_document(&result())).unwrap();
        let first_bracket = text.find('[').unwrap();
        let findings_key = text.find("\"findings\":").unwrap();
        assert!(
            findings_key < first_bracket,
            "an array-valued key sorts before \"findings\": {text}"
        );
        assert_eq!(
            &text[findings_key + "\"findings\":".len()..first_bracket],
            ""
        );
    }

    #[test]
    fn summary_holds_scalars_only_and_carries_the_grade() {
        let doc = scan_result_document(&result());
        let summary = doc["summary"].as_object().unwrap();
        for (k, v) in summary {
            assert!(
                !v.is_array() && !v.is_object(),
                "summary.{k} is not a scalar"
            );
        }
        assert_eq!(summary["grade"], "C");
        assert_eq!(summary["verdict"], "MEDIUM RISK");
        assert!(summary["recommendation"]
            .as_str()
            .unwrap()
            .contains("review"));
    }

    #[test]
    fn findings_are_enriched_with_title_and_behavior() {
        let doc = scan_result_document(&result());
        let f = &doc["findings"][0];
        assert_eq!(f["rule"], "CODE-001");
        assert_eq!(f["title"], "eval() call — arbitrary code execution"); // sigil:ignore CODE-001 -- rule title in a test expectation
        assert_eq!(f["behavior"], "dynamic_execution");
        // The original fields are untouched.
        assert_eq!(f["snippet"], "x: y");
        assert_eq!(f["fingerprint"], "abc");
        assert_eq!(doc["profile"]["behaviors"][0], "dynamic_execution");
        assert_eq!(doc["profile"]["key_risks"].as_array().unwrap().len(), 1);
        assert_eq!(
            doc["suppressed_findings"][0]["behavior"],
            "network_outbound"
        );
    }

    /// `evidence` is additive: absent for the default, present only when a
    /// rule declared `corroborate`, and never displacing an existing key.
    #[test]
    fn evidence_key_is_additive_and_omitted_by_default() {
        let doc = scan_result_document(&result());
        let f = &doc["findings"][0];
        assert!(
            f.get("evidence").is_none(),
            "a standalone finding must serialize exactly as before: {f}"
        );

        let mut with_evidence = result();
        with_evidence.findings[0].evidence = crate::scanner::Evidence::Corroborate;
        let doc = scan_result_document(&with_evidence);
        let f = &doc["findings"][0];
        assert_eq!(f["evidence"], "corroborate");
        // Every pre-existing key is still there and unchanged.
        for key in [
            "rule",
            "severity",
            "file",
            "line",
            "snippet",
            "weight",
            "fingerprint",
            "phase",
        ] {
            assert!(f.get(key).is_some(), "{key} disappeared: {f}");
        }
    }

    /// A cached or baseline document written before the field existed must
    /// still load, and mean `standalone`.
    #[test]
    fn a_finding_without_the_evidence_key_deserializes() {
        let text = serde_json::to_string(&scan_result_document(&result())).unwrap();
        assert!(!text.contains("evidence"));
        let parsed = crate::diff::parse_baseline(&text).expect("parses");
        assert!(parsed.findings[0].evidence.is_standalone());
    }

    /// The enriched document must still deserialize as a `ScanResult` so
    /// `sigil diff --baseline` keeps accepting the scanner's own output.
    #[test]
    fn document_round_trips_through_scan_result() {
        let text = serde_json::to_string(&scan_result_document(&result())).unwrap();
        let parsed = crate::diff::parse_baseline(&text).expect("diff can parse own output");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.score, 15);
    }
}
