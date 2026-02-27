use colored::Colorize;
use std::collections::{HashMap, HashSet};

use crate::quarantine::QuarantineEntry;
use crate::scanner::{Finding, Phase, ScanResult, Severity, Verdict};

// ---------------------------------------------------------------------------
// Verdict display
// ---------------------------------------------------------------------------

/// Print the final verdict with color coding and ASCII art.
pub fn print_verdict(verdict: &Verdict, format: &str) {
    if format == "json" {
        println!(
            "{}",
            serde_json::json!({ "verdict": format!("{}", verdict) })
        );
        return;
    }

    println!();
    let line = "=".repeat(60);

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
                "  HIGH RISK -- Likely malicious patterns found"
                    .red()
                    .bold()
            );
            println!("{}", line.red());
        }
        Verdict::CriticalRisk => {
            println!("{}", line.red().bold());
            println!(
                "{}",
                "  CRITICAL RISK -- Almost certainly malicious!"
                    .red()
                    .bold()
            );
            println!("{}", "  DO NOT install or execute this code.".red().bold());
            println!("{}", line.red().bold());
        }
    }
    println!();
}

// ---------------------------------------------------------------------------
// Findings display
// ---------------------------------------------------------------------------

/// Print findings grouped by scan phase.
pub fn print_findings(findings: &[Finding], format: &str) {
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(findings).unwrap_or_default()
        );
        return;
    }

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

    // Print in phase order
    let phase_order = [
        Phase::InstallHooks,
        Phase::CodePatterns,
        Phase::NetworkExfil,
        Phase::Credentials,
        Phase::Obfuscation,
        Phase::Provenance,
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
            }
        }
    }
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

/// Print a summary with scan statistics.
pub fn print_scan_summary(result: &ScanResult, format: &str) {
    if format == "json" {
        let summary = serde_json::json!({
            "files_scanned": result.files_scanned,
            "findings_count": result.findings.len(),
            "score": result.score,
            "verdict": format!("{}", result.verdict),
            "duration_ms": result.duration_ms,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );
        return;
    }

    println!();
    println!(
        "  {} Scan complete in {}ms",
        "sigil".bold().cyan(),
        result.duration_ms
    );
    println!("  {} files scanned", result.files_scanned);
    println!("  {} findings", result.findings.len());
    println!("  Risk score: {}", format_score(result.score));

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
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sigil",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/nomark/sigil",
                    "rules": generate_rules(&result.findings)
                }
            },
            "results": result.findings.iter().map(|f| {
                serde_json::json!({
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
                    "properties": {
                        "phase": format!("{:?}", f.phase),
                        "weight": f.weight
                    }
                })
            }).collect::<Vec<_>>(),
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "riskScore": result.score,
                    "verdict": format!("{:?}", result.verdict),
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
                Some(serde_json::json!({
                    "id": f.rule,
                    "shortDescription": {
                        "text": f.snippet.chars().take(100).collect::<String>()
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(f.severity)
                    },
                    "properties": {
                        "phase": format!("{:?}", f.phase)
                    }
                }))
            } else {
                None
            }
        })
        .collect()
}
