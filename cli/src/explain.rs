//! `sigil explain` — AI adjudication of a scan finding (F-009 US-111).
//!
//! Capability-minimal by design (D6): the CLI never calls an LLM itself. It
//! submits the scan to the Sigil API with the user's token and requests
//! adjudication of one finding; the server owns model access and metering.

use colored::Colorize;
use serde_json::{json, Value};
use std::path::Path;

/// Extract the findings array from a `sigil scan -f json` output file.
///
/// That output is a concatenation of a banner line, a summary object, the
/// findings array, and a verdict object — so this scans for the first JSON
/// array rather than parsing the file as a single document.
pub fn parse_scan_findings(content: &str) -> Result<Vec<Value>, String> {
    let start = content
        .find('[')
        .ok_or_else(|| "no findings array in scan file (is this `sigil scan -f json` output?)".to_string())?;
    let mut de = serde_json::Deserializer::from_str(&content[start..]).into_iter::<Value>();
    match de.next() {
        Some(Ok(Value::Array(findings))) => Ok(findings),
        Some(Ok(_)) => Err("expected a findings array in scan file".to_string()),
        Some(Err(e)) => Err(format!("failed to parse findings array: {}", e)),
        None => Err("empty findings array region in scan file".to_string()),
    }
}

/// Map a CLI phase name (serde CamelCase) to the API's snake_case value.
fn normalize_phase(phase: &str) -> String {
    match phase {
        "InstallHooks" => "install_hooks".into(),
        "CodePatterns" => "code_patterns".into(),
        "NetworkExfil" => "network_exfil".into(),
        "Credentials" => "credentials".into(),
        "Obfuscation" => "obfuscation".into(),
        "Provenance" => "provenance".into(),
        "PromptInjection" => "prompt_injection".into(),
        "SkillSecurity" => "skill_security".into(),
        "LlmAnalysis" => "llm_analysis".into(),
        other => other.to_lowercase(),
    }
}

/// Normalize one CLI finding to the API's Finding schema (phase snake_case,
/// severity uppercase). Unknown keys pass through untouched.
pub fn normalize_finding(finding: &Value) -> Value {
    let mut out = finding.clone();
    if let Some(obj) = out.as_object_mut() {
        if let Some(phase) = obj.get("phase").and_then(|p| p.as_str()) {
            let normalized = normalize_phase(phase);
            obj.insert("phase".into(), Value::String(normalized));
        }
        if let Some(sev) = obj.get("severity").and_then(|s| s.as_str()) {
            obj.insert("severity".into(), Value::String(sev.to_uppercase()));
        }
    }
    out
}

/// Render a successful adjudication verdict.
fn render_verdict(adjudication: &Value) {
    let classification = adjudication
        .get("classification")
        .and_then(|c| c.as_str())
        .unwrap_or("unknown");
    let confidence = adjudication
        .get("confidence")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0);
    let rationale = adjudication
        .get("rationale")
        .and_then(|r| r.as_str())
        .unwrap_or("");
    let model = adjudication
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");

    let label = match classification {
        "benign_dual_use" => classification.bold().green(),
        "suspicious" => classification.bold().yellow(),
        "malicious" => classification.bold().red(),
        other => other.bold(),
    };
    println!("{} verdict: {}", "sigil:".bold().cyan(), label);
    println!("  confidence: {:.0}%", confidence * 100.0);
    println!("  rationale: {}", rationale);
    println!("  model: {}", model);
}

/// Render the 402 allowance-exhausted denial as a clear upgrade message.
fn render_upgrade(detail: &Value) {
    let inner = detail.get("detail").unwrap_or(detail);
    let message = inner
        .get("detail")
        .and_then(|d| d.as_str())
        .unwrap_or("LLM analysis allowance exhausted for your plan.");
    let upgrade_url = inner
        .get("upgrade_url")
        .and_then(|u| u.as_str())
        .unwrap_or("https://www.sigilsec.ai/pricing");
    eprintln!("{} {}", "sigil:".bold().yellow(), message);
    if let Some(reset) = inner.get("reset_date").and_then(|r| r.as_str()) {
        eprintln!("  allowance resets: {}", reset);
    }
    eprintln!("  {} {}", "Upgrade to Pro:".bold(), upgrade_url);
}

/// Run `sigil explain`. Returns the process exit code.
pub async fn cmd_explain(
    scan_json: &Path,
    finding_index: usize,
    endpoint: &str,
    verbose: bool,
) -> i32 {
    let content = match std::fs::read_to_string(scan_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} cannot read {}: {}",
                "error:".bold().red(),
                scan_json.display(),
                e
            );
            return 2;
        }
    };

    let findings = match parse_scan_findings(&content) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{} {}", "error:".bold().red(), e);
            return 2;
        }
    };

    if finding_index >= findings.len() {
        eprintln!(
            "{} finding index {} out of range — scan has {} finding(s)",
            "error:".bold().red(),
            finding_index,
            findings.len()
        );
        return 2;
    }

    let token = match crate::api::load_token() {
        Some(t) => t,
        None => {
            eprintln!(
                "{} not authenticated — run `sigil login` first",
                "error:".bold().red()
            );
            return 2;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(format!("sigil-cli/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} http client: {}", "error:".bold().red(), e);
            return 2;
        }
    };

    // 1. Submit the scan so the server holds the findings to adjudicate.
    let normalized: Vec<Value> = findings.iter().map(normalize_finding).collect();
    let target = scan_json
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("cli-scan");
    let payload = json!({
        "target": target,
        "target_type": "directory",
        "files_scanned": 0,
        "findings": normalized,
        "metadata": {"source": "sigil-explain"},
    });

    if verbose {
        eprintln!("submitting scan to {}", endpoint);
    }
    let submit = client
        .post(format!("{}/v1/scan", endpoint))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await;
    let scan_id = match submit {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(body) => match body.get("scan_id").and_then(|i| i.as_str()) {
                    Some(id) => id.to_string(),
                    None => {
                        eprintln!(
                            "{} scan submission returned no scan_id",
                            "error:".bold().red()
                        );
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{} scan response parse: {}", "error:".bold().red(), e);
                    return 2;
                }
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "{} scan submission failed ({}): {}",
                "error:".bold().red(),
                status,
                body
            );
            return 2;
        }
        Err(e) => {
            eprintln!("{} cannot reach {}: {}", "error:".bold().red(), endpoint, e);
            return 2;
        }
    };

    // 2. Ask the server to adjudicate the chosen finding.
    if verbose {
        eprintln!("adjudicating finding {} of scan {}", finding_index, scan_id);
    }
    let adjudicate = client
        .post(format!(
            "{}/v1/scans/{}/findings/{}/adjudicate",
            endpoint, scan_id, finding_index
        ))
        .bearer_auth(&token)
        .send()
        .await;

    match adjudicate {
        Ok(resp) => {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            match status.as_u16() {
                200 => {
                    match body.get("adjudication") {
                        Some(adjudication) => {
                            render_verdict(adjudication);
                            0
                        }
                        None => {
                            eprintln!(
                                "{} adjudication response missing verdict",
                                "error:".bold().red()
                            );
                            2
                        }
                    }
                }
                402 => {
                    render_upgrade(&body);
                    2
                }
                422 => {
                    let inner = body.get("detail").unwrap_or(&body);
                    let category = inner
                        .get("category")
                        .and_then(|c| c.as_str())
                        .unwrap_or("unspecified");
                    eprintln!(
                        "{} the model declined to analyze this finding (category: {}). \
                         This can happen with content that trips safety classifiers; \
                         the finding remains unadjudicated.",
                        "sigil:".bold().yellow(),
                        category
                    );
                    2
                }
                401 | 403 => {
                    eprintln!(
                        "{} not authorized — run `sigil login` or check your plan",
                        "error:".bold().red()
                    );
                    2
                }
                _ => {
                    eprintln!(
                        "{} adjudication failed ({}): {}",
                        "error:".bold().red(),
                        status,
                        body
                    );
                    2
                }
            }
        }
        Err(e) => {
            eprintln!("{} cannot reach {}: {}", "error:".bold().red(), endpoint, e);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_document_scan_output() {
        let content = "sigil: scanning...\n{\"files_scanned\":1}\n[{\"phase\":\"NetworkExfil\",\"severity\":\"High\",\"rule\":\"NET-006\",\"file\":\"a.js\"}]\n{\"verdict\":\"HIGH RISK\"}";
        let findings = parse_scan_findings(content).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["rule"], "NET-006");
    }

    #[test]
    fn rejects_file_without_findings_array() {
        assert!(parse_scan_findings("{\"verdict\":\"LOW RISK\"}").is_err());
    }

    #[test]
    fn normalizes_phase_and_severity_for_api() {
        let finding = serde_json::json!({
            "phase": "NetworkExfil", "severity": "High", "rule": "NET-006", "file": "a.js"
        });
        let n = normalize_finding(&finding);
        assert_eq!(n["phase"], "network_exfil");
        assert_eq!(n["severity"], "HIGH");
        assert_eq!(n["rule"], "NET-006");
    }
}
