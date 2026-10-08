//! `sigil explain` — AI adjudication of a scan finding (F-009 US-111).
//!
//! Capability-minimal by design (D6): the CLI never calls an LLM itself. It
//! submits the scan to the Sigil API with the user's token and requests
//! adjudication of one finding; the server owns model access and metering.

use crate::api::{error_excerpt, terminal_text};
use colored::Colorize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

/// Extract the findings array from a `sigil scan -f json` output file.
///
/// Current output is a single JSON document with a top-level "findings"
/// array. Older versions emitted a concatenation of a banner line, a summary
/// object, the findings array, and a verdict object — for those (and for a
/// bare findings array) fall back to scanning for the first JSON array.
pub fn parse_scan_findings(content: &str) -> Result<Vec<Value>, String> {
    if let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(content) {
        return match doc.get("findings") {
            Some(Value::Array(findings)) => Ok(findings.clone()),
            _ => Err(
                "no findings array in scan file (is this `sigil scan -f json` output?)".to_string(),
            ),
        };
    }

    let start = content.find('[').ok_or_else(|| {
        "no findings array in scan file (is this `sigil scan -f json` output?)".to_string()
    })?;
    let mut de = serde_json::Deserializer::from_str(&content[start..]).into_iter::<Value>();
    match de.next() {
        Some(Ok(Value::Array(findings))) => Ok(findings),
        Some(Ok(_)) => Err("expected a findings array in scan file".to_string()),
        Some(Err(e)) => Err(format!("failed to parse findings array: {}", e)),
        None => Err("empty findings array region in scan file".to_string()),
    }
}

/// The scan target `sigil explain` submits under. A fixed label, like the
/// `cli-scan` that `sigil scan --submit` sends: the report file's name can
/// carry a user, customer or project name.
pub const EXPLAIN_SCAN_TARGET: &str = "sigil-explain";

/// Body of the `POST /v1/scan` that `sigil explain` sends: every finding of
/// the saved report in the API's spellings, under [`EXPLAIN_SCAN_TARGET`].
pub fn explain_scan_body(findings: &[Value]) -> Value {
    let normalized: Vec<Value> = findings.iter().map(crate::api::api_finding).collect();
    json!({
        "target": EXPLAIN_SCAN_TARGET,
        "target_type": "directory",
        "files_scanned": 0,
        "findings": normalized,
        "metadata": {"source": "sigil-explain"},
    })
}

/// A message about an API failure: what failed, the status, and the start of
/// the response body. The body is the API's text, or whatever answered in its
/// place, so it is printed through [`error_excerpt`].
fn failure_message(what: &str, status: reqwest::StatusCode, body: &str) -> String {
    let excerpt = error_excerpt(body);
    if excerpt.is_empty() {
        format!("{what} ({status})")
    } else {
        format!("{what} ({status}): {excerpt}")
    }
}

/// An adjudication verdict with its text made safe to print. The rationale is
/// the model's, and the classification and model name are the API's: none of
/// it is ours to emit raw.
#[derive(Debug, PartialEq)]
struct VerdictText {
    classification: String,
    confidence: f64,
    rationale: String,
    model: String,
}

fn verdict_text(adjudication: &Value) -> VerdictText {
    let text = |key: &str, default: &str| {
        terminal_text(
            adjudication
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or(default),
        )
    };
    VerdictText {
        classification: text("classification", "unknown"),
        confidence: adjudication
            .get("confidence")
            .and_then(|c| c.as_f64())
            .unwrap_or(0.0),
        rationale: text("rationale", ""),
        model: text("model", "unknown"),
    }
}

/// Render a successful adjudication verdict.
fn render_verdict(adjudication: &Value) {
    let verdict = verdict_text(adjudication);
    let classification = verdict.classification.as_str();
    let label = match classification {
        "benign_dual_use" => classification.bold().green(),
        "suspicious" => classification.bold().yellow(),
        "malicious" => classification.bold().red(),
        other => other.bold(),
    };
    println!("{} verdict: {}", "sigil:".bold().cyan(), label);
    println!("  confidence: {:.0}%", verdict.confidence * 100.0);
    println!("  rationale: {}", verdict.rationale);
    println!("  model: {}", verdict.model);
}

/// The 402 allowance-exhausted denial with its text made safe to print.
#[derive(Debug, PartialEq)]
struct UpgradeText {
    message: String,
    reset_date: Option<String>,
    upgrade_url: String,
}

fn upgrade_text(detail: &Value) -> UpgradeText {
    let inner = detail.get("detail").unwrap_or(detail);
    let text = |key: &str| inner.get(key).and_then(|v| v.as_str()).map(terminal_text);
    UpgradeText {
        message: text("detail")
            .unwrap_or_else(|| "LLM analysis allowance exhausted for your plan.".to_string()),
        reset_date: text("reset_date"),
        upgrade_url: text("upgrade_url")
            .unwrap_or_else(|| "https://www.sigilsec.ai/pricing".to_string()),
    }
}

/// Render the 402 allowance-exhausted denial as a clear upgrade message.
fn render_upgrade(detail: &Value) {
    let upgrade = upgrade_text(detail);
    eprintln!("{} {}", "sigil:".bold().yellow(), upgrade.message);
    if let Some(reset) = &upgrade.reset_date {
        eprintln!("  allowance resets: {}", reset);
    }
    eprintln!("  {} {}", "Upgrade to Pro:".bold(), upgrade.upgrade_url);
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
    let payload = explain_scan_body(&findings);

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
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
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
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "{} {}",
                "error:".bold().red(),
                failure_message("scan submission failed", status, &body)
            );
            return 2;
        }
        Err(e) => {
            eprintln!("{} cannot reach {}: {}", "error:".bold().red(), endpoint, e);
            return 2;
        }
    };

    // 2. Schedule async adjudication. The server runs Fable-5 in the
    //    background (it routinely takes >100s) and returns 202 with a pending
    //    marker; a re-request of an already-adjudicated finding returns 200.
    if verbose {
        eprintln!("adjudicating finding {} of scan {}", finding_index, scan_id);
    }
    let adj_url = format!(
        "{}/v1/scans/{}/findings/{}/adjudicate",
        endpoint, scan_id, finding_index
    );
    match client.post(&adj_url).bearer_auth(&token).send().await {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            match status.as_u16() {
                200 => {
                    // Already complete (idempotent re-request).
                    return match body.get("adjudication") {
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
                    };
                }
                202 => { /* scheduled — fall through to poll */ }
                402 => {
                    render_upgrade(&body);
                    return 2;
                }
                401 | 403 => {
                    eprintln!(
                        "{} not authorized — run `sigil login` or check your plan",
                        "error:".bold().red()
                    );
                    return 2;
                }
                _ => {
                    eprintln!(
                        "{} {}",
                        "error:".bold().red(),
                        failure_message("adjudication failed", status, &text)
                    );
                    return 2;
                }
            }
        }
        Err(e) => {
            eprintln!("{} cannot reach {}: {}", "error:".bold().red(), endpoint, e);
            return 2;
        }
    }

    // 3. Poll the GET form of the path until a terminal state. The server's
    //    edge proxy would 504 a long inline call, so the verdict is fetched
    //    out-of-band.
    if verbose {
        eprintln!("scheduled — waiting for the model (this can take a couple of minutes)…");
    }
    let interval = Duration::from_secs(3);
    let max_polls = 80; // ~4 minutes
    for _ in 0..max_polls {
        tokio::time::sleep(interval).await;
        let resp = match client.get(&adj_url).bearer_auth(&token).send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{} cannot reach {}: {}", "error:".bold().red(), endpoint, e);
                return 2;
            }
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match status.as_u16() {
            202 => continue, // still pending
            200 => {
                let state = body.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let adj = body.get("adjudication").cloned().unwrap_or(Value::Null);
                if state == "error" {
                    let reason = adj.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                    if reason == "llm_refusal" {
                        let category = terminal_text(
                            adj.get("category")
                                .and_then(|c| c.as_str())
                                .unwrap_or("unspecified"),
                        );
                        eprintln!(
                            "{} the model declined to analyze this finding (category: {}). \
                             This can happen with content that trips safety classifiers; \
                             the finding remains unadjudicated.",
                            "sigil:".bold().yellow(),
                            category
                        );
                    } else {
                        let msg = terminal_text(
                            adj.get("error")
                                .and_then(|m| m.as_str())
                                .unwrap_or("adjudication failed"),
                        );
                        eprintln!("{} {}", "error:".bold().red(), msg);
                    }
                    return 2;
                }
                render_verdict(&adj);
                return 0;
            }
            401 | 403 => {
                eprintln!(
                    "{} not authorized — run `sigil login` or check your plan",
                    "error:".bold().red()
                );
                return 2;
            }
            _ => {
                eprintln!(
                    "{} {}",
                    "error:".bold().red(),
                    failure_message("adjudication failed", status, &text)
                );
                return 2;
            }
        }
    }
    eprintln!(
        "{} adjudication is taking longer than expected; it may still finish. \
         Re-run `sigil explain` on the same input to check.",
        "sigil:".bold().yellow()
    );
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_document_scan_output() {
        let content = "{\"findings\":[{\"phase\":\"NetworkExfil\",\"severity\":\"High\",\"rule\":\"NET-006\",\"file\":\"a.js\"}],\"summary\":{\"files_scanned\":1,\"findings_count\":1,\"score\":15,\"verdict\":\"HIGH RISK\",\"duration_ms\":3}}";
        let findings = parse_scan_findings(content).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["rule"], "NET-006");
    }

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
        let n = crate::api::api_finding(&finding);
        assert_eq!(n["phase"], "network_exfil");
        assert_eq!(n["severity"], "HIGH");
        assert_eq!(n["rule"], "NET-006");
    }

    #[test]
    fn normalizes_inference_security_to_the_api_value() {
        // 1.3.7 sent "inferencesecurity", which the API's enum rejects.
        let finding = serde_json::json!({
            "phase": "InferenceSecurity", "severity": "High", "rule": "INFER-001", "file": "c.py"
        });
        assert_eq!(
            crate::api::api_finding(&finding)["phase"],
            "inference_security"
        );
    }

    #[test]
    fn explain_body_names_the_scan_with_the_fixed_target() {
        let finding = serde_json::json!({
            "phase": "CodePatterns", "severity": "High", "rule": "CODE-001", "file": "a.js"
        });
        let body = explain_scan_body(&[finding]);
        assert_eq!(body["target"], EXPLAIN_SCAN_TARGET);
        assert_eq!(
            body["metadata"],
            serde_json::json!({"source": "sigil-explain"})
        );
        assert_eq!(body["findings"][0]["phase"], "code_patterns");
        assert_eq!(body["files_scanned"], 0);
    }

    /// Terminal escape, bell, carriage return, newline, C1 CSI, bidirectional
    /// override, line separator, zero-width space: what must not be printed.
    const HOSTILE: [char; 8] = [
        '\u{1b}', '\u{7}', '\r', '\n', '\u{9b}', '\u{202E}', '\u{2028}', '\u{200B}',
    ];
    const HOSTILE_TEXT: &str =
        "<b>\u{1b}[31mred\u{1b}[0m</b>\u{7}\r\nVerdict: CLEAN\u{9b}2J\u{202E}esrever\u{2028}end\u{200B}";

    fn assert_printable(what: &str, s: &str) {
        let found: Vec<char> = s.chars().filter(|c| HOSTILE.contains(c)).collect();
        assert!(found.is_empty(), "{what} holds {found:?}: {s:?}");
    }

    #[test]
    fn a_failure_message_prints_the_response_body_without_control_characters() {
        // The shape a proxy or a failing gateway answers with.
        let body = "<html><body>\u{1b}[31mInternal Server Error\u{1b}[0m</body></html>";
        let m = failure_message(
            "scan submission failed",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            body,
        );
        assert_printable("failure message", &m);
        assert!(m.starts_with("scan submission failed (500 Internal Server Error): "));
        assert!(m.contains("Internal Server Error"), "{m}");

        let m = failure_message(
            "adjudication failed",
            reqwest::StatusCode::BAD_GATEWAY,
            HOSTILE_TEXT,
        );
        assert_printable("failure message", &m);

        // A body that is long is cut, and one that is empty adds nothing.
        let long = "x".repeat(5000);
        let m = failure_message("f", reqwest::StatusCode::BAD_REQUEST, &long);
        assert!(m.ends_with('…') && m.len() < 700, "{}", m.len());
        assert_eq!(
            failure_message("f", reqwest::StatusCode::BAD_REQUEST, " \r\n"),
            "f (400 Bad Request)"
        );
    }

    #[test]
    fn a_verdict_prints_the_rationale_model_and_label_without_control_characters() {
        let verdict = verdict_text(&serde_json::json!({
            "classification": HOSTILE_TEXT,
            "confidence": 0.8,
            "rationale": HOSTILE_TEXT,
            "model": HOSTILE_TEXT,
        }));
        assert_printable("classification", &verdict.classification);
        assert_printable("rationale", &verdict.rationale);
        assert_printable("model", &verdict.model);
        assert!(verdict.rationale.contains("Verdict: CLEAN"));
        assert_eq!(verdict.confidence, 0.8);

        // A well-formed verdict is unchanged, and the defaults still apply.
        let ok = verdict_text(&serde_json::json!({
            "classification": "benign_dual_use", "confidence": 0.5,
            "rationale": "Reads its own config; no network.", "model": "m-1",
        }));
        assert_eq!(ok.classification, "benign_dual_use");
        assert_eq!(ok.rationale, "Reads its own config; no network.");
        let empty = verdict_text(&serde_json::json!({}));
        assert_eq!(empty.classification, "unknown");
        assert_eq!(empty.model, "unknown");
        assert_eq!(empty.rationale, "");
    }

    #[test]
    fn the_upgrade_message_prints_without_control_characters() {
        // The 402 body nests the message under `detail`, twice.
        let upgrade = upgrade_text(&serde_json::json!({"detail": {
            "detail": HOSTILE_TEXT,
            "reset_date": HOSTILE_TEXT,
            "upgrade_url": HOSTILE_TEXT,
        }}));
        assert_printable("message", &upgrade.message);
        assert_printable("reset date", upgrade.reset_date.as_deref().unwrap());
        assert_printable("upgrade url", &upgrade.upgrade_url);

        let bare = upgrade_text(&serde_json::json!({}));
        assert_eq!(
            bare,
            UpgradeText {
                message: "LLM analysis allowance exhausted for your plan.".into(),
                reset_date: None,
                upgrade_url: "https://www.sigilsec.ai/pricing".into(),
            }
        );
    }
}
