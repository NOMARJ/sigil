use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{Finding, Phase, Severity};

/// A cloud-fetched signature (matches the API response format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSignature {
    pub id: String,
    pub pattern: String,
    pub phase: String,
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Wrapped format returned by GET /v1/signatures.
#[derive(Debug, Deserialize)]
pub struct SignatureResponse {
    pub signatures: Vec<CloudSignature>,
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub last_updated: Option<String>,
}

/// Path to the locally cached signatures file.
pub fn signatures_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("signatures.json")
}

/// Path to the metadata file that tracks when signatures were last fetched.
fn sync_meta_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("signatures_meta.json")
}

/// Load cloud signatures from disk.  Returns an empty vec if the file is
/// missing or malformed (offline-safe).
pub fn load_cloud_signatures() -> Vec<CloudSignature> {
    let path = signatures_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    // Try wrapped format first ({signatures: [...]})
    if let Ok(resp) = serde_json::from_str::<SignatureResponse>(&contents) {
        return resp.signatures;
    }

    // Fall back to raw array format
    serde_json::from_str::<Vec<CloudSignature>>(&contents).unwrap_or_default()
}

/// Get the last_updated timestamp from the sync metadata, for delta sync.
pub fn get_last_sync_time() -> Option<String> {
    let path = sync_meta_path();
    let contents = std::fs::read_to_string(&path).ok()?;
    let meta: serde_json::Value = serde_json::from_str(&contents).ok()?;
    meta.get("last_updated")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Save sync metadata after a successful signature fetch.
pub fn save_sync_meta(last_updated: &str) {
    let path = sync_meta_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let meta = serde_json::json!({
        "last_updated": last_updated,
        "fetched_at": chrono::Utc::now().to_rfc3339(),
    });
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&meta).unwrap_or_default());
}

fn parse_phase(s: &str) -> Phase {
    match s.to_lowercase().as_str() {
        "install_hooks" | "install-hooks" => Phase::InstallHooks,
        "code_patterns" | "code-patterns" => Phase::CodePatterns,
        "network_exfil" | "network-exfil" => Phase::NetworkExfil,
        "credentials" => Phase::Credentials,
        "obfuscation" => Phase::Obfuscation,
        "provenance" => Phase::Provenance,
        _ => Phase::CodePatterns, // default
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn phase_weight(phase: Phase) -> u32 {
    match phase {
        Phase::InstallHooks => 10,
        Phase::CodePatterns => 5,
        Phase::NetworkExfil => 3,
        Phase::Credentials => 2,
        Phase::Obfuscation => 5,
        Phase::Provenance => 1,
    }
}

/// Scan a file's contents against all loaded cloud signatures.
/// Returns findings for any matches.
pub fn scan_with_cloud_signatures(
    file: &str,
    contents: &str,
    signatures: &[CloudSignature],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for sig in signatures {
        let re = match Regex::new(&sig.pattern) {
            Ok(r) => r,
            Err(_) => continue, // Skip invalid patterns silently
        };

        let phase = parse_phase(&sig.phase);
        let severity = parse_severity(&sig.severity);
        let weight = phase_weight(phase);

        for (line_num, line) in contents.lines().enumerate() {
            if re.is_match(line) {
                let snippet = if line.len() > 200 {
                    format!("{} ...", &line[..200])
                } else {
                    line.to_string()
                };
                findings.push(Finding {
                    phase,
                    rule: sig.id.clone(),
                    severity,
                    file: file.to_string(),
                    line: Some(line_num + 1),
                    snippet: format!(
                        "[cloud] {}: {}",
                        sig.description.as_str(),
                        snippet.trim()
                    ),
                    weight,
                });
            }
        }
    }

    findings
}
