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
#[allow(dead_code)]
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
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    );
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// A cloud signature with its regex compiled and its phase resolved.
///
/// Compilation happens once per scan rather than once per file: the previous
/// shape called `Regex::new` inside the per-file loop, so a 1,000-file scan
/// recompiled every cloud pattern 1,000 times.
pub struct CompiledCloudSignature {
    id: String,
    description: String,
    regex: Regex,
    phase: Phase,
    severity: Severity,
    weight: u32,
}

/// Compile loaded cloud signatures, resolving phase and severity once.
///
/// Signatures with an unparseable regex or an unrecognised phase are dropped
/// with a warning rather than silently mishandled. An unknown phase used to
/// fall through to `CodePatterns`, which gave the signature the wrong weight
/// and filed it under the wrong heading — a cloud `prompt_injection`
/// signature scored 5 instead of 10.
pub fn compile_cloud_signatures(signatures: &[CloudSignature]) -> Vec<CompiledCloudSignature> {
    let mut compiled = Vec::with_capacity(signatures.len());
    let mut bad_pattern = Vec::new();
    let mut bad_phase = Vec::new();

    for sig in signatures {
        let Some(phase) = Phase::from_name(&sig.phase) else {
            bad_phase.push(format!("{} (phase {:?})", sig.id, sig.phase));
            continue;
        };
        let regex = match Regex::new(&sig.pattern) {
            Ok(r) => r,
            Err(_) => {
                bad_pattern.push(sig.id.clone());
                continue;
            }
        };
        compiled.push(CompiledCloudSignature {
            id: sig.id.clone(),
            description: sig.description.clone(),
            regex,
            phase,
            severity: parse_severity(&sig.severity),
            weight: phase.default_weight(),
        });
    }

    if !bad_pattern.is_empty() {
        eprintln!(
            "[cloud] warning: {} signature(s) skipped — invalid regex: {}",
            bad_pattern.len(),
            bad_pattern.join(", ")
        );
    }
    if !bad_phase.is_empty() {
        eprintln!(
            "[cloud] warning: {} signature(s) skipped — unrecognised phase: {}. \
             This usually means the signature feed is newer than this binary; run `sigil install --update`.",
            bad_phase.len(),
            bad_phase.join(", ")
        );
    }

    compiled
}

/// Scan a file's contents against all compiled cloud signatures.
/// Returns findings for any matches.
pub fn scan_with_cloud_signatures(
    file: &str,
    contents: &str,
    signatures: &[CompiledCloudSignature],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for sig in signatures {
        for (line_num, line) in contents.lines().enumerate() {
            if sig.regex.is_match(line) {
                findings.push(Finding {
                    phase: sig.phase,
                    rule: sig.id.clone(),
                    severity: sig.severity,
                    file: file.to_string(),
                    line: Some(line_num + 1),
                    snippet: format!(
                        "[cloud] {}: {}",
                        sig.description.as_str(),
                        truncate_snippet(line).trim()
                    ),
                    weight: sig.weight,
                    kev: false,
                    epss: 0.0,
                });
            }
        }
    }

    findings
}

/// Truncate a match line to ~200 bytes for display, cutting on a character
/// boundary.
///
/// `&line[..200]` panics when byte 200 lands inside a multi-byte character.
/// The same bug was found and fixed in `corpus::engine`; this is the port of
/// that fix to the cloud-signature path.
fn truncate_snippet(line: &str) -> String {
    const LIMIT: usize = 200;
    if line.len() <= LIMIT {
        return line.to_string();
    }
    let end = line
        .char_indices()
        .take_while(|(i, _)| *i < LIMIT)
        .last()
        .map(|(i, ch)| i + ch.len_utf8())
        .unwrap_or(0);
    format!("{} ...", &line[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(id: &str, phase: &str, pattern: &str) -> CloudSignature {
        CloudSignature {
            id: id.to_string(),
            pattern: pattern.to_string(),
            phase: phase.to_string(),
            severity: "HIGH".to_string(),
            description: "test".to_string(),
            updated_at: None,
        }
    }

    /// Regression: `&line[..200]` panicked when byte 200 landed inside a
    /// multi-byte character. Mirrors the `corpus::engine` regression test.
    #[test]
    fn truncate_snippet_handles_multibyte_at_boundary() {
        // 'é' is two bytes. Placing them so one straddles byte 200 is the
        // panicking case for a raw byte slice.
        for pad in 195..205 {
            let line = format!("{}{}", "a".repeat(pad), "é".repeat(20));
            let out = truncate_snippet(&line);
            assert!(out.ends_with(" ..."), "expected truncation for pad={pad}");
        }
    }

    #[test]
    fn truncate_snippet_leaves_short_lines_alone() {
        assert_eq!(truncate_snippet("short"), "short");
    }

    /// Regression for the phase-misfiling defect: cloud signatures for the
    /// three newest phases used to fall through to `CodePatterns` with the
    /// wrong weight.
    #[test]
    fn compiles_every_phase_with_its_own_weight() {
        for phase in Phase::ALL {
            let compiled = compile_cloud_signatures(&[sig("X-1", phase.canonical_name(), "evil")]);
            assert_eq!(compiled.len(), 1, "phase {phase} was dropped");
            assert_eq!(compiled[0].phase, phase);
            assert_eq!(
                compiled[0].weight,
                phase.default_weight(),
                "phase {phase} got the wrong weight"
            );
        }
    }

    #[test]
    fn prompt_injection_keeps_weight_ten() {
        let compiled = compile_cloud_signatures(&[sig("PI-1", "prompt_injection", "ignore .*")]);
        assert_eq!(compiled[0].phase, Phase::PromptInjection);
        assert_eq!(compiled[0].weight, 10);
    }

    #[test]
    fn unknown_phase_is_dropped_not_misfiled() {
        let compiled = compile_cloud_signatures(&[sig("Z-1", "phase_from_the_future", "evil")]);
        assert!(
            compiled.is_empty(),
            "an unknown phase must not be silently filed as CodePatterns"
        );
    }

    #[test]
    fn invalid_regex_is_dropped() {
        assert!(compile_cloud_signatures(&[sig("B-1", "credentials", "(unclosed")]).is_empty());
    }

    #[test]
    fn scan_reports_line_numbers_and_phase() {
        let compiled = compile_cloud_signatures(&[sig("N-1", "network_exfil", "curl")]);
        let findings = scan_with_cloud_signatures("a.sh", "ok\ncurl http://x\n", &compiled);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, Some(2));
        assert_eq!(findings[0].phase, Phase::NetworkExfil);
        assert_eq!(findings[0].weight, 3);
    }
}
