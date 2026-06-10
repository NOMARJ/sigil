//! Pack engine: runs `SignaturePack` rules against file content and returns
//! `Finding`s with the same structure as the hardcoded phase functions.

use regex::Regex;
use std::path::Path;
use walkdir::DirEntry;

use crate::scanner::{Finding, Phase, Severity};

use super::schema::{ProvenanceKind, SignaturePack};

// ---------------------------------------------------------------------------
// Phase/severity parsers (mirrors scanner::cloud_sigs helpers)
// ---------------------------------------------------------------------------

fn parse_phase(s: &str) -> Option<Phase> {
    match s.to_lowercase().as_str() {
        "install_hooks" | "install-hooks" => Some(Phase::InstallHooks),
        "code_patterns" | "code-patterns" => Some(Phase::CodePatterns),
        "network_exfil" | "network-exfil" => Some(Phase::NetworkExfil),
        "credentials" => Some(Phase::Credentials),
        "obfuscation" => Some(Phase::Obfuscation),
        "provenance" => Some(Phase::Provenance),
        "prompt_injection" | "prompt-injection" => Some(Phase::PromptInjection),
        "skill_security" | "skill-security" => Some(Phase::SkillSecurity),
        "inference_security" | "inference-security" => Some(Phase::InferenceSecurity),
        _ => None,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn default_weight(phase: Phase) -> u32 {
    match phase {
        Phase::InstallHooks => 10,
        Phase::CodePatterns => 5,
        Phase::NetworkExfil => 3,
        Phase::Credentials => 2,
        Phase::Obfuscation => 5,
        Phase::Provenance => 1,
        Phase::PromptInjection => 10,
        Phase::SkillSecurity => 5,
        Phase::InferenceSecurity => 5,
    }
}

// ---------------------------------------------------------------------------
// Content scanning
// ---------------------------------------------------------------------------

/// Run all content-based pack rules against a single file.
///
/// `file_path` is the relative path used in findings.
/// `filename`  is the basename (used for file-filter matching).
/// `contents`  is the full file text.
pub fn scan_file_with_packs(
    packs: &[SignaturePack],
    file_path: &str,
    filename: &str,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Precompute file header (first 1 KB) for suppression checks.
    let header_len = contents.len().min(1024);
    let file_header = &contents[..header_len];

    for pack in packs {
        for rule in &pack.rules {
            // File-filter gate
            if !rule.file_filter.is_empty() && !rule.file_filter.matches(filename) {
                continue;
            }

            let phase = match parse_phase(&rule.phase) {
                Some(p) => p,
                None => continue,
            };
            let severity = parse_severity(&rule.severity);
            let weight = rule.weight.unwrap_or_else(|| default_weight(phase));

            let re = match Regex::new(&rule.pattern) {
                Ok(r) => r,
                Err(_) => continue, // skip invalid patterns gracefully
            };

            for (line_num, line) in contents.lines().enumerate() {
                if !re.is_match(line) {
                    continue;
                }

                // Suppression gate
                if rule
                    .suppress
                    .should_suppress(file_path, filename, line, file_header)
                {
                    continue;
                }

                let snippet = if line.len() > 200 {
                    let truncated = line
                        .char_indices()
                        .take_while(|(i, _)| *i < 200)
                        .last()
                        .map(|(i, ch)| i + ch.len_utf8())
                        .unwrap_or(0);
                    format!("{} ...", &line[..truncated])
                } else {
                    line.to_string()
                };

                findings.push(Finding {
                    phase,
                    rule: rule.id.clone(),
                    severity,
                    file: file_path.to_string(),
                    line: Some(line_num + 1),
                    snippet: format!("{}: {}", rule.description, snippet.trim()),
                    weight,
                });
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Provenance scanning (filesystem metadata, not content)
// ---------------------------------------------------------------------------

/// Run provenance (Phase 6) pack rules against directory entries.
///
/// This mirrors `phases::scan_provenance` in structure but uses declarative
/// pack rules instead of hardcoded Rust logic.
pub fn scan_provenance_with_packs(
    packs: &[SignaturePack],
    base_path: &Path,
    entries: &[DirEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for pack in packs {
        for rule in &pack.provenance_rules {
            let severity = parse_severity(&rule.severity);

            // Build regex once per rule (for FilenameRegex kind).
            let re: Option<Regex> = if rule.kind == ProvenanceKind::FilenameRegex {
                rule.pattern
                    .as_deref()
                    .and_then(|p| Regex::new(p).ok())
            } else {
                None
            };

            for entry in entries {
                let file_path = entry.path();
                let rel_path = file_path
                    .strip_prefix(base_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                if rel_path.starts_with(".git/") || rel_path == ".git" {
                    continue;
                }

                let filename = file_path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();

                match rule.kind {
                    ProvenanceKind::FilenameRegex => {
                        if let Some(ref r) = re {
                            if r.is_match(&filename) {
                                findings.push(Finding {
                                    phase: Phase::Provenance,
                                    rule: rule.id.clone(),
                                    severity,
                                    file: rel_path.clone(),
                                    line: None,
                                    snippet: format!("{}: {}", rule.description, filename),
                                    weight: default_weight(Phase::Provenance),
                                });
                            }
                        }
                    }

                    ProvenanceKind::HiddenFile => {
                        if filename.starts_with('.')
                            && !rule.excluded_filenames.iter().any(|e| e == &filename)
                        {
                            findings.push(Finding {
                                phase: Phase::Provenance,
                                rule: rule.id.clone(),
                                severity,
                                file: rel_path.clone(),
                                line: None,
                                snippet: format!("{}: {}", rule.description, filename),
                                weight: 1,
                            });
                        }
                    }

                    ProvenanceKind::BinaryExtension => {
                        let lower = filename.to_lowercase();
                        let is_binary = [
                            ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".a", ".pyc",
                            ".pyo", ".class", ".jar", ".war", ".ear", ".wasm", ".node",
                        ]
                        .iter()
                        .any(|ext| lower.ends_with(ext));

                        if is_binary {
                            let is_expected = rule
                                .allowed_path_prefixes
                                .iter()
                                .any(|prefix| rel_path.starts_with(prefix.as_str()));
                            if !is_expected {
                                findings.push(Finding {
                                    phase: Phase::Provenance,
                                    rule: rule.id.clone(),
                                    severity,
                                    file: rel_path.clone(),
                                    line: None,
                                    snippet: format!(
                                        "{}: {}",
                                        rule.description, filename
                                    ),
                                    weight: 2,
                                });
                            }
                        }
                    }

                    ProvenanceKind::FileSizeBytes => {
                        let threshold = rule.size_threshold.unwrap_or(5_000_000);
                        if let Ok(meta) = entry.metadata() {
                            if meta.len() > threshold {
                                findings.push(Finding {
                                    phase: Phase::Provenance,
                                    rule: rule.id.clone(),
                                    severity,
                                    file: rel_path.clone(),
                                    line: None,
                                    snippet: format!(
                                        "{}: {} bytes",
                                        rule.description,
                                        meta.len()
                                    ),
                                    weight: 1,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
