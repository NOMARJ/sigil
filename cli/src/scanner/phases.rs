//! Phase dispatch — thin wrappers that route each scan phase through the
//! corpus engine.  No inline `Regex::new` calls live here; all patterns are
//! declared in `packs/core/v1/*.json` and loaded via `corpus::loader`.

use std::path::{Path, PathBuf};

use super::{Finding, Phase, Severity};
use crate::corpus::{
    engine::scan_file_with_packs,
    loader::load_all_packs,
    schema::{ProvenanceKind, SignaturePack},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_packs() -> Vec<SignaturePack> {
    load_all_packs()
}

fn phase_packs(packs: &[SignaturePack], phase: &str) -> Vec<SignaturePack> {
    packs
        .iter()
        .filter(|p| p.rules.iter().any(|r| r.phase == phase))
        .cloned()
        .collect()
}

fn make_finding(
    phase: Phase,
    rule: &str,
    severity: Severity,
    file: &str,
    line: Option<usize>,
    snippet: &str,
    weight: u32,
) -> Finding {
    Finding {
        phase,
        rule: rule.to_string(),
        severity,
        file: file.to_string(),
        line,
        snippet: snippet.to_string(),
        weight,
        kev: false,
        epss: 0.0,
    }
}

fn filename(file: &str) -> String {
    Path::new(file)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Phase 1: Install Hooks (Critical, 10x weight)
// ---------------------------------------------------------------------------

pub fn scan_install_hooks(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "install_hooks");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 2: Code Patterns (High, 5x weight)
// ---------------------------------------------------------------------------

pub fn scan_code_patterns(file: &str, contents: &str) -> Vec<Finding> {
    if super::context::is_declaration_file(file) {
        return Vec::new();
    }
    let packs = all_packs();
    let phase = phase_packs(&packs, "code_patterns");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 3: Network / Exfiltration (High, 3x weight)
// ---------------------------------------------------------------------------

pub fn scan_network_exfil(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "network_exfil");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 4: Credentials (Medium, 2x weight)
// ---------------------------------------------------------------------------

pub fn scan_credentials(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "credentials");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 5: Obfuscation (High, 5x weight)
// ---------------------------------------------------------------------------

pub fn scan_obfuscation(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "obfuscation");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 6: Provenance (Low, 1-3x weight)
//
// Provenance rules operate on filesystem metadata (filename, size, path),
// not file content.  The engine's `scan_provenance_with_packs` accepts
// `&[DirEntry]`; `run_scan` passes `Vec<PathBuf>`, so we implement the
// pack-based provenance scan directly here against `PathBuf` slices.
//
// PROV-005 (shallow clone) and PROV-006 (missing .git) check for paths
// that exist outside the file walker's scope — they remain as Rust logic
// below the pack dispatch.
// ---------------------------------------------------------------------------

fn parse_severity_prov(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

pub fn scan_provenance(base_path: &Path, entries: &[PathBuf]) -> Vec<Finding> {
    let packs = all_packs();
    let mut findings = Vec::new();

    // Precompile provenance rules from all packs
    use regex::Regex;
    struct CompiledProv<'a> {
        id: &'a str,
        severity: Severity,
        description: &'a str,
        kind: &'a ProvenanceKind,
        pattern_re: Option<Regex>,
        size_threshold: u64,
        allowed_prefixes: &'a [String],
        excluded_filenames: &'a [String],
    }

    let compiled: Vec<CompiledProv<'_>> = packs
        .iter()
        .flat_map(|p| p.provenance_rules.iter())
        .filter_map(|rule| {
            let pattern_re = if rule.kind == ProvenanceKind::FilenameRegex {
                let re = rule.pattern.as_deref().and_then(|p| Regex::new(p).ok())?;
                Some(re)
            } else {
                None
            };
            Some(CompiledProv {
                id: &rule.id,
                severity: parse_severity_prov(&rule.severity),
                description: &rule.description,
                kind: &rule.kind,
                pattern_re,
                size_threshold: rule.size_threshold.unwrap_or(5_000_000),
                allowed_prefixes: &rule.allowed_path_prefixes,
                excluded_filenames: &rule.excluded_filenames,
            })
        })
        .collect();

    for file_path in entries {
        let rel_path = file_path
            .strip_prefix(base_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if rel_path.starts_with(".git/") || rel_path == ".git" {
            continue;
        }

        let fname = file_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        for rule in &compiled {
            match rule.kind {
                ProvenanceKind::HiddenFile => {
                    if fname.starts_with('.')
                        && !rule.excluded_filenames.iter().any(|e| e == &fname)
                    {
                        findings.push(make_finding(
                            Phase::Provenance,
                            rule.id,
                            rule.severity,
                            &rel_path,
                            None,
                            &format!("{}: {}", rule.description, fname),
                            1,
                        ));
                    }
                }

                ProvenanceKind::BinaryExtension => {
                    let lower = fname.to_lowercase();
                    let is_binary = [
                        ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".a", ".pyc",
                        ".pyo", ".class", ".jar", ".war", ".ear", ".wasm", ".node",
                    ]
                    .iter()
                    .any(|ext| lower.ends_with(ext));

                    if is_binary {
                        let is_expected = rule
                            .allowed_prefixes
                            .iter()
                            .any(|prefix| rel_path.starts_with(prefix.as_str()));
                        if !is_expected {
                            findings.push(make_finding(
                                Phase::Provenance,
                                rule.id,
                                rule.severity,
                                &rel_path,
                                None,
                                &format!("{}: {}", rule.description, fname),
                                2,
                            ));
                        }
                    }
                }

                ProvenanceKind::FilenameRegex => {
                    if let Some(ref re) = rule.pattern_re {
                        if re.is_match(&fname) {
                            findings.push(make_finding(
                                Phase::Provenance,
                                rule.id,
                                rule.severity,
                                &rel_path,
                                None,
                                &format!("{}: {}", rule.description, fname),
                                3,
                            ));
                        }
                    }
                }

                ProvenanceKind::FileSizeBytes => {
                    if let Ok(meta) = std::fs::metadata(file_path) {
                        if meta.len() > rule.size_threshold {
                            findings.push(make_finding(
                                Phase::Provenance,
                                rule.id,
                                rule.severity,
                                &rel_path,
                                None,
                                &format!("{}: {} bytes", rule.description, meta.len()),
                                1,
                            ));
                        }
                    }
                }
            }
        }
    }

    // PROV-005: shallow clone (not expressible as a pack rule — requires
    // checking a path outside the scanned file set).
    let git_dir = base_path.join(".git");
    if git_dir.exists() {
        if git_dir.join("shallow").exists() {
            findings.push(make_finding(
                Phase::Provenance,
                "PROV-005",
                Severity::Low,
                ".git/shallow",
                None,
                "Shallow clone detected — limited git history available",
                1,
            ));
        }
    } else if base_path.join("package.json").exists() || base_path.join("setup.py").exists() {
        // PROV-006: no .git directory but project manifest present.
        findings.push(make_finding(
            Phase::Provenance,
            "PROV-006",
            Severity::Medium,
            ".",
            None,
            "No .git directory — provenance cannot be verified via git history",
            2,
        ));
    }

    findings
}

// ---------------------------------------------------------------------------
// Phase 7: Prompt Injection (Critical, 10x weight)
// ---------------------------------------------------------------------------

pub fn scan_prompt_injection(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "prompt_injection");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 8: Skill Security (High, 5x weight)
// ---------------------------------------------------------------------------

pub fn scan_skill_security(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "skill_security");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}

// ---------------------------------------------------------------------------
// Phase 10: Inference Security (High, 5x weight)
// ---------------------------------------------------------------------------

pub fn scan_inference_security(file: &str, contents: &str) -> Vec<Finding> {
    let packs = all_packs();
    let phase = phase_packs(&packs, "inference_security");
    scan_file_with_packs(&phase, file, &filename(file), contents)
}
