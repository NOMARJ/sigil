pub mod cloud_sigs;
pub mod context;
pub mod normalize;
pub mod phases;
pub mod scoring;

use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// The scan phases, each targeting a different threat category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Phase {
    /// Phase 1: Install hooks
    InstallHooks,
    /// Phase 2: Dangerous code patterns
    CodePatterns,
    /// Phase 3: Network and exfiltration
    NetworkExfil,
    /// Phase 4: Credential access
    Credentials,
    /// Phase 5: Obfuscation
    Obfuscation,
    /// Phase 6: Provenance
    Provenance,
    /// Phase 7: Prompt injection detection
    PromptInjection,
    /// Phase 8: Skill / plugin security
    SkillSecurity,
    /// Phase 10: Inference security
    InferenceSecurity,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::InstallHooks => write!(f, "Install Hooks"),
            Phase::CodePatterns => write!(f, "Code Patterns"),
            Phase::NetworkExfil => write!(f, "Network/Exfil"),
            Phase::Credentials => write!(f, "Credentials"),
            Phase::Obfuscation => write!(f, "Obfuscation"),
            Phase::Provenance => write!(f, "Provenance"),
            Phase::PromptInjection => write!(f, "Prompt Injection"),
            Phase::SkillSecurity => write!(f, "Skill Security"),
            Phase::InferenceSecurity => write!(f, "Inference Security"),
        }
    }
}

/// Severity level for an individual finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding discovered during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub phase: Phase,
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    pub line: Option<usize>,
    pub snippet: String,
    pub weight: u32,
}

/// Overall risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Verdict {
    LowRisk,
    MediumRisk,
    HighRisk,
    CriticalRisk,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::LowRisk => write!(f, "LOW RISK"),
            Verdict::MediumRisk => write!(f, "MEDIUM RISK"),
            Verdict::HighRisk => write!(f, "HIGH RISK"),
            Verdict::CriticalRisk => write!(f, "CRITICAL RISK"),
        }
    }
}

/// The result of a complete scan across all phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub score: u32,
    pub verdict: Verdict,
    pub files_scanned: usize,
    pub duration_ms: u64,
}

fn phase_from_name(name: &str) -> Option<Phase> {
    match name.to_lowercase().as_str() {
        "install-hooks" | "install_hooks" | "installhooks" => Some(Phase::InstallHooks),
        "code-patterns" | "code_patterns" | "codepatterns" => Some(Phase::CodePatterns),
        "network-exfil" | "network_exfil" | "networkexfil" => Some(Phase::NetworkExfil),
        "credentials" => Some(Phase::Credentials),
        "obfuscation" => Some(Phase::Obfuscation),
        "provenance" => Some(Phase::Provenance),
        "prompt-injection" | "prompt_injection" | "promptinjection" => Some(Phase::PromptInjection),
        "skill-security" | "skill_security" | "skillsecurity" => Some(Phase::SkillSecurity),
        "inference-security" | "inference_security" | "inferencesecurity" => {
            Some(Phase::InferenceSecurity)
        }
        _ => None,
    }
}

fn severity_from_name(name: &str) -> Option<Severity> {
    match name.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Directories that are never content-scanned: vendored/generated trees whose
/// contents produce noise without manifest context (ADR-0008). Dependency
/// *manifests* (package.json, lockfiles) at the project root are still scanned.
const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Files larger than this are skipped for content scanning (still visible to
/// the Provenance phase, which flags oversized files).
const MAX_CONTENT_SCAN_BYTES: u64 = 10_000_000;

/// Collect candidate files honoring `.gitignore` (only inside real git repos —
/// `require_git(true)` — so a malicious `.gitignore` inside an extracted
/// tarball cannot hide files from the scanner), `.sigilignore` (always), and
/// the hard default excludes above. Dotfiles are walked: instruction files
/// like `.cursorrules` are a primary scan target.
pub(crate) fn collect_files(path: &Path) -> Vec<PathBuf> {
    let mut builder = WalkBuilder::new(path);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .require_git(true)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .parents(false)
        .add_custom_ignore_filename(".sigilignore");
    builder.filter_entry(|entry| {
        let is_dir = entry.file_type().map_or(false, |t| t.is_dir());
        if !is_dir {
            return true;
        }
        let name = entry.file_name().to_string_lossy();
        !DEFAULT_EXCLUDED_DIRS.contains(&name.as_ref())
    });
    let mut files: Vec<PathBuf> = builder
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map_or(false, |t| t.is_file()))
        .map(|e| e.into_path())
        .collect();
    files.sort();
    files
}

pub fn run_scan(
    path: &Path,
    phase_filter: Option<&[String]>,
    min_severity: Option<&str>,
) -> ScanResult {
    let start = std::time::Instant::now();

    let mut findings: Vec<Finding> = Vec::new();

    let active_phases: Option<Vec<Phase>> =
        phase_filter.map(|names| names.iter().filter_map(|n| phase_from_name(n)).collect());

    let min_sev: Option<Severity> = min_severity.and_then(severity_from_name);

    let should_run_phase = |phase: Phase| -> bool {
        match &active_phases {
            Some(phases) => phases.contains(&phase),
            None => true,
        }
    };

    // Load cloud signatures (if available — gracefully returns empty if offline)
    let cloud_sigs = cloud_sigs::load_cloud_signatures();

    let files = collect_files(path);
    let files_scanned = files.len();

    // When the target is a single file, relative paths must be taken against
    // its parent — otherwise strip_prefix(file) yields "" and filename-gated
    // phases (e.g. install hooks keying on "setup.py") silently never fire.
    let strip_base: &Path = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };

    if should_run_phase(Phase::Provenance) {
        findings.extend(phases::scan_provenance(strip_base, &files));
    }

    // Content phases run per-file in parallel; collect() preserves file order
    // so results stay deterministic.
    let per_file: Vec<Vec<Finding>> = files
        .par_iter()
        .map(|file_path| {
            let contents = match std::fs::metadata(file_path) {
                Ok(meta) if meta.len() > MAX_CONTENT_SCAN_BYTES => return Vec::new(),
                Ok(_) => match std::fs::read(file_path) {
                    Ok(bytes) => {
                        // Skip binary files (contains null bytes) and use lossy UTF-8
                        if bytes.contains(&0) {
                            return Vec::new();
                        }
                        String::from_utf8_lossy(&bytes).into_owned()
                    }
                    Err(_) => return Vec::new(),
                },
                Err(_) => return Vec::new(),
            };

            let rel_path = file_path
                .strip_prefix(strip_base)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let mut file_findings: Vec<Finding> = Vec::new();

            // Invisible-Unicode inspection runs on the RAW contents, then all
            // pattern phases match against the de-cloaked form so zero-width
            // splitting cannot hide tokens like `eval(` (ADR-0008).
            if should_run_phase(Phase::Obfuscation) {
                file_findings.extend(normalize::inspect_invisible(&rel_path, &contents));
            }
            let contents = normalize::normalize_for_matching(&contents);
            let contents: &str = &contents;

            if should_run_phase(Phase::InstallHooks) {
                file_findings.extend(phases::scan_install_hooks(&rel_path, &contents));
            }
            if should_run_phase(Phase::CodePatterns) {
                file_findings.extend(phases::scan_code_patterns(&rel_path, &contents));
            }
            if should_run_phase(Phase::NetworkExfil) {
                file_findings.extend(phases::scan_network_exfil(&rel_path, &contents));
            }
            if should_run_phase(Phase::Credentials) {
                file_findings.extend(phases::scan_credentials(&rel_path, &contents));
            }
            if should_run_phase(Phase::Obfuscation) {
                file_findings.extend(phases::scan_obfuscation(&rel_path, &contents));
            }
            if should_run_phase(Phase::PromptInjection) {
                file_findings.extend(phases::scan_prompt_injection(&rel_path, &contents));
            }
            if should_run_phase(Phase::SkillSecurity) {
                file_findings.extend(phases::scan_skill_security(&rel_path, &contents));
            }
            if should_run_phase(Phase::InferenceSecurity) {
                file_findings.extend(phases::scan_inference_security(&rel_path, &contents));
            }

            // Apply cloud signatures (from ~/.sigil/signatures.json)
            if !cloud_sigs.is_empty() {
                file_findings.extend(cloud_sigs::scan_with_cloud_signatures(
                    &rel_path,
                    &contents,
                    &cloud_sigs,
                ));
            }
            file_findings
        })
        .collect();

    findings.extend(per_file.into_iter().flatten());

    if let Some(min) = min_sev {
        findings.retain(|f| f.severity >= min);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let score = scoring::calculate_score(&findings);
    let verdict = scoring::determine_verdict(&findings, score);

    ScanResult {
        findings,
        score,
        verdict,
        files_scanned,
        duration_ms,
    }
}

#[cfg(test)]
mod walker_tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "content").unwrap();
    }

    #[test]
    fn excludes_default_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("src/main.js"));
        touch(&root.join("node_modules/evil/index.js"));
        touch(&root.join("target/debug/x.rs"));
        touch(&root.join(".next/server/page.js"));
        touch(&root.join("dist/bundle.js"));

        let files = collect_files(root);
        let rels: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(rels, vec!["src/main.js"]);
    }

    #[test]
    fn walks_dotfiles_but_not_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join(".cursorrules"));
        touch(&root.join(".git/objects/aa/bb"));

        let files = collect_files(root);
        let rels: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(rels, vec![".cursorrules"]);
    }

    #[test]
    fn respects_sigilignore_always() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("keep.js"));
        touch(&root.join("skipped/noise.js"));
        fs::write(root.join(".sigilignore"), "skipped/\n").unwrap();

        let files = collect_files(root);
        let rels: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        assert!(rels.contains(&"keep.js".to_string()));
        assert!(!rels.iter().any(|r| r.starts_with("skipped/")));
    }

    #[test]
    fn gitignore_ignored_without_git_dir_tarball_evasion() {
        // A malicious .gitignore inside an extracted tarball (no .git) must
        // NOT hide files from the scanner.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("payload.js"));
        fs::write(root.join(".gitignore"), "payload.js\n").unwrap();

        let files = collect_files(root);
        let rels: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        assert!(rels.contains(&"payload.js".to_string()));
    }
}

#[cfg(test)]
mod fixtures_tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures")
    }

    #[test]
    fn fixture_corpus_matches_manifest() {
        let root = fixtures_root();
        let manifest_raw = std::fs::read_to_string(root.join("MANIFEST.json"))
            .expect("MANIFEST.json readable");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_raw).expect("MANIFEST.json valid");

        // Disclosure fields are mandatory (CLAUDE.md No Fake Data).
        for key in ["data_source", "sample_size", "limitations"] {
            assert!(manifest.get(key).is_some(), "manifest missing {key}");
        }

        let cases = manifest["cases"].as_array().expect("cases array");
        for case in cases {
            let rel = case["path"].as_str().unwrap();
            let file = root.join(rel);
            // Scan the single fixture file's parent so only it is in scope,
            // then keep findings for this file.
            let result = run_scan(&file, None, None);

            if case.get("expect_clean").and_then(|v| v.as_bool()).unwrap_or(false) {
                assert!(
                    result.findings.is_empty(),
                    "{rel} expected clean, got {:?}",
                    result.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
                );
                continue;
            }

            let want_phase = case["expect_phase"].as_str().unwrap();
            let want_sev = severity_from_name(case["expect_min_severity"].as_str().unwrap())
                .expect("valid severity in manifest");
            let hit = result
                .findings
                .iter()
                .any(|f| format!("{:?}", f.phase) == want_phase && f.severity >= want_sev);
            assert!(
                hit,
                "{rel} expected phase {want_phase} >= {want_sev:?}; got {:?}",
                result
                    .findings
                    .iter()
                    .map(|f| (format!("{:?}", f.phase), f.severity, &f.rule))
                    .collect::<Vec<_>>()
            );
        }
    }
}
