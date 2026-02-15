pub mod phases;
pub mod scoring;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use walkdir::WalkDir;

/// The six scan phases, each targeting a different threat category.
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

/// Overall scan verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    LowRisk,
    MediumRisk,
    HighRisk,
    Critical,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::LowRisk => write!(f, "LOW RISK"),
            Verdict::MediumRisk => write!(f, "MEDIUM RISK"),
            Verdict::HighRisk => write!(f, "HIGH RISK"),
            Verdict::Critical => write!(f, "CRITICAL"),
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

pub fn run_scan(
    path: &Path,
    phase_filter: Option<&[String]>,
    min_severity: Option<&str>,
) -> ScanResult {
    let start = std::time::Instant::now();

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: usize = 0;

    let active_phases: Option<Vec<Phase>> = phase_filter.map(|names| {
        names.iter().filter_map(|n| phase_from_name(n)).collect()
    });

    let min_sev: Option<Severity> = min_severity.and_then(severity_from_name);

    let should_run_phase = |phase: Phase| -> bool {
        match &active_phases {
            Some(phases) => phases.contains(&phase),
            None => true,
        }
    };

    let entries: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    if should_run_phase(Phase::Provenance) {
        findings.extend(phases::scan_provenance(path, &entries));
    }

    for entry in &entries {
        let file_path = entry.path();
        files_scanned += 1;

        let contents = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if should_run_phase(Phase::InstallHooks) {
            findings.extend(phases::scan_install_hooks(&rel_path, &contents));
        }
        if should_run_phase(Phase::CodePatterns) {
            findings.extend(phases::scan_code_patterns(&rel_path, &contents));
        }
        if should_run_phase(Phase::NetworkExfil) {
            findings.extend(phases::scan_network_exfil(&rel_path, &contents));
        }
        if should_run_phase(Phase::Credentials) {
            findings.extend(phases::scan_credentials(&rel_path, &contents));
        }
        if should_run_phase(Phase::Obfuscation) {
            findings.extend(phases::scan_obfuscation(&rel_path, &contents));
        }
    }

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
