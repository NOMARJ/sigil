pub mod phases;
pub mod scoring;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use walkdir::WalkDir;

/// The six scan phases, each targeting a different threat category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Phase {
    /// Phase 1: Install hooks — setup.py cmdclass, npm postinstall, Makefile targets
    InstallHooks,
    /// Phase 2: Dangerous code patterns — eval, exec, pickle, child_process
    CodePatterns,
    /// Phase 3: Network & exfiltration — outbound HTTP, webhooks, sockets
    NetworkExfil,
    /// Phase 4: Credential access — ENV vars, .aws, SSH keys, API key patterns
    Credentials,
    /// Phase 5: Obfuscation — base64, charCode, hex encoding
    Obfuscation,
    /// Phase 6: Provenance — git history anomalies, binary files, hidden files
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
    /// Which scan phase produced this finding
    pub phase: Phase,
    /// Short rule identifier (e.g. "INSTALL-001")
    pub rule: String,
    /// Severity level
    pub severity: Severity,
    /// File where the finding was detected
    pub file: String,
    /// Line number (1-based), if applicable
    pub line: Option<usize>,
    /// Code snippet or description of the match
    pub snippet: String,
    /// Weight multiplier for scoring (derived from phase)
    pub weight: u32,
}

/// Overall scan verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// No findings at all
    Clean,
    /// Score <= 10 — minor informational findings
    LowRisk,
    /// Score <= 50 — some suspicious patterns
    MediumRisk,
    /// Score <= 100 — likely malicious patterns
    HighRisk,
    /// Score > 100 — almost certainly malicious
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
    /// All findings from every phase
    pub findings: Vec<Finding>,
    /// Aggregated risk score
    pub score: u32,
    /// Overall verdict
    pub verdict: Verdict,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

/// Run all scan phases against the given path and return aggregated results.
///
/// This is the primary entry point for the scanner. It walks the directory tree,
/// reads each file, and runs all six phases against it.
pub fn run_scan(path: &Path) -> ScanResult {
    let start = std::time::Instant::now();

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned: usize = 0;

    // Collect scannable files from the directory tree
    let entries: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // Phase 6 (Provenance) operates on directory-level metadata, so run it first
    findings.extend(phases::scan_provenance(path, &entries));

    // Run file-level phases on each file
    for entry in &entries {
        let file_path = entry.path();
        files_scanned += 1;

        // Read file contents, skip binary / unreadable files
        let contents = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // Phase 1: Install Hooks
        findings.extend(phases::scan_install_hooks(&rel_path, &contents));

        // Phase 2: Code Patterns
        findings.extend(phases::scan_code_patterns(&rel_path, &contents));

        // Phase 3: Network / Exfiltration
        findings.extend(phases::scan_network_exfil(&rel_path, &contents));

        // Phase 4: Credentials
        findings.extend(phases::scan_credentials(&rel_path, &contents));

        // Phase 5: Obfuscation
        findings.extend(phases::scan_obfuscation(&rel_path, &contents));
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    // Score and verdict
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
