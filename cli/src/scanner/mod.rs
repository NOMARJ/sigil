pub mod cloud_sigs;
pub mod context;
pub mod derive;
pub mod normalize;
pub mod phases;
pub mod profile;
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

impl Phase {
    /// Every phase, in canonical scan order.
    ///
    /// This is the single enumeration of phases in the codebase. Anything that
    /// needs to iterate phases, or that needs to prove it handles all of them,
    /// goes through here — see `phase_registry_is_total` in the tests below.
    pub const ALL: [Phase; 9] = [
        Phase::InstallHooks,
        Phase::CodePatterns,
        Phase::NetworkExfil,
        Phase::Credentials,
        Phase::Obfuscation,
        Phase::Provenance,
        Phase::PromptInjection,
        Phase::SkillSecurity,
        Phase::InferenceSecurity,
    ];

    /// The canonical `snake_case` identifier, as used in signature packs,
    /// cloud signatures and the `--phases` CLI flag.
    pub fn canonical_name(self) -> &'static str {
        match self {
            Phase::InstallHooks => "install_hooks",
            Phase::CodePatterns => "code_patterns",
            Phase::NetworkExfil => "network_exfil",
            Phase::Credentials => "credentials",
            Phase::Obfuscation => "obfuscation",
            Phase::Provenance => "provenance",
            Phase::PromptInjection => "prompt_injection",
            Phase::SkillSecurity => "skill_security",
            Phase::InferenceSecurity => "inference_security",
        }
    }

    /// The human-readable label used in terminal output.
    pub fn display_name(self) -> &'static str {
        match self {
            Phase::InstallHooks => "Install Hooks",
            Phase::CodePatterns => "Code Patterns",
            Phase::NetworkExfil => "Network/Exfil",
            Phase::Credentials => "Credentials",
            Phase::Obfuscation => "Obfuscation",
            Phase::Provenance => "Provenance",
            Phase::PromptInjection => "Prompt Injection",
            Phase::SkillSecurity => "Skill Security",
            Phase::InferenceSecurity => "Inference Security",
        }
    }

    /// The phase's severity-weight multiplier.
    ///
    /// Provenance findings carry per-finding weights (1–3) and override this.
    pub fn default_weight(self) -> u32 {
        match self {
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

    /// Parse a phase name, accepting `snake_case`, `kebab-case` and
    /// `concatenated` spellings, case-insensitively.
    ///
    /// Returns `None` for an unrecognised name. Callers must decide what an
    /// unknown phase means for them — silently defaulting to a real phase
    /// gives a rule the wrong weight and files it under the wrong heading.
    pub fn from_name(name: &str) -> Option<Phase> {
        let normalized: String = name
            .chars()
            .filter(|c| !matches!(c, '_' | '-' | ' '))
            .flat_map(|c| c.to_lowercase())
            .collect();
        Phase::ALL
            .into_iter()
            .find(|p| p.canonical_name().replace('_', "") == normalized)
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
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
    /// Whether this advisory appears in the CISA Known Exploited Vulnerabilities catalogue.
    /// Only set for OSV-derived findings; defaults to false for all other findings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kev: bool,
    /// FIRST EPSS exploit-probability score (0.0–1.0).
    /// Only set for OSV-derived CVE findings; defaults to 0.0 for all other findings.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub epss: f32,
    /// Content-anchored identity for this finding.
    ///
    /// Deliberately **excludes the line number**: identity keyed on
    /// `(rule, file, line)` makes every finding below an inserted line look
    /// new and resolved at once, which churns `sigil diff` and re-raises
    /// every GitHub Code Scanning alert on any drift. Assigned centrally by
    /// [`assign_fingerprints`] once a result set is complete, because
    /// disambiguating repeats of the same rule and snippet in one file needs
    /// to see all of them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// Where the finding lives when it is inside a container, as a composable
    /// locator: `npm://left-pad-1.3.0.tgz|tar://package/dist/index.js`.
    ///
    /// Modelled on Ghidra's FSRL, which addresses a file inside an archive
    /// inside an image by composing `fstype://path` segments with `|`. `file`
    /// alone points into a temporary extraction directory, which says nothing
    /// about which artifact the finding came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

/// Detect a package that partly matches a published release.
///
/// If several files under a directory are byte-identical to
/// `npm:lodash@4.17.21` and a sibling file is not the published bytes, the
/// tree is a *modified copy* of that release. That is the `event-stream` /
/// `ua-parser-js` shape, and Sigil could not previously observe it at any
/// severity: without something to compare against, a trojanised library is
/// just code.
///
/// Reported as Critical, because the whole point of the known-good corpus is
/// that drift is a finding rather than a suppression.
fn detect_knowngood_drift(
    files: &[PathBuf],
    strip_base: &Path,
    known_good: &crate::knowngood::KnownGood,
    recognised: &std::collections::HashMap<String, (String, String)>,
) -> Vec<Finding> {
    use std::collections::{HashMap, HashSet};

    if recognised.is_empty() {
        return Vec::new();
    }

    // Where each recognised release is rooted in the scanned tree.
    //
    // A recognised file's scanned path ends with its path inside the release
    // (`vendor/leftpad/package/index.js` ends with `package/index.js`), so the
    // prefix is where that release was unpacked. Anchoring on the release's
    // own layout rather than on directory adjacency is what lets drift be
    // detected in a subdirectory of the package.
    let mut roots: HashMap<(String, String), usize> = HashMap::new();
    for (scanned_path, (coordinate, index_path)) in recognised {
        if let Some(prefix) = scanned_path.strip_suffix(index_path.as_str()) {
            *roots
                .entry((coordinate.clone(), prefix.to_string()))
                .or_insert(0) += 1;
        }
    }

    let present: HashSet<&str> = files
        .iter()
        .filter_map(|f| f.strip_prefix(strip_base).ok())
        .filter_map(|p| p.to_str())
        .collect();

    let mut out = Vec::new();
    let mut reported: HashSet<String> = HashSet::new();

    for ((coordinate, root), anchors) in &roots {
        // Require more than one anchor: a single coincidental match (an empty
        // file, a common LICENSE) is not evidence that a tree is that release.
        if *anchors < 2 {
            continue;
        }

        for index_path in known_good.release_paths(coordinate) {
            let expected = format!("{root}{index_path}");
            // Only files the release is supposed to contain, that exist here,
            // and whose bytes are not the published bytes.
            if !present.contains(expected.as_str()) || recognised.contains_key(&expected) {
                continue;
            }
            if !reported.insert(expected.clone()) {
                continue;
            }

            out.push(Finding {
                phase: Phase::Provenance,
                rule: "KNOWNGOOD-DRIFT-001".to_string(),
                severity: Severity::Critical,
                file: expected.clone(),
                line: None,
                snippet: format!(
                    "Modified copy of a published release: {anchors} sibling file(s) match \
                     {coordinate} exactly, but this file differs from the published bytes. \
                     A library that is mostly a known release with local modifications is \
                     the trojanised-dependency shape."
                ),
                weight: 10,
                kev: false,
                epss: 0.0,
                fingerprint: String::new(),
                locator: Some(format!("{coordinate}|file://{expected}")),
            });
        }
    }

    out
}

/// Run every enabled content phase over one unit of content.
///
/// Factored out of the scan loop so the same phase set applies to a file and
/// to anything derived from it. `rel_path` stays the originating file for
/// derived units, so file-filtered rules (a `setup.py`-gated install-hook
/// rule, say) still apply to a payload decoded out of that file.
fn run_phases(
    rel_path: &str,
    contents: &str,
    should_run_phase: &impl Fn(Phase) -> bool,
    cloud_sigs: &[cloud_sigs::CompiledCloudSignature],
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    if should_run_phase(Phase::InstallHooks) {
        out.extend(phases::scan_install_hooks(rel_path, contents));
    }
    if should_run_phase(Phase::CodePatterns) {
        out.extend(phases::scan_code_patterns(rel_path, contents));
    }
    if should_run_phase(Phase::NetworkExfil) {
        out.extend(phases::scan_network_exfil(rel_path, contents));
    }
    if should_run_phase(Phase::Credentials) {
        out.extend(phases::scan_credentials(rel_path, contents));
    }
    if should_run_phase(Phase::Obfuscation) {
        out.extend(phases::scan_obfuscation(rel_path, contents));
    }
    if should_run_phase(Phase::PromptInjection) {
        out.extend(phases::scan_prompt_injection(rel_path, contents));
    }
    if should_run_phase(Phase::SkillSecurity) {
        out.extend(phases::scan_skill_security(rel_path, contents));
    }
    if should_run_phase(Phase::InferenceSecurity) {
        out.extend(phases::scan_inference_security(rel_path, contents));
    }

    // Cloud signatures (from ~/.sigil/signatures.json)
    if !cloud_sigs.is_empty() {
        out.extend(cloud_sigs::scan_with_cloud_signatures(
            rel_path, contents, cloud_sigs,
        ));
    }

    out
}

/// Assign content-anchored fingerprints across a complete result set.
///
/// The fingerprint covers the rule, the file, the normalised snippet, and an
/// occurrence index that distinguishes genuine repeats of the same rule and
/// text within one file. It does not cover the line number, so moving code
/// around a file does not change any finding's identity.
pub fn assign_fingerprints(findings: &mut [Finding]) {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
    for f in findings.iter_mut() {
        let snippet = normalize_snippet(&f.snippet);
        let key = (f.rule.clone(), f.file.clone(), snippet.clone());
        let occurrence = seen.entry(key).or_insert(0);

        let mut hasher = Sha256::new();
        for part in [
            f.rule.as_str(),
            f.file.as_str(),
            snippet.as_str(),
            &occurrence.to_string(),
        ] {
            hasher.update(part.as_bytes());
            hasher.update([0u8]);
        }
        f.fingerprint = format!("{:x}", hasher.finalize())
            .chars()
            .take(32)
            .collect();
        *occurrence += 1;
    }
}

/// Collapse whitespace so reindentation does not change a fingerprint.
fn normalize_snippet(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_zero_f32(v: &f32) -> bool {
    *v == 0.0
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
    /// Findings suppressed by a trust-ledger approval (F-010). Kept in the
    /// result — never silently dropped — but excluded from score, verdict, and
    /// exit code. Suppression is all-or-nothing per artifact (exact-digest
    /// approval), so attribution lives at result level, not per finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed_findings: Vec<Finding>,
    /// Attribution for the suppression, e.g. `ledger:lodash@4.17.20#ab12cd34
    /// approved 2026-06-11`. `None` when nothing is suppressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<String>,
    /// What produced this result: engine version and corpus identity.
    ///
    /// `None` on results written by an older binary, which is why `diff`
    /// degrades gracefully rather than assuming it is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner: Option<ScannerInfo>,
}

/// Provenance of a scan: which engine and which detection corpus ran.
///
/// `cache.rs` already refuses to serve a result produced by a different
/// scanner version, because a stale verdict after a detection upgrade is a
/// security bug. This carries the same discipline into the output contract so
/// consumers — `sigil diff` above all — can tell a code change from a rules
/// change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannerInfo {
    /// The `sigil` binary version that produced the result.
    pub engine_version: String,
    /// Stable digest over every active rule's id and pattern.
    pub corpus_digest: String,
    /// Number of active content rules.
    pub corpus_rule_count: usize,
    /// Every active rule ID, sorted — lets `diff` attribute a new finding to
    /// a newly added rule rather than to changed code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
}

fn phase_from_name(name: &str) -> Option<Phase> {
    Phase::from_name(name)
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
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        if !is_dir {
            return true;
        }
        let name = entry.file_name().to_string_lossy();
        !DEFAULT_EXCLUDED_DIRS.contains(&name.as_ref())
    });
    let mut files: Vec<PathBuf> = builder
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
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

    // Load cloud signatures (if available — gracefully returns empty if
    // offline) and compile them once, not once per file.
    let cloud_sigs = cloud_sigs::compile_cloud_signatures(&cloud_sigs::load_cloud_signatures());

    // Known-good corpus (ADR-0011). Absent by default; a verification failure
    // is fatal, because an index that can suppress findings is a trust input.
    let known_good = match crate::knowngood::load_installed() {
        Ok(kg) => kg,
        Err(e) => {
            eprintln!("[known-good] fatal: {e}");
            std::process::exit(2);
        }
    };

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

            // Analysis is a bounded worklist, not a single pass. A phase that
            // decodes something enqueues the decoded content, and every phase
            // then runs over that too — so a payload hidden inside base64
            // reaches the install-hook, exfiltration and credential rules
            // instead of only tripping one obfuscation rule on its shape.
            let mut budget = derive::DeriveBudget::new();
            let mut queue: Vec<derive::DerivedUnit> = vec![derive::DerivedUnit {
                contents: contents.into_owned(),
                via: String::new(),
                parent_line: 0,
                depth: 0,
            }];

            while let Some(unit) = queue.pop() {
                let unit_findings =
                    run_phases(&rel_path, &unit.contents, &should_run_phase, &cloud_sigs);

                if unit.depth == 0 {
                    file_findings.extend(unit_findings);
                } else {
                    // Re-anchor findings from decoded content onto the line of
                    // the parent file that carried the blob, so a finding still
                    // points at a real line of a real file, and record how the
                    // content was obtained.
                    file_findings.extend(unit_findings.into_iter().map(|mut f| {
                        f.line = Some(unit.parent_line);
                        f.snippet = format!("[decoded {}] {}", unit.via, f.snippet);
                        f.locator = Some(format!("file://{}|{}", rel_path, unit.via));
                        f
                    }));
                }

                for derived in derive::derive_units(&unit.contents, unit.depth, &mut budget) {
                    queue.push(derived);
                }
            }

            file_findings
        })
        .collect();

    findings.extend(per_file.into_iter().flatten());

    if let Some(min) = min_sev {
        findings.retain(|f| f.severity >= min);
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    assign_fingerprints(&mut findings);

    // Known-good recognition (ADR-0011). Findings in files that are
    // byte-identical to published releases move to `suppressed_findings` with
    // attribution — never dropped. Files the corpus does not recognise are
    // scanned and reported exactly as before, so an absent or partial index
    // can only ever reduce noise, never create false confidence.
    let mut suppressed_by_knowngood: Vec<Finding> = Vec::new();
    let mut knowngood_note: Option<String> = None;
    if !known_good.is_empty() {
        let recognised: std::collections::HashMap<String, (String, String)> = files
            .par_iter()
            .filter_map(|p| {
                let bytes = std::fs::read(p).ok()?;
                match known_good.lookup(&bytes) {
                    crate::knowngood::Match::Exact { coordinate, path } => {
                        let rel = p
                            .strip_prefix(strip_base)
                            .unwrap_or(p)
                            .to_string_lossy()
                            .to_string();
                        Some((rel, (coordinate, path)))
                    }
                    crate::knowngood::Match::Unknown => None,
                }
            })
            .collect();

        if !recognised.is_empty() {
            let mut kept = Vec::with_capacity(findings.len());
            for f in findings.into_iter() {
                match recognised.get(&f.file) {
                    Some(_) => suppressed_by_knowngood.push(f),
                    None => kept.push(f),
                }
            }
            findings = kept;

            let mut coords: Vec<&String> = recognised.values().map(|(c, _)| c).collect();
            coords.sort_unstable();
            coords.dedup();
            knowngood_note = Some(format!(
                "known-good: {} file(s) matched {} published release(s) unmodified",
                recognised.len(),
                coords.len()
            ));
        }

        // Drift: a release we partly recognise, where some files are not the
        // published bytes, is the trojanised-dependency shape. This is the
        // detection Sigil could not previously make at any severity.
        findings.extend(detect_knowngood_drift(
            &files,
            strip_base,
            &known_good,
            &recognised,
        ));
        assign_fingerprints(&mut findings);
    }

    let score = scoring::calculate_score(&findings);
    let verdict = scoring::determine_verdict(&findings, score);

    let compiled = crate::corpus::compiled::corpus();
    ScanResult {
        findings,
        score,
        verdict,
        files_scanned,
        duration_ms,
        suppressed_findings: suppressed_by_knowngood,
        suppressed_by: knowngood_note,
        scanner: Some(ScannerInfo {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            corpus_digest: compiled.digest(),
            corpus_rule_count: compiled.rule_count(),
            rule_ids: compiled.rule_ids(),
        }),
    }
}

#[cfg(test)]
mod phase_registry_tests {
    use super::*;

    /// `Phase::ALL` must actually list every variant. If a phase is added to
    /// the enum but not to `ALL`, every consumer that iterates phases silently
    /// skips it — which is the shape of the cloud-signature misfiling bug.
    ///
    /// The match below is exhaustive, so adding a variant fails to compile
    /// until it is handled here, and the assertion then forces it into `ALL`.
    #[test]
    fn phase_registry_is_total() {
        for phase in Phase::ALL {
            // Exhaustive match: a new variant breaks the build here first.
            let expected_in_all = match phase {
                Phase::InstallHooks
                | Phase::CodePatterns
                | Phase::NetworkExfil
                | Phase::Credentials
                | Phase::Obfuscation
                | Phase::Provenance
                | Phase::PromptInjection
                | Phase::SkillSecurity
                | Phase::InferenceSecurity => true,
            };
            assert!(expected_in_all);
        }
        assert_eq!(
            Phase::ALL.len(),
            9,
            "Phase::ALL is out of sync with the Phase enum"
        );
    }

    /// Every phase must round-trip through its own canonical name. This is
    /// what makes a missing parse arm impossible: `Phase::from_name` is
    /// derived from `ALL`, so it cannot omit a phase the way three separate
    /// hand-written `match` blocks could.
    #[test]
    fn every_phase_round_trips_through_its_canonical_name() {
        for phase in Phase::ALL {
            assert_eq!(
                Phase::from_name(phase.canonical_name()),
                Some(phase),
                "{phase} did not round-trip"
            );
        }
    }

    #[test]
    fn from_name_accepts_kebab_and_concatenated_spellings() {
        assert_eq!(
            Phase::from_name("prompt-injection"),
            Some(Phase::PromptInjection)
        );
        assert_eq!(
            Phase::from_name("promptinjection"),
            Some(Phase::PromptInjection)
        );
        assert_eq!(
            Phase::from_name("PROMPT_INJECTION"),
            Some(Phase::PromptInjection)
        );
    }

    #[test]
    fn from_name_rejects_unknown_phases() {
        assert_eq!(Phase::from_name("phase_from_the_future"), None);
        assert_eq!(Phase::from_name(""), None);
    }

    /// Canonical names must be unique, or `from_name` becomes ambiguous.
    #[test]
    fn canonical_names_are_unique() {
        let mut names: Vec<&str> = Phase::ALL.iter().map(|p| p.canonical_name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate canonical phase name");
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
        let manifest_raw =
            std::fs::read_to_string(root.join("MANIFEST.json")).expect("MANIFEST.json readable");
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

            if case
                .get("expect_clean")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
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

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    fn f(rule: &str, file: &str, line: usize, snippet: &str) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity: Severity::High,
            file: file.to_string(),
            line: Some(line),
            snippet: snippet.to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
        }
    }

    /// The whole point: a finding that moves down the file is the same
    /// finding. Keying identity on the line number is what made `sigil diff`
    /// report every finding below an inserted line as new *and* resolved.
    #[test]
    fn fingerprint_survives_line_drift() {
        let mut a = [f("CODE-001", "a.js", 12, "sample rule hit: token-a")];
        let mut b = [f("CODE-001", "a.js", 480, "sample rule hit: token-a")];
        assign_fingerprints(&mut a);
        assign_fingerprints(&mut b);
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
        assert!(!a[0].fingerprint.is_empty());
    }

    /// Reindenting a line must not change its identity either.
    #[test]
    fn fingerprint_survives_reindentation() {
        let mut a = [f("CODE-001", "a.js", 1, "sample rule hit: token-a")];
        let mut b = [f("CODE-001", "a.js", 1, "sample rule hit:      token-a")];
        assign_fingerprints(&mut a);
        assign_fingerprints(&mut b);
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
    }

    #[test]
    fn different_rule_file_or_content_differ() {
        let mut v = [
            f("CODE-001", "a.js", 1, "sample rule hit: token-a"),
            f("CODE-002", "a.js", 1, "sample rule hit: token-a"),
            f("CODE-001", "b.js", 1, "sample rule hit: token-a"),
            f("CODE-001", "a.js", 1, "sample rule hit: token-b"),
        ];
        assign_fingerprints(&mut v);
        let mut fps: Vec<&str> = v.iter().map(|x| x.fingerprint.as_str()).collect();
        fps.sort_unstable();
        let before = fps.len();
        fps.dedup();
        assert_eq!(before, fps.len(), "distinct findings collided: {v:#?}");
    }

    /// Genuine repeats of the same rule and text in one file are still
    /// distinct findings and must not collapse into one fingerprint.
    #[test]
    fn repeated_identical_matches_stay_distinct() {
        let mut v = [
            f("CODE-001", "a.js", 1, "sample rule hit: token-a"),
            f("CODE-001", "a.js", 9, "sample rule hit: token-a"),
            f("CODE-001", "a.js", 40, "sample rule hit: token-a"),
        ];
        assign_fingerprints(&mut v);
        let mut fps: Vec<&str> = v.iter().map(|x| x.fingerprint.as_str()).collect();
        fps.sort_unstable();
        fps.dedup();
        assert_eq!(fps.len(), 3, "repeats collapsed: {v:#?}");
    }

    /// Fingerprints must be stable across runs, or GitHub Code Scanning
    /// re-raises every alert on every scan.
    #[test]
    fn fingerprints_are_deterministic() {
        let build = || {
            let mut v = [
                f("CODE-001", "a.js", 1, "sample rule hit: token-a"),
                f("NET-012", "b.sh", 4, "sample rule hit: token-c"),
            ];
            assign_fingerprints(&mut v);
            v
        };
        let a = build();
        let b = build();
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
        assert_eq!(a[1].fingerprint, b[1].fingerprint);
    }
}
