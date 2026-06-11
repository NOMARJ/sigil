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
            !(e.file_type().is_dir()
                && e.file_name().to_str().map_or(false, is_excluded_dir))
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
    let json =
        serde_json::to_string_pretty(records).map_err(|e| format!("failed to serialize ledger: {}", e))?;
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

// Default-location wrappers used by the CLI.

pub fn record_approval(entry: &QuarantineEntry, reason: Option<&str>) -> Result<LedgerRecord, String> {
    record_approval_in(&ledger_dir(), entry, reason)
}

pub fn get(id: &str) -> Option<LedgerRecord> {
    get_in(&ledger_dir(), id)
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
        assert_eq!(a.artifact_digest, b.artifact_digest, "pin must be deterministic");
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
        assert_eq!(version_from_source("lodash@4.17.20", "npm"), Some("4.17.20".to_string()));
        assert_eq!(
            version_from_source("@scope/pkg@1.2.3", "npm"),
            Some("1.2.3".to_string())
        );
        assert_eq!(version_from_source("lodash", "npm"), None);
        assert_eq!(version_from_source("requests==2.31.0", "pip"), Some("2.31.0".to_string()));
        assert_eq!(version_from_source("https://github.com/x/y", "git"), None);
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
