//! Declarative signature pack schema.
//!
//! A pack is a JSON document containing rule entries.  No executable code lives
//! here — only regexes and declarative predicates that the engine evaluates.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// File filter predicates — declarative, no exec code
// ---------------------------------------------------------------------------

/// Restricts which files a rule applies to.
/// An absent field means "all files".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileFilter {
    /// Exact filenames that must match (e.g. `["setup.py", "package.json"]`).
    #[serde(default)]
    pub filename_exact: Vec<String>,

    /// File extensions that must match, without leading dot (e.g. `["py", "js"]`).
    #[serde(default)]
    pub extensions: Vec<String>,

    /// Filename suffix patterns (e.g. `[".mcp.yaml", ".mcp.yml"]`).
    #[serde(default)]
    pub filename_suffix: Vec<String>,
}

impl FileFilter {
    /// Returns `true` when the filter is empty (matches every file).
    pub fn is_empty(&self) -> bool {
        self.filename_exact.is_empty()
            && self.extensions.is_empty()
            && self.filename_suffix.is_empty()
    }

    /// Returns `true` when *filename* (basename) passes this filter.
    pub fn matches(&self, filename: &str) -> bool {
        if self.is_empty() {
            return true;
        }

        if self.filename_exact.iter().any(|n| n == filename) {
            return true;
        }

        let ext = filename
            .rsplit_once('.')
            .map(|(_, e)| e)
            .unwrap_or("");
        if !ext.is_empty() && self.extensions.iter().any(|e| e == ext) {
            return true;
        }

        if self
            .filename_suffix
            .iter()
            .any(|s| filename.ends_with(s.as_str()))
        {
            return true;
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Suppression predicates
// ---------------------------------------------------------------------------

/// Declarative predicates that suppress a finding when matched.
/// Evaluated after a regex match — if any predicate fires, the finding is
/// discarded.  No executable code; all predicates are pure pattern checks.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuppressionPredicates {
    /// Path fragments that suppress the finding (e.g. `"node_modules/"` for
    /// vendor paths).
    #[serde(default)]
    pub path_contains: Vec<String>,

    /// Filename suffixes that suppress the finding (e.g. `".min.js"`).
    #[serde(default)]
    pub filename_suffix: Vec<String>,

    /// If set, suppress when the matched *line* contains any of these substrings.
    #[serde(default)]
    pub line_contains: Vec<String>,

    /// If set, suppress when any of these strings appear in the first `n` bytes
    /// of the file.  Used for UMD-wrapper / polyfill header detection.
    #[serde(default)]
    pub file_header_contains: Vec<String>,

    /// Safe-domain list: suppress when the matched line also contains one of
    /// these domain strings.
    #[serde(default)]
    pub safe_domains: Vec<String>,
}

impl SuppressionPredicates {
    /// Returns `true` when the finding should be suppressed.
    ///
    /// `file_path`   — relative path of the scanned file
    /// `filename`    — basename of the scanned file
    /// `line`        — the matched line text
    /// `file_header` — first 1 KB of the file (for header checks)
    pub fn should_suppress(
        &self,
        file_path: &str,
        filename: &str,
        line: &str,
        file_header: &str,
    ) -> bool {
        if self
            .path_contains
            .iter()
            .any(|p| file_path.contains(p.as_str()))
        {
            return true;
        }

        if self
            .filename_suffix
            .iter()
            .any(|s| filename.ends_with(s.as_str()))
        {
            return true;
        }

        if self.line_contains.iter().any(|s| line.contains(s.as_str())) {
            return true;
        }

        if self
            .file_header_contains
            .iter()
            .any(|s| file_header.contains(s.as_str()))
        {
            return true;
        }

        if self
            .safe_domains
            .iter()
            .any(|d| line.contains(d.as_str()))
        {
            return true;
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Rule entry
// ---------------------------------------------------------------------------

/// A single detection rule in a pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackRule {
    /// Unique rule identifier, e.g. `"CODE-001"`.
    pub id: String,

    /// Target phase name: `"install_hooks"`, `"code_patterns"`, `"network_exfil"`,
    /// `"credentials"`, `"obfuscation"`, `"prompt_injection"`,
    /// `"skill_security"`, `"inference_security"`.
    /// Phase 6 (`"provenance"`) rules use a separate entry type — see [`ProvenanceRule`].
    pub phase: String,

    /// Severity: `"low"`, `"medium"`, `"high"`, `"critical"`.
    pub severity: String,

    /// ECMAScript-compatible regex string (compiled with the `regex` crate).
    pub pattern: String,

    /// Human-readable description used as the finding snippet prefix.
    pub description: String,

    /// Phase scoring weight (integer).  Defaults to the phase-level weight
    /// when absent — kept here for explicit overrides.
    #[serde(default)]
    pub weight: Option<u32>,

    /// Optional file filter.  When absent, rule applies to all files.
    #[serde(default)]
    pub file_filter: FileFilter,

    /// Optional suppression predicates.
    #[serde(default)]
    pub suppress: SuppressionPredicates,
}

// ---------------------------------------------------------------------------
// Provenance rule (filename / metadata based, not content-line based)
// ---------------------------------------------------------------------------

/// Detection kind for a provenance rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// Match on the filename (basename) using a regex.
    FilenameRegex,
    /// Match if the filename starts with `.` (dotfile).
    HiddenFile,
    /// Match if the file has a known binary extension.
    BinaryExtension,
    /// Match if the file size exceeds a threshold in bytes.
    FileSizeBytes,
}

/// A provenance rule that operates on filesystem metadata rather than file content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRule {
    pub id: String,
    pub severity: String,
    pub description: String,
    pub kind: ProvenanceKind,

    /// Regex string (required for `FilenameRegex` kind).
    #[serde(default)]
    pub pattern: Option<String>,

    /// Threshold in bytes (required for `FileSizeBytes` kind).
    #[serde(default)]
    pub size_threshold: Option<u64>,

    /// List of path prefixes under which binary files are *expected* and thus
    /// suppressed (for `BinaryExtension` kind).
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,

    /// Filenames that should be excluded from `HiddenFile` matching (e.g. known
    /// safe dotfiles like `.gitignore`).
    #[serde(default)]
    pub excluded_filenames: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pack metadata
// ---------------------------------------------------------------------------

/// Metadata block at the top of a pack file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMeta {
    /// Pack identifier, e.g. `"sigil-core"`.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// ISO-8601 date of last modification.
    pub updated_at: String,
    /// Pack author or publisher.
    pub author: String,
    /// Short description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Top-level pack document
// ---------------------------------------------------------------------------

/// A complete signature pack as stored in `packs/core/v1/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePack {
    pub meta: PackMeta,

    /// Content-scanning rules (phases 1-2, 4-5, 7-8, 10).
    #[serde(default)]
    pub rules: Vec<PackRule>,

    /// Filesystem-metadata rules (phase 6 provenance).
    #[serde(default)]
    pub provenance_rules: Vec<ProvenanceRule>,
}
