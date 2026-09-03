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

        let ext = filename.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
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

    /// If set, suppress when any of these strings appear near the matched line.
    /// This supports formatter-stable review markers on multi-line constructs.
    #[serde(default)]
    pub nearby_contains: Vec<String>,

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
    /// `nearby`      — matched line plus a small following context window
    /// `file_header` — first 1 KB of the file (for header checks)
    pub fn should_suppress(
        &self,
        file_path: &str,
        filename: &str,
        line: &str,
        nearby: &str,
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
            .nearby_contains
            .iter()
            .any(|s| nearby.contains(s.as_str()))
        {
            return true;
        }

        if self
            .file_header_contains
            .iter()
            .any(|s| file_header.contains(s.as_str()))
        {
            return true;
        }

        if self.safe_domains.iter().any(|d| line.contains(d.as_str())) {
            return true;
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Evidence strength
// ---------------------------------------------------------------------------

/// How much a Critical finding from this rule is worth **on its own**.
///
/// A Critical severity says "this is what a compromised package looks like".
/// Some patterns earn that alone — an `INSTALL-003` postinstall that pipes a
/// download into a shell is not something a legitimate package does by
/// accident. Others are Critical because of what they *usually* accompany: a
/// PEM `PRIVATE KEY` armour header is Critical in a published tarball and
/// completely ordinary in `tests/certs/`, and the regex cannot tell the two
/// apart from one line.
///
/// `Corroborate` marks the second kind. Such a rule still reports at Critical
/// and still contributes its full weight to the score; it just cannot, by
/// itself, drive the verdict to `CRITICAL RISK` — see
/// [`crate::scanner::scoring::determine_verdict`], which needs either one
/// `Standalone` Critical or two `Corroborate` Criticals from *different*
/// rules.
///
/// Absent from a rule means [`Evidence::Standalone`], so every existing pack
/// keeps its behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// This rule's Critical finding gates the verdict on its own.
    #[default]
    Standalone,
    /// This rule's Critical finding needs a second, different Critical rule
    /// before the verdict may be `CRITICAL RISK`.
    Corroborate,
}

impl Evidence {
    /// True for the default, so serialization can skip the common case and
    /// keep the finding JSON byte-identical for every rule that does not set
    /// the field.
    pub fn is_standalone(&self) -> bool {
        matches!(self, Evidence::Standalone)
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

    /// Whether a Critical finding from this rule gates the `CRITICAL RISK`
    /// verdict on its own. See [`Evidence`]. Defaults to
    /// [`Evidence::Standalone`]; only meaningful for `severity: "critical"`
    /// rules, and carried onto every finding the rule produces.
    #[serde(default, skip_serializing_if = "Evidence::is_standalone")]
    pub evidence: Evidence,

    /// What to change or verify when this rule fires. Declarative text only;
    /// surfaced next to the finding in JSON, SARIF (`help`) and HTML output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// External references that justify the rule — CWE, MITRE ATT&CK
    /// technique, advisory, or the campaign it was derived from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Behaviour tags (e.g. `"exfiltration"`, `"persistence"`) carried onto
    /// each finding the rule produces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
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

    /// See [`PackRule::remediation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// See [`PackRule::references`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// See [`PackRule::tags`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Correlation rules (post-pass over findings, not over content)
// ---------------------------------------------------------------------------

/// Which findings a correlation rule accepts as a source or a sink.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingSelector {
    /// Rule-id prefixes, e.g. `["CRED-"]`.
    #[serde(default)]
    pub rule_prefixes: Vec<String>,
    /// Exact rule ids, e.g. `["NET-001", "NET-004"]`.
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

impl FindingSelector {
    /// Does this selector accept a finding with this rule id?
    pub fn accepts(&self, rule_id: &str) -> bool {
        self.rule_ids.iter().any(|r| r == rule_id)
            || self
                .rule_prefixes
                .iter()
                .any(|p| rule_id.starts_with(p.as_str()))
    }
}

/// A rule over *findings* rather than over file content: fires when a source
/// finding and a sink finding occur in the same file within a window and
/// the value the source produced reaches the sink's arguments.
///
/// This is the declarative shape of the one thing a line regex cannot say —
/// "a credential read on line 9 is what line 10 sends" — without the engine
/// executing anything: the link is a text identity check between an
/// assignment on the source line and the sink call's argument window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub phase: String,
    pub severity: String,
    pub description: String,
    #[serde(default)]
    pub weight: Option<u32>,
    pub source: FindingSelector,
    pub sink: FindingSelector,
    /// Maximum lines from source to sink (source first, or the same line).
    #[serde(default = "default_window")]
    pub window_lines: usize,
    /// Substrings whose presence in the sink's argument window disqualifies
    /// the link — an auth header is where a key legitimately goes.
    #[serde(default)]
    pub sink_excludes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

fn default_window() -> usize {
    20
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

    /// Finding-correlation rules (post-pass; see [`CorrelationRule`]).
    #[serde(default)]
    pub correlation_rules: Vec<CorrelationRule>,
}
