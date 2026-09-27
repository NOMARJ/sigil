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

    /// Match-local exemptions: a match is exempt when the text around it
    /// fits one of these contexts (see [`MatchContext`]). Unlike the
    /// line-level predicates above, a line is dropped only when *every*
    /// match of the rule on it is exempt, so an exempt match cannot hide a
    /// real one beside it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_context: Vec<MatchContext>,

    /// Match-local exemption by value: a match is exempt when the text its
    /// `(?P<value>...)` group captured matches one of these regexes in full.
    /// Compiled case-sensitively on their own, even when the rule's pattern
    /// is `(?i)`. A rule that lists them must have a `value` group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_matches: Vec<String>,
}

/// The text around one match of a rule, for [`SuppressionPredicates::match_context`].
///
/// The windows are taken around the rule's `(?P<anchor>...)` group, or the
/// whole match when the pattern has none: `before` is matched against at
/// most 120 bytes ending where the anchor starts (anchored at its end),
/// `after` against at most 120 bytes starting where it ends (anchored at its
/// start). Both must match when both are given.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MatchContext {
    /// Regex for the text just before the anchor, matched as `(?:before)$`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Regex for the text just after the anchor, matched as `^(?:after)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// File extensions (no leading dot) this context applies in; empty
    /// means every file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// Pairs of named groups from `before` / `after` whose captured texts
    /// must be equal (the regex crate has no backreferences).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub same: Vec<[String; 2]>,
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
    /// Non-zero switches the sink's window from "the sink line and the lines
    /// after it" to the sink's *statement*, and bounds how far above the sink
    /// that statement (and its set-up lines) may reach. That is for a sink
    /// matched on a keyword argument that sits on its own line at the end of
    /// a call (`verify=False,` under `requests.post(`), whose other arguments
    /// — the headers that carry the token — are above it. The statement is
    /// the lines above that continue into the sink line (each ends with `(`,
    /// `[`, `,`, `\` or a literal's `{`), the sink line, and the lines its
    /// call continues onto; the window adds nearby lines that set up or use
    /// the object the statement works with (see
    /// `scanner::correlate::statement_scope`). A complete statement about
    /// something else is never read. A source on a line of the statement that
    /// starts in the sink line's bracket group, or one nested inside or
    /// around it, is part of the same call and links without naming anything;
    /// a sibling literal is not. In this mode a bound name links only where it
    /// is used as a value, not as a keyword argument's name or an object key.
    /// Default 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub sink_window_before: usize,
    /// A source or sink on a line longer than this many bytes is not linked
    /// (0: no limit). On a minified bundle one line holds a whole program, so
    /// a credential read and an insecure setting on that line say nothing
    /// about each other.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_line_length: usize,
    /// Which occurrences of a bound name in the sink's window link (see
    /// [`NameUses`]). `word` (the default) takes any whole word; `value`
    /// takes only a use of the name as a value, so a keyword argument's name,
    /// an assignment target or an object key that merely repeats it (a call's
    /// `url=` keyword beside a bound `url`) does not link. Every built-in
    /// chain sets `value`. A rule with `sink_window_before` reads names as
    /// `value` whatever this says. `null` (an empty YAML value) is the
    /// default, as a missing field is.
    #[serde(
        default,
        deserialize_with = "null_is_default",
        skip_serializing_if = "NameUses::is_word"
    )]
    pub name_uses: NameUses,
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

/// Which occurrences of a bound name in a sink's window link a correlation
/// rule's source to its sink ([`CorrelationRule::name_uses`]).
///
/// The difference is the names a call gives its parameters. With `url` bound
/// from a credential read (`url = os.environ[...]`) and a later
/// `requests.get(url=base + "/ping")`, the word `url` is in the call, but
/// only as the keyword argument's name: the value sent is `base + "/ping"`.
/// `json={"token": "x"}` beside a bound `token` is the same, with an object
/// key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NameUses {
    /// Links on any whole-word occurrence in the argument window
    /// (`scanner::correlate::contains_word`), keyword names, keys, strings
    /// and comments included. The default: a rule without the field links
    /// this way outside the statement mode.
    #[default]
    Word,
    /// Links only where the sink sends the bound value
    /// (`scanner::correlate::uses_value`; the module documentation has the
    /// whole reading). The window is read as code: comments and string
    /// contents are blanked, what a string interpolates is kept
    /// (`f"{token:>40}"`, `f"{token=}"`, `"${TOKEN:-}"`). An occurrence that
    /// is a keyword argument's name, an assignment or destructuring target,
    /// an object key (`name:` after `{`, `,`, `(`, `;` or at the start of a
    /// line; a quoted `"name":`; not a Python dict key, which is an
    /// expression), a TypeScript member, an attribute of another object, an
    /// export list, a count (`len(token)`), or a parameter of a function the
    /// sink is in, is skipped. Outside the statement mode the window is the
    /// sink's own call, not the lines after it. `data=token`,
    /// `json={"k": token}`, `f"...{token}"`, `token=token`, `{ token }` and a
    /// positional `token` are uses. Only the bound name itself links: a
    /// value computed from it on another line (`encoded = urlencode(data)`)
    /// is not followed (docs/detection/correlation-names.md).
    Value,
}

impl NameUses {
    fn is_word(&self) -> bool {
        *self == NameUses::Word
    }
}

/// A field whose `null` means what leaving it out means: a pack that loaded
/// before the field existed ignored it whatever it held, so `name_uses: null`
/// (or `name_uses:` with nothing after it in YAML) must not refuse the pack.
fn null_is_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

fn default_window() -> usize {
    20
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

// ---------------------------------------------------------------------------
// Engine rules (implemented in Rust, documented in a pack)
// ---------------------------------------------------------------------------

/// A rule whose detection lives in the scanner's Rust code rather than in a
/// regex — checks a pattern cannot express, such as comparing a `.pyc`
/// header with the shipped source or opening a bundled archive.
///
/// The pack entry carries what every rule carries for a reader (title,
/// remediation, references, tags) so these findings are explained exactly
/// like corpus findings in JSON, SARIF and HTML output, and so `sigil diff`
/// can attribute a new finding to a newly added rule. The engine owns the
/// detection and the severity it reports; a test pins the two together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineRule {
    pub id: String,
    pub phase: String,
    pub severity: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Evidence::is_standalone")]
    pub evidence: Evidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
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

    /// Metadata for rules the engine implements in Rust (see [`EngineRule`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_rules: Vec<EngineRule>,

    /// The compiled rules of a YARA file loaded as a custom pack
    /// ([`super::yara`]). Never part of a JSON pack: a YARA pack is read from
    /// `.yar` source, and its signature is detached.
    #[serde(skip)]
    pub yara: Option<std::sync::Arc<super::yara::YaraFile>>,
}

impl SignaturePack {
    /// Every rule id this pack defines, of every kind.
    pub fn rule_ids(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|r| r.id.clone())
            .chain(self.provenance_rules.iter().map(|r| r.id.clone()))
            .chain(self.correlation_rules.iter().map(|r| r.id.clone()))
            .chain(self.engine_rules.iter().map(|r| r.id.clone()))
            .chain(
                self.yara
                    .iter()
                    .flat_map(|y| y.rules.iter().map(|r| r.id.clone())),
            )
            .collect()
    }

    /// How many rules the pack defines, of every kind.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
            + self.provenance_rules.len()
            + self.correlation_rules.len()
            + self.engine_rules.len()
            + self.yara.as_ref().map_or(0, |y| y.rules.len())
    }
}
