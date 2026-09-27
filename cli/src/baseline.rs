//! Baselines: accept the findings a project has today, fail only on new ones.
//!
//! `sigil baseline <path>` records every active finding; `sigil scan
//! --baseline FILE` (or a policy's `baseline:` key) moves the findings that
//! match it out of the score, verdict and exit code — into the report's
//! `policy.suppressed` list and SARIF `suppressions` (`kind: external`), never
//! out of sight. It follows the model of inline `sigil:ignore` markers
//! (`scanner::suppress`), applied from a file instead of the source.
//!
//! # Identity
//!
//! A baseline entry matches by the finding's content-anchored fingerprint
//! (`scanner::assign_fingerprints`: rule, file, normalised snippet and an
//! occurrence index — **not** the line number), so inserting code above a
//! baselined finding does not resurrect it, and a second copy of the same
//! line is a new finding. Each entry is consumed once. Entries that stop
//! matching are reported as stale.
//!
//! As a fallback an entry also matches on `(rule, file, snippet_hash)`, where
//! the snippet hash is taken over the matched line *without* the rule's
//! description prefix, so editing a rule's wording in a Sigil upgrade does not
//! invalidate every baseline written before it.
//!
//! The file stores hashes, not snippets: a baseline committed to a repository
//! does not itself contain the attack strings it accepts.
//!
//! # Glob rules
//!
//! A baseline may also carry hand-written rules — `rule`, `path` and
//! `message` globs, all of which must match, with a mandatory `reason` and an
//! optional `expires` date after which the rule stops suppressing:
//!
//! ```yaml
//! rules:
//!   - rule: "NET-012"
//!     path: "scripts/install/**"
//!     reason: "installer downloads pinned release assets over TLS (SEC-1234)"
//!     expires: 2027-01-31
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::project_config::{rule_glob_matches, text_glob_matches, PathGlobs};
use crate::scanner::{normalize_snippet, Finding, ScanResult};

pub const BASELINE_KIND: &str = "sigil-baseline";
pub const BASELINE_VERSION: u32 = 1;
/// Default file name written by `sigil baseline`.
pub const DEFAULT_BASELINE_FILE: &str = ".sigil-baseline.json";
/// Largest baseline file read.
const MAX_BASELINE_BYTES: u64 = 64 * 1024 * 1024;

/// The on-disk baseline document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(default)]
    pub kind: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub sigil_version: String,
    #[serde(default)]
    pub created_at: String,
    /// The scan target the entries' paths are relative to.
    #[serde(default)]
    pub target: String,
    /// Corpus the findings were recorded under.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub corpus_digest: String,
    /// Why these findings were accepted (applies to every entry without its
    /// own reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub findings: Vec<BaselineEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<GlobRule>,
}

fn default_version() -> u32 {
    BASELINE_VERSION
}

/// One accepted finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule: String,
    pub file: String,
    /// Informational: matching never uses the line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub snippet_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A hand-written suppression: every glob given must match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRule {
    /// Rule-id glob, e.g. `NET-*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Path glob in `.sigilignore` (gitignore) syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Case-insensitive glob over the finding message (`*` any text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub reason: String,
    /// `YYYY-MM-DD`: the rule stops suppressing after this date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// A loaded, validated baseline ready to match findings.
pub struct Baseline {
    file: BaselineFile,
    rule_paths: Vec<Option<PathGlobs>>,
    expired: Vec<bool>,
}

/// The matched text of a finding: its whitespace-normalised snippet without
/// the rule's description prefix.
///
/// `CompiledCorpus::scan_phase` writes `"{description}: {line}"`. Stripping
/// the description the *current* corpus uses leaves the line itself, which
/// does not change when a rule's wording does. A decoded-content marker in
/// front (`[decoded base64] …`) is kept: it is part of what was matched.
pub fn matched_text(f: &Finding) -> String {
    let snippet = normalize_snippet(&f.snippet);
    crate::corpus::compiled::corpus()
        .rule_meta(&f.rule)
        .map(|m| normalize_snippet(&m.title))
        .and_then(|title| {
            let prefix = format!("{title}: ");
            snippet.find(&prefix).map(|i| {
                let mut s = snippet[..i].to_string();
                s.push_str(&snippet[i + prefix.len()..]);
                s
            })
        })
        .unwrap_or(snippet)
}

/// Hash of the matched text (see [`matched_text`]), rule and file.
pub fn snippet_hash(f: &Finding) -> String {
    let body = matched_text(f);
    let mut h = Sha256::new();
    for part in [f.rule.as_str(), f.file.as_str(), body.as_str()] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    format!("{:x}", h.finalize()).chars().take(32).collect()
}

impl BaselineFile {
    /// Record every active finding of a scan.
    pub fn from_result(result: &ScanResult, target: &str, reason: Option<String>) -> Self {
        let mut findings: Vec<BaselineEntry> = result
            .findings
            .iter()
            .map(|f| BaselineEntry {
                rule: f.rule.clone(),
                file: f.file.clone(),
                line: f.line,
                severity: f.severity.to_string(),
                fingerprint: f.fingerprint.clone(),
                snippet_hash: snippet_hash(f),
                reason: None,
            })
            .collect();
        // Stable order so a regenerated baseline diffs cleanly in review.
        findings.sort_by(|a, b| {
            (&a.file, &a.rule, a.line, &a.fingerprint).cmp(&(
                &b.file,
                &b.rule,
                b.line,
                &b.fingerprint,
            ))
        });
        BaselineFile {
            kind: BASELINE_KIND.to_string(),
            version: BASELINE_VERSION,
            sigil_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            target: target.to_string(),
            corpus_digest: result
                .scanner
                .as_ref()
                .map(|s| s.corpus_digest.clone())
                .unwrap_or_default(),
            reason,
            findings,
            rules: Vec::new(),
        }
    }
}

impl Baseline {
    /// Read a baseline: a file written by `sigil baseline` (JSON or YAML), a
    /// hand-written YAML file of glob `rules`, or a `sigil scan -f json`
    /// report (whose findings are then the accepted set).
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("{}: cannot read baseline: {e}", path.display()))?;
        if meta.len() > MAX_BASELINE_BYTES {
            return Err(format!(
                "{}: baseline is {} bytes; the limit is {MAX_BASELINE_BYTES}",
                path.display(),
                meta.len()
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: cannot read baseline: {e}", path.display()))?;
        Self::parse(&text, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str, path: &Path) -> Result<Self, String> {
        let yaml = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        );
        let value: serde_json::Value = if yaml {
            let y: serde_yaml::Value =
                serde_yaml::from_str(text).map_err(|e| format!("YAML parse error: {e}"))?;
            serde_json::to_value(y).map_err(|e| e.to_string())?
        } else {
            serde_json::from_str(text).map_err(|e| format!("JSON parse error: {e}"))?
        };

        let file = if value.get("summary").is_some() && value.get("kind").is_none() {
            // A scan report: accept its findings as they stand.
            let result = crate::diff::parse_baseline(text)?;
            let mut f = BaselineFile::from_result(
                &result,
                "",
                Some(format!("accepted from scan report {}", path.display())),
            );
            // Keep the report's own fingerprints (from_result copies them) but
            // not a creation time it never had.
            f.created_at = String::new();
            f
        } else {
            let kind = value.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            if !kind.is_empty() && kind != BASELINE_KIND {
                return Err(format!(
                    "kind '{kind}' is not a Sigil baseline (expected '{BASELINE_KIND}'; create one with `sigil baseline`)"
                ));
            }
            if value.get("findings").is_none() && value.get("rules").is_none() {
                return Err(
                    "not a baseline: no `findings` or `rules` (create one with `sigil baseline`)"
                        .to_string(),
                );
            }
            serde_json::from_value::<BaselineFile>(value).map_err(|e| e.to_string())?
        };
        if file.version > BASELINE_VERSION {
            return Err(format!(
                "baseline version {} was written by a newer Sigil (this one reads {BASELINE_VERSION})",
                file.version
            ));
        }
        Self::from_file(file)
    }

    fn from_file(file: BaselineFile) -> Result<Self, String> {
        let today = chrono::Utc::now().date_naive();
        let mut errors = Vec::new();
        let mut rule_paths = Vec::new();
        let mut expired = Vec::new();
        for (i, r) in file.rules.iter().enumerate() {
            let label = format!("rules[{i}]");
            if r.reason.trim().is_empty() {
                errors.push(format!("{label}: every glob rule needs a non-empty reason"));
            }
            let given: Vec<&String> = [&r.rule, &r.path, &r.message]
                .into_iter()
                .flatten()
                .collect();
            if given.is_empty() {
                errors.push(format!(
                    "{label}: give at least one of rule, path, message (an empty rule would suppress everything)"
                ));
            } else if given
                .iter()
                .all(|g| g.chars().all(|c| c == '*' || c == '/'))
            {
                errors.push(format!(
                    "{label}: every glob is match-all, which would suppress every finding"
                ));
            }
            rule_paths.push(match &r.path {
                Some(p) => match PathGlobs::new(std::slice::from_ref(p)) {
                    Ok(g) => Some(g),
                    Err(e) => {
                        errors.push(format!("{label}: path '{p}': {e}"));
                        None
                    }
                },
                None => None,
            });
            expired.push(match &r.expires {
                Some(d) => match chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d") {
                    Ok(date) => date < today,
                    Err(_) => {
                        errors.push(format!("{label}: expires '{d}' is not a YYYY-MM-DD date"));
                        false
                    }
                },
                None => false,
            });
        }
        for (i, e) in file.findings.iter().enumerate() {
            if e.rule.is_empty() || e.file.is_empty() {
                errors.push(format!("findings[{i}]: rule and file are required"));
            }
            if e.fingerprint.is_empty() && e.snippet_hash.is_empty() {
                errors.push(format!(
                    "findings[{i}] ({}): needs a fingerprint or snippet_hash",
                    e.rule
                ));
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }
        Ok(Baseline {
            file,
            rule_paths,
            expired,
        })
    }

    pub fn entry_count(&self) -> usize {
        self.file.findings.len()
    }

    pub fn rule_count(&self) -> usize {
        self.file.rules.len()
    }

    /// Split findings into (kept, suppressed with reason, notes).
    pub fn partition(
        &self,
        findings: Vec<Finding>,
    ) -> (Vec<Finding>, Vec<(Finding, String)>, Vec<String>) {
        let default_reason = self
            .file
            .reason
            .clone()
            .unwrap_or_else(|| "accepted in baseline".to_string());
        let reason_of =
            |e: &BaselineEntry| e.reason.clone().unwrap_or_else(|| default_reason.clone());

        // Unconsumed entries, by fingerprint and by fallback key.
        let fallback_key = |rule: &str, file: &str, hash: &str| format!("{rule}\0{file}\0{hash}");
        let mut by_fp: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in self.file.findings.iter().enumerate() {
            if !e.fingerprint.is_empty() {
                by_fp.entry(e.fingerprint.as_str()).or_default().push(i);
            }
            if !e.snippet_hash.is_empty() {
                by_key
                    .entry(fallback_key(&e.rule, &e.file, &e.snippet_hash))
                    .or_default()
                    .push(i);
            }
        }
        let mut consumed = vec![false; self.file.findings.len()];

        let mut kept = Vec::new();
        let mut suppressed = Vec::new();
        let mut rule_hits = vec![0usize; self.file.rules.len()];
        for f in findings {
            let mut hit = take_unconsumed(by_fp.get_mut(f.fingerprint.as_str()), &mut consumed);
            if hit.is_none() {
                let key = fallback_key(&f.rule, &f.file, &snippet_hash(&f));
                hit = take_unconsumed(by_key.get_mut(&key), &mut consumed);
            }
            if let Some(i) = hit {
                let reason = reason_of(&self.file.findings[i]);
                suppressed.push((f, reason));
                continue;
            }
            if let Some(ri) = self.matching_rule(&f) {
                rule_hits[ri] += 1;
                let r = &self.file.rules[ri];
                suppressed.push((f, format!("rule {}: {}", describe_rule(r), r.reason)));
                continue;
            }
            kept.push(f);
        }

        let mut notes = Vec::new();
        let stale = consumed.iter().filter(|c| !**c).count();
        if stale > 0 {
            notes.push(format!(
                "{stale} of {} baseline entr{} no longer match a finding (fixed or changed); \
                 regenerate with `sigil baseline` to prune",
                self.file.findings.len(),
                if stale == 1 { "y" } else { "ies" }
            ));
        }
        for (i, r) in self.file.rules.iter().enumerate() {
            if self.expired[i] {
                notes.push(format!(
                    "rule {} expired on {} and no longer suppresses",
                    describe_rule(r),
                    r.expires.as_deref().unwrap_or("")
                ));
            } else if rule_hits[i] == 0 {
                notes.push(format!(
                    "rule {} matched no finding; remove it if what it covered is gone",
                    describe_rule(r)
                ));
            }
        }
        (kept, suppressed, notes)
    }

    fn matching_rule(&self, f: &Finding) -> Option<usize> {
        self.file.rules.iter().enumerate().find_map(|(i, r)| {
            if self.expired[i] {
                return None;
            }
            let rule_ok = r
                .rule
                .as_ref()
                .is_none_or(|g| rule_glob_matches(g, &f.rule));
            let path_ok = match (&r.path, &self.rule_paths[i]) {
                (Some(_), Some(globs)) => globs.matching(&f.file).is_some(),
                (Some(_), None) => false,
                (None, _) => true,
            };
            let msg_ok = r
                .message
                .as_ref()
                .is_none_or(|g| text_glob_matches(g, &f.snippet));
            (rule_ok && path_ok && msg_ok).then_some(i)
        })
    }
}

/// Pop the first entry index not yet consumed. Each baseline entry accepts
/// exactly one finding.
fn take_unconsumed(idxs: Option<&mut Vec<usize>>, consumed: &mut [bool]) -> Option<usize> {
    let idxs = idxs?;
    while let Some(i) = idxs.pop() {
        if !consumed[i] {
            consumed[i] = true;
            return Some(i);
        }
    }
    None
}

fn describe_rule(r: &GlobRule) -> String {
    let mut parts = Vec::new();
    if let Some(v) = &r.rule {
        parts.push(format!("rule={v}"));
    }
    if let Some(v) = &r.path {
        parts.push(format!("path={v}"));
    }
    if let Some(v) = &r.message {
        parts.push(format!("message={v}"));
    }
    format!("[{}]", parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{assign_fingerprints, Phase, Severity};

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

    fn result(mut findings: Vec<Finding>) -> ScanResult {
        assign_fingerprints(&mut findings);
        ScanResult {
            findings,
            score: 0,
            verdict: crate::scanner::Verdict::LowRisk,
            files_scanned: 1,
            duration_ms: 0,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
            scanner: None,
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            platform: String::new(),
        }
    }

    fn roundtrip(file: &BaselineFile) -> Baseline {
        let text = serde_json::to_string(file).unwrap();
        Baseline::parse(&text, Path::new("b.json")).expect("baseline parses")
    }

    #[test]
    fn only_new_findings_survive_and_line_drift_does_not_matter() {
        let old = result(vec![
            f("R-1", "a.py", 3, "x: one"),
            f("R-2", "b.py", 9, "y: two"),
        ]);
        let bl = roundtrip(&BaselineFile::from_result(
            &old,
            ".",
            Some("adopted".into()),
        ));

        // Same findings moved down the file, plus one genuinely new one.
        let now = result(vec![
            f("R-1", "a.py", 30, "x: one"),
            f("R-2", "b.py", 90, "y: two"),
            f("R-1", "a.py", 31, "x: three"),
        ])
        .findings;
        let (kept, suppressed, notes) = bl.partition(now);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].snippet, "x: three");
        assert_eq!(suppressed.len(), 2);
        assert!(suppressed.iter().all(|(_, r)| r == "adopted"));
        assert!(notes.is_empty(), "{notes:?}");
    }

    /// Each entry is consumed once: a second copy of an accepted line is new.
    #[test]
    fn a_duplicated_accepted_line_is_still_new() {
        let old = result(vec![f("R-1", "a.py", 3, "x: same")]);
        let bl = roundtrip(&BaselineFile::from_result(&old, ".", None));
        let now = result(vec![
            f("R-1", "a.py", 3, "x: same"),
            f("R-1", "a.py", 4, "x: same"),
        ])
        .findings;
        let (kept, suppressed, _) = bl.partition(now);
        assert_eq!((kept.len(), suppressed.len()), (1, 1));
    }

    #[test]
    fn fixed_findings_are_reported_as_stale_entries() {
        let old = result(vec![
            f("R-1", "a.py", 3, "x: gone"),
            f("R-2", "a.py", 4, "x: kept"),
        ]);
        let bl = roundtrip(&BaselineFile::from_result(&old, ".", None));
        let (_, suppressed, notes) =
            bl.partition(result(vec![f("R-2", "a.py", 4, "x: kept")]).findings);
        assert_eq!(suppressed.len(), 1);
        assert!(notes[0].starts_with("1 of 2 baseline entry"), "{notes:?}");
    }

    #[test]
    fn the_fallback_key_survives_a_fingerprint_change() {
        let old = result(vec![f("R-1", "a.py", 3, "x: body")]);
        let mut file = BaselineFile::from_result(&old, ".", None);
        file.findings[0].fingerprint = "0000".into();
        let bl = roundtrip(&file);
        let (kept, suppressed, _) =
            bl.partition(result(vec![f("R-1", "a.py", 3, "x: body")]).findings);
        assert!(kept.is_empty());
        assert_eq!(suppressed.len(), 1);
    }

    #[test]
    fn glob_rules_need_a_reason_and_honour_expiry() {
        let yaml = r#"
rules:
  - rule: "NET-*"
    path: "scripts/"
    reason: "installer fetches pinned assets"
  - message: "*telemetry*"
    reason: "opt-in telemetry"
    expires: 2000-01-01
"#;
        let bl = Baseline::parse(yaml, Path::new("b.yaml")).expect("parses");
        let findings = vec![
            f("NET-012", "scripts/install.sh", 1, "fetch: get https://x"),
            f("NET-012", "src/x.sh", 1, "fetch: get https://x"),
            f("NET-004", "src/t.js", 1, "fetch: telemetry endpoint"),
        ];
        let (kept, suppressed, notes) = bl.partition(findings);
        assert_eq!(suppressed.len(), 1);
        assert!(suppressed[0].1.contains("installer fetches pinned assets"));
        assert_eq!(
            kept.len(),
            2,
            "the expired telemetry rule no longer suppresses"
        );
        assert!(notes.iter().any(|n| n.contains("expired on 2000-01-01")));

        for bad in [
            "rules:\n  - rule: NET-*\n    reason: ''\n",
            "rules:\n  - reason: everything\n",
            "rules:\n  - message: '*'\n    reason: r\n",
            "rules:\n  - rule: X-1\n    reason: r\n    expires: tomorrow\n",
        ] {
            assert!(Baseline::parse(bad, Path::new("b.yaml")).is_err(), "{bad}");
        }
    }

    #[test]
    fn foreign_documents_are_refused_with_a_hint() {
        let err = Baseline::parse(r#"{"kind":"residue","items":[]}"#, Path::new("r.json"))
            .err()
            .unwrap();
        assert!(err.contains("not a Sigil baseline"), "{err}");
        let err = Baseline::parse(r#"{"hello":1}"#, Path::new("x.json"))
            .err()
            .unwrap();
        assert!(err.contains("sigil baseline"), "{err}");
        let newer = r#"{"kind":"sigil-baseline","version":99,"findings":[]}"#;
        assert!(Baseline::parse(newer, Path::new("n.json"))
            .err()
            .unwrap()
            .contains("newer"));
    }

    #[test]
    fn a_scan_report_can_serve_as_a_baseline() {
        let old = result(vec![f("R-1", "a.py", 3, "x: one")]);
        let doc = crate::output::scan_result_document(&old);
        let bl =
            Baseline::parse(&doc.to_string(), Path::new("scan.json")).expect("report accepted");
        assert_eq!(bl.entry_count(), 1);
        let (kept, _, _) = bl.partition(result(vec![f("R-1", "a.py", 7, "x: one")]).findings);
        assert!(kept.is_empty());
    }

    #[test]
    fn the_file_holds_hashes_not_snippets() {
        let old = result(vec![f("R-1", "a.py", 3, "x: a-distinctive-attack-string")]);
        let text = serde_json::to_string(&BaselineFile::from_result(&old, ".", None)).unwrap();
        assert!(!text.contains("a-distinctive-attack-string"));
    }
}
