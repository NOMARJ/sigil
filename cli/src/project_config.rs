//! Scan policy: `.sigil.yml` for a project, `SIGIL_POLICY_FILE` for an
//! organisation, and the `sigil scan` flags that override both.
//!
//! A policy decides what a scan *enforces*, never what it *detects* — with one
//! additive exception, `rule_packs`, which can only add rules. Everything a
//! policy takes out of the verdict is kept in the report with the file and key
//! that took it out, the same discipline the ledger and `sigil:ignore`
//! markers follow: a finding is never silently dropped.
//!
//! # Layers
//!
//! 1. **Organisation** — the file named by `SIGIL_POLICY_FILE` (pushed by MDM
//!    or baked into a CI image). It may list keys under `locked:`; a locked
//!    key can afterwards only be made *stricter*.
//! 2. **Project** — `--config FILE`, or else the first of `.sigil.yml`,
//!    `.sigil.yaml`, `sigil.yml` found in the scan root and then in the
//!    current directory.
//! 3. **Flags** — `--fail-on`, `--fail-on-verdict`, `--severity`,
//!    `--baseline`, `--rules`.
//!
//! # The scanned-tree guard
//!
//! Sigil exists to judge code you do not trust yet, so a policy file shipped
//! *inside* that code must not be able to weaken the judgement. A project file
//! discovered in the scan root is trusted only when you are working inside
//! that tree (the current directory is the scan root or below it); otherwise,
//! as when the organisation sets `allow_project_policy: false`, it is applied
//! **tighten-only**: it can lower `fail_on`, add rules and raise severities,
//! but its `disable_rules`, `ignore_paths`, `trusted_domains`, `baseline` and
//! any loosening value are refused, and each refusal is reported. Naming the
//! file with `--config` is how you vouch for it. Acquisitions (`sigil clone`,
//! `pip`, `npm`) never read a policy from the quarantined content at all.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::baseline::Baseline;
use crate::corpus::custom;
use crate::scanner::{Finding, Phase, ScanResult, Severity, Verdict};

/// File names discovered in the scan root, then in the current directory.
pub const PROJECT_FILE_NAMES: &[&str] = &[".sigil.yml", ".sigil.yaml", "sigil.yml"];
/// Organisation policy file, e.g. pushed by MDM.
pub const ORG_POLICY_ENV: &str = "SIGIL_POLICY_FILE";
/// Set to `1` to skip project-policy discovery (as `--no-project-config`).
pub const NO_PROJECT_POLICY_ENV: &str = "SIGIL_NO_PROJECT_CONFIG";

/// Largest policy file read.
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

const KNOWN_KEYS: &[&str] = &[
    "version",
    "fail_on",
    "fail_on_verdict",
    "fail_on_incomplete",
    "min_severity",
    "disable_rules",
    "severity_overrides",
    "ignore_paths",
    "rule_packs",
    "trusted_domains",
    "baseline",
    "locked",
    "allow_project_policy",
];

/// Keys an organisation policy may lock.
pub const LOCKABLE_KEYS: &[&str] = &[
    "fail_on",
    "fail_on_verdict",
    "fail_on_incomplete",
    "min_severity",
    "disable_rules",
    "severity_overrides",
    "ignore_paths",
    "rule_packs",
    "trusted_domains",
    "baseline",
];

/// Where a policy layer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `SIGIL_POLICY_FILE`.
    Org,
    /// `--config` or a discovered `.sigil.yml`.
    Project,
}

impl Origin {
    fn label(self) -> &'static str {
        match self {
            Origin::Org => "organisation",
            Origin::Project => "project",
        }
    }
}

/// One policy document, parsed and validated but not yet merged.
#[derive(Debug, Clone, Default)]
pub struct PolicyDoc {
    pub fail_on: Option<Severity>,
    pub fail_on_verdict: Option<Verdict>,
    pub fail_on_incomplete: Option<bool>,
    pub min_severity: Option<Severity>,
    pub disable_rules: Vec<String>,
    /// In file order: later entries win for the same rule.
    pub severity_overrides: Vec<(String, Severity)>,
    pub ignore_paths: Vec<String>,
    /// Resolved against the policy file's directory.
    pub rule_packs: Vec<PathBuf>,
    pub trusted_domains: Vec<String>,
    /// Resolved against the policy file's directory.
    pub baseline: Option<PathBuf>,
    pub locked: Vec<String>,
    pub allow_project_policy: Option<bool>,
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/// Parse a severity name (`low` .. `critical`, any case).
pub fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Parse a verdict name: `LOW`, `medium`, `HIGH RISK`, `critical_risk`.
pub fn parse_verdict(s: &str) -> Option<Verdict> {
    let norm = s.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    let norm = norm.strip_suffix("_risk").unwrap_or(&norm);
    match norm {
        "low" => Some(Verdict::LowRisk),
        "medium" => Some(Verdict::MediumRisk),
        "high" => Some(Verdict::HighRisk),
        "critical" => Some(Verdict::CriticalRisk),
        _ => None,
    }
}

/// Order of verdicts for `fail_on_verdict`.
///
/// `Verdict` deliberately does not derive `Ord` (see its docs): the exit-code
/// gate is the one consumer here, and it spells the order out rather than
/// letting any caller write `>= HighRisk`. Like `acquisition_exit_code`, it
/// answers "how bad is it", not "may we run it", so it is not an
/// `enforcement` consumer.
fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::LowRisk => 0,
        Verdict::MediumRisk => 1,
        Verdict::HighRisk => 2,
        Verdict::CriticalRisk => 3,
    }
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::LowRisk => "LOW",
        Verdict::MediumRisk => "MEDIUM",
        Verdict::HighRisk => "HIGH",
        Verdict::CriticalRisk => "CRITICAL",
    }
}

/// Read and parse a policy file. Every problem in it is reported, prefixed
/// with the file name.
pub fn load_policy_file(path: &Path, origin: Origin) -> Result<PolicyDoc, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("{}: cannot read policy file: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: policy path is not a file", path.display()));
    }
    if meta.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "{}: policy file is {} bytes; the limit is {MAX_POLICY_BYTES}",
            path.display(),
            meta.len()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read policy file: {e}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    parse_policy(&text, base, origin).map_err(|errs| {
        errs.iter()
            .map(|e| format!("{}: {e}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Parse policy text. Relative paths resolve against `base_dir`.
pub fn parse_policy(text: &str, base_dir: &Path, origin: Origin) -> Result<PolicyDoc, Vec<String>> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| vec![format!("YAML parse error: {e}")])?;
    let map = match value {
        serde_yaml::Value::Null => return Ok(PolicyDoc::default()),
        serde_yaml::Value::Mapping(m) => m,
        _ => return Err(vec!["a policy file must be a mapping of keys".to_string()]),
    };

    let mut errors = Vec::new();
    let mut doc = PolicyDoc::default();
    for (k, v) in &map {
        let Some(key) = k.as_str() else {
            errors.push(format!("keys must be strings, found {k:?}"));
            continue;
        };
        match key {
            "version" => match v.as_u64() {
                Some(1) => {}
                Some(n) => errors.push(format!(
                    "version: {n} is not supported by this Sigil (supported: 1)"
                )),
                None => errors.push("version: must be the number 1".to_string()),
            },
            "fail_on" => doc.fail_on = severity_value(key, v, &mut errors),
            "min_severity" => doc.min_severity = severity_value(key, v, &mut errors),
            "fail_on_verdict" => {
                if !v.is_null() {
                    match v.as_str().and_then(parse_verdict) {
                        Some(verdict) => doc.fail_on_verdict = Some(verdict),
                        None => errors.push(format!(
                            "fail_on_verdict: {} is not a verdict (use LOW, MEDIUM, HIGH or CRITICAL)",
                            show(v)
                        )),
                    }
                }
            }
            "fail_on_incomplete" => match v {
                serde_yaml::Value::Null => {}
                serde_yaml::Value::Bool(b) => doc.fail_on_incomplete = Some(*b),
                _ => errors.push(format!(
                    "fail_on_incomplete: {} is not a boolean (use true or false)",
                    show(v)
                )),
            },
            "disable_rules" => {
                for id in string_list(key, v, &mut errors) {
                    match check_rule_glob(&id) {
                        Ok(()) => doc.disable_rules.push(id),
                        Err(e) => errors.push(format!("disable_rules: {e}")),
                    }
                }
            }
            "severity_overrides" => match v {
                serde_yaml::Value::Null => {}
                serde_yaml::Value::Mapping(m) => {
                    for (rk, rv) in m {
                        let Some(rule) = rk.as_str() else {
                            errors.push("severity_overrides: keys must be rule ids".to_string());
                            continue;
                        };
                        if let Err(e) = check_rule_glob(rule) {
                            errors.push(format!("severity_overrides: {e}"));
                            continue;
                        }
                        match rv.as_str().and_then(parse_severity) {
                            Some(sev) => doc.severity_overrides.push((rule.to_string(), sev)),
                            None => errors.push(format!(
                                "severity_overrides.{rule}: {} is not a severity (use low, medium, high or critical)",
                                show(rv)
                            )),
                        }
                    }
                }
                _ => errors.push(
                    "severity_overrides: must be a mapping of rule id to severity".to_string(),
                ),
            },
            "ignore_paths" => {
                for glob in string_list(key, v, &mut errors) {
                    match PathGlobs::new(std::slice::from_ref(&glob)) {
                        Ok(_) => doc.ignore_paths.push(glob),
                        Err(e) => errors.push(format!("ignore_paths: '{glob}': {e}")),
                    }
                }
            }
            "rule_packs" => {
                for p in string_list(key, v, &mut errors) {
                    doc.rule_packs.push(base_dir.join(p));
                }
            }
            "trusted_domains" => {
                for d in string_list(key, v, &mut errors) {
                    match normalize_domain(&d) {
                        Ok(n) => doc.trusted_domains.push(n),
                        Err(e) => errors.push(format!("trusted_domains: '{d}': {e}")),
                    }
                }
            }
            "baseline" => {
                if let Some(s) = v.as_str() {
                    if s.trim().is_empty() {
                        errors.push("baseline: must be a path".to_string());
                    } else {
                        doc.baseline = Some(base_dir.join(s));
                    }
                } else if !v.is_null() {
                    errors.push("baseline: must be a path".to_string());
                }
            }
            "locked" => {
                if origin != Origin::Org {
                    errors.push(format!(
                        "locked: only the organisation policy ({ORG_POLICY_ENV}) can lock keys"
                    ));
                    continue;
                }
                for k in string_list(key, v, &mut errors) {
                    if k == "*" || k == "all" {
                        doc.locked
                            .extend(LOCKABLE_KEYS.iter().map(|s| s.to_string()));
                    } else if LOCKABLE_KEYS.contains(&k.as_str()) {
                        doc.locked.push(k);
                    } else {
                        errors.push(match custom::closest(&k, LOCKABLE_KEYS) {
                            Some(s) => {
                                format!("locked: '{k}' is not a lockable key (did you mean '{s}'?)")
                            }
                            None => format!(
                                "locked: '{k}' is not a lockable key (lockable: {})",
                                LOCKABLE_KEYS.join(", ")
                            ),
                        });
                    }
                }
            }
            "allow_project_policy" => {
                if origin != Origin::Org {
                    errors.push(format!(
                        "allow_project_policy: only the organisation policy ({ORG_POLICY_ENV}) can set this"
                    ));
                } else {
                    match v.as_bool() {
                        Some(b) => doc.allow_project_policy = Some(b),
                        None => {
                            errors.push("allow_project_policy: must be true or false".to_string())
                        }
                    }
                }
            }
            other => errors.push(match custom::closest(other, KNOWN_KEYS) {
                Some(s) => format!("unknown key '{other}' (did you mean '{s}'?)"),
                None => format!(
                    "unknown key '{other}' (known keys: {})",
                    KNOWN_KEYS.join(", ")
                ),
            }),
        }
    }
    if errors.is_empty() {
        Ok(doc)
    } else {
        Err(errors)
    }
}

fn show(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => format!("'{s}'"),
        other => serde_yaml::to_string(other)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "value".to_string()),
    }
}

fn severity_value(key: &str, v: &serde_yaml::Value, errors: &mut Vec<String>) -> Option<Severity> {
    if v.is_null() {
        return None;
    }
    match v.as_str().and_then(parse_severity) {
        Some(s) => Some(s),
        None => {
            let hint = v
                .as_str()
                .and_then(|s| custom::closest(s, &["low", "medium", "high", "critical"]))
                .map(|s| format!(", did you mean '{s}'?"))
                .unwrap_or_default();
            errors.push(format!(
                "{key}: {} is not a severity (use low, medium, high or critical{hint})",
                show(v)
            ));
            None
        }
    }
}

fn string_list(key: &str, v: &serde_yaml::Value, errors: &mut Vec<String>) -> Vec<String> {
    match v {
        serde_yaml::Value::Null => Vec::new(),
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .filter_map(|i| match i.as_str() {
                Some(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                _ => {
                    errors.push(format!("{key}: every entry must be a non-empty string"));
                    None
                }
            })
            .collect(),
        _ => {
            errors.push(format!("{key}: must be a list of strings"));
            Vec::new()
        }
    }
}

/// A rule id or a glob over rule ids (`NET-*`, `CODE-01?`).
fn check_rule_glob(s: &str) -> Result<(), String> {
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*' | '?' | '.'))
    {
        return Err(format!(
            "'{s}' is not a rule id or rule glob (letters, digits, '-', '*', '?')"
        ));
    }
    Ok(())
}

/// Normalise a trusted domain: lower case, no scheme, path or port, and at
/// least two labels so `com` cannot trust the whole TLD.
fn normalize_domain(d: &str) -> Result<String, String> {
    let d = d.trim().to_ascii_lowercase();
    if d.contains("://") || d.contains('/') {
        let host = d
            .split("://")
            .last()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        return Err(format!("give a host name, not a URL (e.g. '{host}')"));
    }
    let d = d.strip_prefix("*.").unwrap_or(&d).trim_end_matches('.');
    if d.contains(':') {
        return Err("give a host name without a port".to_string());
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        || d.is_empty()
    {
        return Err("not a host name".to_string());
    }
    if !d.contains('.') {
        return Err(
            "too broad: a trusted domain needs at least two labels (example.com)".to_string(),
        );
    }
    Ok(d.to_string())
}

// ---------------------------------------------------------------------------
// Globs
// ---------------------------------------------------------------------------

/// Case-insensitive glob over a rule id: `*` any run of characters, `?` one.
pub fn rule_glob_matches(pattern: &str, id: &str) -> bool {
    text_glob_matches(pattern, id)
}

/// Case-insensitive glob over free text: `*` (and `**`) any run of
/// characters including `/`, `?` any one character.
pub fn text_glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    // Iterative wildcard match with single-star backtracking: linear in
    // practice, and no regex compilation per finding.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Path globs in `.sigilignore` (gitignore) syntax, matched against a
/// finding's path relative to the scan root.
pub struct PathGlobs {
    matcher: ignore::gitignore::Gitignore,
    patterns: Vec<String>,
}

impl PathGlobs {
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        let mut b = ignore::gitignore::GitignoreBuilder::new("");
        for p in patterns {
            b.add_line(None, p).map_err(|e| e.to_string())?;
        }
        let matcher = b.build().map_err(|e| e.to_string())?;
        Ok(PathGlobs {
            matcher,
            patterns: patterns.to_vec(),
        })
    }

    /// The pattern that matches `path`, if any.
    pub fn matching(&self, path: &str) -> Option<&str> {
        let norm = normalize_rel_path(path);
        if norm.is_empty() {
            return None;
        }
        match self
            .matcher
            .matched_path_or_any_parents(Path::new(&norm), false)
        {
            ignore::Match::Ignore(glob) => Some(
                self.patterns
                    .iter()
                    .find(|p| p.as_str() == glob.original())
                    .map(|p| p.as_str())
                    .unwrap_or(glob.original()),
            ),
            _ => None,
        }
    }
}

/// Relative, forward-slash form of a finding path. Absolute paths and
/// container locators never reach the gitignore matcher, which requires paths
/// under its root.
fn normalize_rel_path(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.trim_start_matches("./").trim_start_matches('/');
    p.to_string()
}

// ---------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------

/// A value together with the source that set it (`.sigil.yml`,
/// `organisation policy /etc/sigil/policy.yml`, `--baseline`).
#[derive(Debug, Clone)]
pub struct Sourced<T> {
    pub value: T,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct SeverityOverride {
    pub pattern: String,
    pub severity: Severity,
    /// Set when the layer could only tighten: the override may raise a
    /// severity but never lower one.
    pub raise_only: bool,
    pub source: String,
}

/// A policy file that was applied.
#[derive(Debug, Clone)]
pub struct AppliedSource {
    pub path: String,
    pub origin: Origin,
    /// Applied tighten-only, and why.
    pub restricted: Option<String>,
}

/// The merged policy a scan runs under.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    pub fail_on: Severity,
    pub fail_on_verdict: Option<Verdict>,
    /// Fail the gate when part of the target could not be fully inspected
    /// (see [`crate::scanner::coverage`]).
    pub fail_on_incomplete: bool,
    pub min_severity: Option<Severity>,
    pub disable_rules: Vec<Sourced<String>>,
    pub severity_overrides: Vec<SeverityOverride>,
    pub ignore_paths: Vec<Sourced<String>>,
    pub trusted_domains: Vec<Sourced<String>>,
    pub baselines: Vec<Sourced<PathBuf>>,
    pub rule_packs: Vec<Sourced<PathBuf>>,
    pub locked: Vec<String>,
    pub sources: Vec<AppliedSource>,
    /// Loosening values a restricted layer asked for and did not get.
    pub refused: Vec<String>,
    /// Non-fatal problems, e.g. a disable_rules entry that matches no rule.
    pub warnings: Vec<String>,
    /// The directory finding paths are relative to (canonical).
    pub scan_root: Option<PathBuf>,
    /// Sigil's own configuration in play — the trusted policy files and the
    /// baselines (canonical). A policy or baseline you committed is not a
    /// finding in the tree it configures; see [`SuppressionKind::ConfigFile`].
    pub config_files: Vec<PathBuf>,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        EffectivePolicy {
            fail_on: Severity::High,
            fail_on_verdict: None,
            fail_on_incomplete: false,
            min_severity: None,
            disable_rules: Vec::new(),
            severity_overrides: Vec::new(),
            ignore_paths: Vec::new(),
            trusted_domains: Vec::new(),
            baselines: Vec::new(),
            rule_packs: Vec::new(),
            locked: Vec::new(),
            sources: Vec::new(),
            refused: Vec::new(),
            warnings: Vec::new(),
            scan_root: None,
            config_files: Vec::new(),
        }
    }
}

/// Values given on the command line.
#[derive(Debug, Clone, Default)]
pub struct CliPolicy {
    pub fail_on: Option<String>,
    pub fail_on_verdict: Option<String>,
    /// `--fail-on-incomplete`: can only switch the gate on.
    pub fail_on_incomplete: bool,
    pub min_severity: Option<String>,
    pub baseline: Option<PathBuf>,
    pub rules: Vec<PathBuf>,
}

/// What to resolve a policy for.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// The scan target; `None` for commands that do not scan a tree.
    pub scan_root: Option<PathBuf>,
    pub cwd: PathBuf,
    /// `--config FILE`.
    pub explicit_config: Option<PathBuf>,
    /// Look for `.sigil.yml` in the scan root / current directory.
    pub discover: bool,
    pub cli: CliPolicy,
}

/// How a layer is merged.
struct LayerRules<'a> {
    source: String,
    /// Tighten-only for every key, and why.
    restricted_all: Option<String>,
    locked: &'a [String],
}

impl LayerRules<'_> {
    fn restricted(&self, key: &str) -> Option<String> {
        if let Some(why) = &self.restricted_all {
            return Some(why.clone());
        }
        self.locked
            .iter()
            .any(|k| k == key)
            .then(|| "locked by the organisation policy".to_string())
    }
}

fn merge(eff: &mut EffectivePolicy, doc: PolicyDoc, rules: &LayerRules) {
    let src = &rules.source;
    let refuse = |eff: &mut EffectivePolicy, key: &str, what: String, why: String| {
        eff.refused
            .push(format!("{key}: {src} asked for {what}; refused ({why})"));
    };

    if let Some(v) = doc.fail_on {
        match rules.restricted("fail_on") {
            Some(why) if v > eff.fail_on => refuse(
                eff,
                "fail_on",
                format!("{v} (looser than {})", eff.fail_on),
                why,
            ),
            _ => eff.fail_on = v,
        }
    }
    if let Some(v) = doc.fail_on_verdict {
        let looser = eff
            .fail_on_verdict
            .is_some_and(|cur| verdict_rank(v) > verdict_rank(cur));
        match rules.restricted("fail_on_verdict") {
            Some(why) if looser => refuse(
                eff,
                "fail_on_verdict",
                format!("{} (looser than the current gate)", verdict_label(v)),
                why,
            ),
            _ => eff.fail_on_verdict = Some(v),
        }
    }
    if let Some(v) = doc.fail_on_incomplete {
        match rules.restricted("fail_on_incomplete") {
            Some(why) if !v && eff.fail_on_incomplete => refuse(
                eff,
                "fail_on_incomplete",
                "false (would pass a scan that could not inspect everything)".to_string(),
                why,
            ),
            _ => eff.fail_on_incomplete = v,
        }
    }
    if let Some(v) = doc.min_severity {
        let cur = eff.min_severity.unwrap_or(Severity::Low);
        match rules.restricted("min_severity") {
            Some(why) if v > cur => refuse(
                eff,
                "min_severity",
                format!("{v} (would hide findings below it)"),
                why,
            ),
            _ => eff.min_severity = Some(v),
        }
    }
    let list_key =
        |eff: &mut EffectivePolicy,
         key: &str,
         values: Vec<String>,
         target: fn(&mut EffectivePolicy) -> &mut Vec<Sourced<String>>| {
            if values.is_empty() {
                return;
            }
            match rules.restricted(key) {
                Some(why) => eff.refused.push(format!(
                    "{key}: {src} asked for [{}]; refused ({why})",
                    values.join(", ")
                )),
                None => target(eff).extend(values.into_iter().map(|value| Sourced {
                    value,
                    source: src.clone(),
                })),
            }
        };
    list_key(eff, "disable_rules", doc.disable_rules, |e| {
        &mut e.disable_rules
    });
    list_key(eff, "ignore_paths", doc.ignore_paths, |e| {
        &mut e.ignore_paths
    });
    list_key(eff, "trusted_domains", doc.trusted_domains, |e| {
        &mut e.trusted_domains
    });

    let raise_only = rules.restricted("severity_overrides").is_some();
    for (pattern, severity) in doc.severity_overrides {
        eff.severity_overrides.push(SeverityOverride {
            pattern,
            severity,
            raise_only,
            source: src.clone(),
        });
    }

    if let Some(b) = doc.baseline {
        match rules.restricted("baseline") {
            Some(why) => eff.refused.push(format!(
                "baseline: {src} asked for {}; refused ({why})",
                b.display()
            )),
            None => eff.baselines.push(Sourced {
                value: b,
                source: src.clone(),
            }),
        }
    }
    if !doc.rule_packs.is_empty() {
        match rules.restricted("rule_packs") {
            Some(why) => eff.refused.push(format!(
                "rule_packs: {src} asked for {} pack path(s); refused ({why})",
                doc.rule_packs.len()
            )),
            None => eff
                .rule_packs
                .extend(doc.rule_packs.into_iter().map(|p| Sourced {
                    value: p,
                    source: src.clone(),
                })),
        }
    }
}

/// Find a project policy file in `dir`.
fn find_policy_in(dir: &Path, warnings: &mut Vec<String>) -> Option<PathBuf> {
    let found: Vec<PathBuf> = PROJECT_FILE_NAMES
        .iter()
        .map(|n| dir.join(n))
        .filter(|p| p.is_file())
        .collect();
    if found.len() > 1 {
        warnings.push(format!(
            "{} policy files in {}; using {} and ignoring the rest",
            found.len(),
            dir.display(),
            found[0].display()
        ));
    }
    found.into_iter().next()
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Merge the organisation policy, the project policy and the flags.
pub fn resolve(opts: &ResolveOptions) -> Result<EffectivePolicy, String> {
    let mut eff = EffectivePolicy::default();

    // 1. Organisation.
    let mut allow_project = true;
    if let Some(org_path) = std::env::var_os(ORG_POLICY_ENV).filter(|v| !v.is_empty()) {
        let org_path = PathBuf::from(org_path);
        let doc = load_policy_file(&org_path, Origin::Org)
            .map_err(|e| format!("organisation policy ({ORG_POLICY_ENV}): {e}"))?;
        allow_project = doc.allow_project_policy.unwrap_or(true);
        let locked = doc.locked.clone();
        let source = format!("organisation policy {}", org_path.display());
        merge(
            &mut eff,
            doc,
            &LayerRules {
                source,
                restricted_all: None,
                locked: &[],
            },
        );
        eff.locked = locked;
        eff.sources.push(AppliedSource {
            path: org_path.display().to_string(),
            origin: Origin::Org,
            restricted: None,
        });
    }

    // 2. Project.
    let cwd = canonical(&opts.cwd);
    let project: Option<(PathBuf, Option<String>)> = if let Some(explicit) = &opts.explicit_config {
        Some((explicit.clone(), None))
    } else if opts.discover {
        let mut found = None;
        if let Some(root) = &opts.scan_root {
            let root_dir = if root.is_file() {
                root.parent().map(Path::to_path_buf).unwrap_or_default()
            } else {
                root.clone()
            };
            let root_dir = canonical(&root_dir);
            if let Some(p) = find_policy_in(&root_dir, &mut eff.warnings) {
                // Trusted only when you are working inside the tree it
                // ships in; otherwise it is part of what is being judged.
                let guard = (!cwd.starts_with(&root_dir)).then(|| {
                    format!(
                        "this file ships inside the scanned tree and you are not working in it; \
                         pass --config {} to trust it",
                        p.display()
                    )
                });
                found = Some((p, guard));
            }
        }
        if found.is_none() {
            found = find_policy_in(&cwd, &mut eff.warnings).map(|p| (p, None));
        }
        found
    } else {
        None
    };
    if let Some((path, guard)) = project {
        let doc = load_policy_file(&path, Origin::Project)?;
        let restricted_all = if !allow_project {
            Some("the organisation policy sets allow_project_policy: false".to_string())
        } else {
            guard
        };
        let locked = eff.locked.clone();
        merge(
            &mut eff,
            doc,
            &LayerRules {
                source: path.display().to_string(),
                restricted_all: restricted_all.clone(),
                locked: &locked,
            },
        );
        eff.sources.push(AppliedSource {
            path: path.display().to_string(),
            origin: Origin::Project,
            restricted: restricted_all,
        });
    }

    // 3. Flags.
    let cli = &opts.cli;
    let mut doc = PolicyDoc::default();
    let mut errors = Vec::new();
    if let Some(s) = &cli.fail_on {
        match parse_severity(s) {
            Some(v) => doc.fail_on = Some(v),
            None => errors.push(format!(
                "invalid --fail-on '{s}' (use low, medium, high, critical)"
            )),
        }
    }
    if let Some(s) = &cli.fail_on_verdict {
        match parse_verdict(s) {
            Some(v) => doc.fail_on_verdict = Some(v),
            None => errors.push(format!(
                "invalid --fail-on-verdict '{s}' (use low, medium, high, critical)"
            )),
        }
    }
    if cli.fail_on_incomplete {
        doc.fail_on_incomplete = Some(true);
    }
    if let Some(s) = &cli.min_severity {
        match parse_severity(s) {
            Some(v) => doc.min_severity = Some(v),
            None => errors.push(format!(
                "invalid --severity '{s}' (use low, medium, high, critical)"
            )),
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    doc.baseline = cli.baseline.clone();
    doc.rule_packs = cli.rules.clone();
    let locked = eff.locked.clone();
    merge(
        &mut eff,
        doc,
        &LayerRules {
            source: "command line".to_string(),
            restricted_all: None,
            locked: &locked,
        },
    );

    // Sigil's own configuration in play. A restricted (untrusted) policy is
    // not included: it is part of what is being judged.
    eff.scan_root = opts.scan_root.as_ref().map(|root| {
        if root.is_file() {
            canonical(root.parent().unwrap_or(Path::new(".")))
        } else {
            canonical(root)
        }
    });
    let mut config_files: Vec<PathBuf> = eff
        .sources
        .iter()
        .filter(|s| s.restricted.is_none())
        .map(|s| canonical(Path::new(&s.path)))
        .collect();
    config_files.extend(eff.baselines.iter().map(|b| canonical(&b.value)));
    eff.config_files = config_files;

    Ok(eff)
}

impl EffectivePolicy {
    /// Load this policy's rule packs and add them to the corpus.
    ///
    /// Must run before the corpus is first used. Packs are checked against
    /// the built-in corpus and each other first: a custom pack can add rules,
    /// never replace one.
    pub fn activate_rule_packs(&self) -> Result<Vec<custom::CustomPack>, String> {
        if self.rule_packs.is_empty() {
            return Ok(Vec::new());
        }
        let mut packs = Vec::new();
        let mut errors = Vec::new();
        for p in &self.rule_packs {
            match custom::load_path(&p.value) {
                Ok(mut loaded) => packs.append(&mut loaded),
                Err(e) => errors.push(format!("{e} (rule pack from {})", p.source)),
            }
        }
        if errors.is_empty() {
            let base = crate::corpus::loader::load_base_packs()?;
            errors.extend(custom::check_against(&base, &packs));
        }
        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }
        custom::register(packs.clone())?;
        Ok(packs)
    }

    /// Load every baseline this policy names. A named baseline that cannot be
    /// read is an error: running without it would fail the build on findings
    /// the team already accepted, or worse, pass on a typo.
    pub fn load_baselines(&self) -> Result<Vec<(Baseline, String)>, String> {
        self.baselines
            .iter()
            .map(|b| {
                Baseline::load(&b.value)
                    .map(|bl| (bl, format!("{} ({})", b.value.display(), b.source)))
            })
            .collect()
    }

    /// Warn about entries that match no active rule — usually a typo, which
    /// would otherwise leave the noisy rule enabled with nobody noticing.
    pub fn check_rule_references(&mut self, active_ids: &[String]) {
        let entries = self
            .disable_rules
            .iter()
            .map(|d| ("disable_rules", &d.value, &d.source))
            .chain(
                self.severity_overrides
                    .iter()
                    .map(|o| ("severity_overrides", &o.pattern, &o.source)),
            );
        let unmatched: Vec<String> = entries
            .filter(|(_, pattern, _)| !active_ids.iter().any(|id| rule_glob_matches(pattern, id)))
            .map(|(kind, pattern, source)| {
                format!("{kind} '{pattern}' ({source}) matches no active rule")
            })
            .collect();
        self.warnings.extend(unmatched);
    }

    /// Whether any policy file or enforcement flag is in play. When not, the
    /// report is left byte-identical to a scan without this module.
    pub fn is_active(&self) -> bool {
        !self.sources.is_empty()
            || !self.baselines.is_empty()
            || !self.refused.is_empty()
            || self.fail_on_verdict.is_some()
            || self.fail_on_incomplete
            || self.min_severity.is_some()
            || !self.disable_rules.is_empty()
            || !self.severity_overrides.is_empty()
            || !self.ignore_paths.is_empty()
            || !self.trusted_domains.is_empty()
            || !self.rule_packs.is_empty()
    }

    /// Would this result fail the gate (exit 1 under ADR-0010)? True when an
    /// active finding is at or above `fail_on`, the verdict is at or above
    /// `fail_on_verdict`, or `fail_on_incomplete` is set and part of the
    /// target could not be fully inspected.
    pub fn fails(&self, result: &ScanResult) -> bool {
        result.findings.iter().any(|f| f.severity >= self.fail_on)
            || self.fails_on_verdict(result)
            || self.fails_on_incomplete(result)
    }

    /// Does incomplete coverage alone fail the gate? Only active findings
    /// count: a coverage finding you suppressed with a written reason is a
    /// decision, like any other suppression.
    pub fn fails_on_incomplete(&self, result: &ScanResult) -> bool {
        self.fail_on_incomplete && crate::scanner::coverage::is_incomplete(&result.findings)
    }

    /// Does the verdict alone fail the gate?
    pub fn fails_on_verdict(&self, result: &ScanResult) -> bool {
        self.fail_on_verdict
            .is_some_and(|v| verdict_rank(result.verdict) >= verdict_rank(v))
    }

    /// Apply the policy to a finished scan: rewrite severities, move
    /// suppressed findings out of the verdict (keeping them, attributed), and
    /// recompute score and verdict.
    pub fn apply(
        &self,
        result: &mut ScanResult,
        baselines: &[(Baseline, String)],
    ) -> PolicyOutcome {
        let mut outcome = PolicyOutcome::default();
        let before = result.findings.len();

        // 1. Severity overrides, in order; later entries win.
        if !self.severity_overrides.is_empty() {
            for f in result.findings.iter_mut() {
                let original = f.severity;
                for o in &self.severity_overrides {
                    if rule_glob_matches(&o.pattern, &f.rule) {
                        f.severity = if o.raise_only {
                            f.severity.max(o.severity)
                        } else {
                            o.severity
                        };
                    }
                }
                if f.severity != original {
                    outcome.severity_changed += 1;
                }
            }
        }

        // 2. Minimum severity: a report threshold, exactly as `--severity`
        // has always behaved. Counted, not listed.
        // Coverage findings are exempt: a severity floor must not hide that
        // part of the target was never inspected (see scanner::coverage).
        if let Some(min) = self.min_severity {
            let n = result.findings.len();
            result.findings.retain(|f| {
                f.severity >= min || crate::scanner::coverage::is_coverage_rule(&f.rule)
            });
            outcome.hidden_below_min_severity = n - result.findings.len();
        }

        // 3-5. Rule, path and domain suppressions.
        let path_globs = if self.ignore_paths.is_empty() {
            None
        } else {
            let pats: Vec<String> = self.ignore_paths.iter().map(|s| s.value.clone()).collect();
            PathGlobs::new(&pats).ok()
        };
        let correlation_ids: HashSet<String> = crate::corpus::compiled::corpus()
            .correlation_rules
            .iter()
            .map(|r| r.id.clone())
            .collect();
        let mut kept = Vec::with_capacity(result.findings.len());
        for f in std::mem::take(&mut result.findings) {
            if let Some(path) = self.config_file_of(&f) {
                let reason = format!("Sigil configuration file {}", path.display());
                outcome.push(f, SuppressionKind::ConfigFile, reason);
                continue;
            }
            if let Some(d) = self
                .disable_rules
                .iter()
                .find(|d| rule_glob_matches(&d.value, &f.rule))
            {
                outcome.push(
                    f,
                    SuppressionKind::DisabledRule,
                    format!("disable_rules {} ({})", d.value, d.source),
                );
                continue;
            }
            if let Some(globs) = &path_globs {
                if let Some(pat) = globs.matching(&f.file) {
                    let source = self
                        .ignore_paths
                        .iter()
                        .find(|s| s.value == pat)
                        .map(|s| s.source.as_str())
                        .unwrap_or("policy");
                    outcome.push(
                        f,
                        SuppressionKind::IgnoredPath,
                        format!("ignore_paths {pat} ({source})"),
                    );
                    continue;
                }
            }
            if !self.trusted_domains.is_empty() {
                if let Some(reason) = self.trusted_domain_reason(&f, &correlation_ids) {
                    outcome.push(f, SuppressionKind::TrustedDomain, reason);
                    continue;
                }
            }
            kept.push(f);
        }
        result.findings = kept;

        // 6. Baselines.
        for (baseline, source) in baselines {
            let (kept, suppressed, notes) =
                baseline.partition(std::mem::take(&mut result.findings));
            result.findings = kept;
            for (f, reason) in suppressed {
                outcome.push(
                    f,
                    SuppressionKind::Baseline,
                    format!("baseline {source}: {reason}"),
                );
            }
            outcome
                .notes
                .extend(notes.into_iter().map(|n| format!("{source}: {n}")));
        }

        if result.findings.len() != before || outcome.severity_changed > 0 {
            result.score = crate::scanner::scoring::calculate_score(&result.findings);
            result.verdict = crate::scanner::scoring::determine_verdict_with_size(
                &result.findings,
                result.score,
                result.files_scanned,
            );
        }
        outcome
    }

    /// Treat `path` as Sigil configuration too — `sigil baseline` registers the
    /// file it is about to (re)write, so regenerating a baseline does not
    /// record the previous one as a finding. The file need not exist yet.
    pub fn add_config_file(&mut self, path: &Path) {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Some(name) = path.file_name() {
            self.config_files.push(canonical(dir).join(name));
        }
    }

    /// The trusted configuration file (policy or baseline) a finding sits in.
    ///
    /// A committed `.sigil.yml` or `.sigil-baseline.json` is a dotfile, and
    /// the hidden-file rule would otherwise report the configuration as a
    /// finding in the tree it configures — making `sigil baseline` add a new
    /// finding by writing its own file. Only files this run actually trusts
    /// qualify; a policy shipped in a tree being judged is never one of them.
    fn config_file_of(&self, f: &Finding) -> Option<&Path> {
        let root = self.scan_root.as_ref()?;
        let name = Path::new(&f.file).file_name()?;
        let candidate = self
            .config_files
            .iter()
            .find(|c| c.file_name() == Some(name))?;
        (canonical(&root.join(&f.file)) == *candidate).then_some(candidate.as_path())
    }

    /// Why a network finding is excused by `trusted_domains`, if it is.
    ///
    /// Deliberately narrow. Only Network/Exfil findings up to High qualify;
    /// Critical findings, correlation chains (a credential flowing to a host
    /// — trusted hosts like GitHub are classic exfiltration channels) and
    /// reverse shells never do. Every URL visible on the line must point at a
    /// trusted host, and a line whose snippet was truncated or decoded from
    /// an encoded blob is never excused, because part of it is out of sight.
    fn trusted_domain_reason(
        &self,
        f: &Finding,
        correlation_ids: &HashSet<String>,
    ) -> Option<String> {
        if f.phase != Phase::NetworkExfil
            || f.severity >= Severity::Critical
            || correlation_ids.contains(&f.rule)
            || f.rule.starts_with("RSHELL-")
            || f.snippet.starts_with("[decoded")
            || f.snippet.starts_with("[tail of oversized file]")
            || f.snippet.ends_with(" ...")
        {
            return None;
        }
        let hosts = url_hosts(&f.snippet);
        if hosts.is_empty() {
            return None;
        }
        let mut matched = Vec::new();
        for host in &hosts {
            let d = self
                .trusted_domains
                .iter()
                .find(|d| host == &d.value || host.ends_with(&format!(".{}", d.value)))?;
            matched.push(format!("{} ({})", d.value, d.source));
        }
        matched.dedup();
        Some(format!("trusted_domains {}", matched.join(", ")))
    }

    /// The JSON `policy` block.
    pub fn to_json(&self, outcome: &PolicyOutcome) -> serde_json::Value {
        json!({
            "sources": self.sources.iter().map(|s| json!({
                "path": s.path,
                "origin": s.origin.label(),
                "tighten_only": s.restricted.is_some(),
                "tighten_only_reason": s.restricted,
            })).collect::<Vec<_>>(),
            "fail_on": self.fail_on.to_string(),
            "fail_on_verdict": self.fail_on_verdict.map(verdict_label),
            "fail_on_incomplete": self.fail_on_incomplete,
            "min_severity": self.min_severity.map(|s| s.to_string()),
            "locked": self.locked,
            "refused": self.refused,
            "warnings": self.warnings,
            "notes": outcome.notes,
            "hidden_below_min_severity": outcome.hidden_below_min_severity,
            "severity_overridden": outcome.severity_changed,
            "suppressed": outcome.suppressed.iter().map(|s| {
                let mut v = crate::output::finding_json(&s.finding);
                v["suppressed_by"] = json!(s.reason);
                v["suppression"] = json!(s.kind.label());
                v
            }).collect::<Vec<_>>(),
        })
    }
}

/// Hosts of every URL in `text`.
fn url_hosts(text: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(?:https?|wss?|ftp)://(?:[^/\s@'\x22]*@)?([a-z0-9.-]+)")
            .expect("url regex")
    });
    re.captures_iter(text)
        .map(|c| c[1].to_ascii_lowercase().trim_end_matches('.').to_string())
        .collect()
}

/// Why a finding was taken out of the verdict by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionKind {
    DisabledRule,
    IgnoredPath,
    TrustedDomain,
    Baseline,
    /// The finding is in a trusted Sigil policy or baseline file.
    ConfigFile,
}

impl SuppressionKind {
    pub fn label(self) -> &'static str {
        match self {
            SuppressionKind::DisabledRule => "disabled_rule",
            SuppressionKind::IgnoredPath => "ignored_path",
            SuppressionKind::TrustedDomain => "trusted_domain",
            SuppressionKind::Baseline => "baseline",
            SuppressionKind::ConfigFile => "config_file",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicySuppressed {
    pub finding: Finding,
    pub kind: SuppressionKind,
    pub reason: String,
}

/// What applying a policy did.
#[derive(Debug, Clone, Default)]
pub struct PolicyOutcome {
    pub suppressed: Vec<PolicySuppressed>,
    pub hidden_below_min_severity: usize,
    pub severity_changed: usize,
    pub notes: Vec<String>,
}

impl PolicyOutcome {
    fn push(&mut self, finding: Finding, kind: SuppressionKind, reason: String) {
        self.suppressed.push(PolicySuppressed {
            finding,
            kind,
            reason,
        });
    }

    pub fn count(&self, kind: SuppressionKind) -> usize {
        self.suppressed.iter().filter(|s| s.kind == kind).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `resolve` reads SIGIL_POLICY_FILE; tests that set it serialise here.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn finding(rule: &str, file: &str, sev: Severity, snippet: &str) -> Finding {
        Finding {
            phase: if rule.starts_with("NET-") {
                Phase::NetworkExfil
            } else {
                Phase::CodePatterns
            },
            rule: rule.to_string(),
            severity: sev,
            file: file.to_string(),
            line: Some(1),
            snippet: snippet.to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        let score = crate::scanner::scoring::calculate_score(&findings);
        let verdict = crate::scanner::scoring::determine_verdict(&findings, score);
        ScanResult {
            findings,
            score,
            verdict,
            files_scanned: 3,
            duration_ms: 0,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
            scanner: None,
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            platform: String::new(),
        }
    }

    fn opts(dir: &Path) -> ResolveOptions {
        ResolveOptions {
            scan_root: Some(dir.to_path_buf()),
            cwd: dir.to_path_buf(),
            explicit_config: None,
            discover: true,
            cli: CliPolicy::default(),
        }
    }

    fn resolve_clean(o: &ResolveOptions) -> Result<EffectivePolicy, String> {
        std::env::remove_var(ORG_POLICY_ENV);
        resolve(o)
    }

    #[test]
    fn a_full_policy_parses() {
        let doc = parse_policy(
            r#"
version: 1
fail_on: medium
fail_on_verdict: HIGH
min_severity: low
disable_rules: [NET-012, "PROV-*"]
severity_overrides:
  CODE-013: low
ignore_paths: ["tests/fixtures/", "*.snap"]
rule_packs: [rules/acme.yaml]
trusted_domains: [api.openai.com, "*.nvidia.com"]
baseline: .sigil-baseline.json
"#,
            Path::new("/repo"),
            Origin::Project,
        )
        .expect("parses");
        assert_eq!(doc.fail_on, Some(Severity::Medium));
        assert_eq!(doc.fail_on_verdict, Some(Verdict::HighRisk));
        assert_eq!(doc.disable_rules, vec!["NET-012", "PROV-*"]);
        assert_eq!(
            doc.severity_overrides,
            vec![("CODE-013".to_string(), Severity::Low)]
        );
        assert_eq!(doc.trusted_domains, vec!["api.openai.com", "nvidia.com"]);
        assert_eq!(doc.rule_packs, vec![PathBuf::from("/repo/rules/acme.yaml")]);
        assert_eq!(
            doc.baseline,
            Some(PathBuf::from("/repo/.sigil-baseline.json"))
        );
    }

    #[test]
    fn errors_are_precise_and_all_reported() {
        let errs = parse_policy(
            "fail_onn: high\nfail_on: hgh\nfail_on_verdict: severe\nmin_severity: 3\n\
             trusted_domains: [https://api.example.com/v1, com]\ndisable_rules: ['NET 012']\n\
             locked: [fail_on]\n",
            Path::new("."),
            Origin::Project,
        )
        .expect_err("invalid");
        let all = errs.join("\n");
        assert!(
            all.contains("unknown key 'fail_onn' (did you mean 'fail_on'?)"),
            "{all}"
        );
        assert!(all.contains("fail_on: 'hgh' is not a severity"), "{all}");
        assert!(all.contains("did you mean 'high'?"), "{all}");
        assert!(
            all.contains("fail_on_verdict: 'severe' is not a verdict"),
            "{all}"
        );
        assert!(all.contains("min_severity: 3 is not a severity"), "{all}");
        assert!(
            all.contains("give a host name, not a URL (e.g. 'api.example.com')"),
            "{all}"
        );
        assert!(all.contains("too broad"), "{all}");
        assert!(all.contains("'NET 012' is not a rule id"), "{all}");
        assert!(
            all.contains("locked: only the organisation policy"),
            "{all}"
        );
    }

    #[test]
    fn an_empty_file_is_an_empty_policy() {
        let doc = parse_policy("", Path::new("."), Origin::Project).expect("empty ok");
        assert!(doc.fail_on.is_none() && doc.disable_rules.is_empty());
        assert!(parse_policy("- a\n- b\n", Path::new("."), Origin::Project).is_err());
    }

    #[test]
    fn project_file_is_discovered_in_the_scan_root_then_the_cwd() {
        let _g = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".sigil.yml"), "fail_on: critical\n").unwrap();
        let eff = resolve_clean(&opts(root.path())).unwrap();
        assert_eq!(eff.fail_on, Severity::Critical);
        assert_eq!(eff.sources.len(), 1);
        assert!(eff.sources[0].restricted.is_none());

        // Nothing in the root: the cwd's file is used.
        let empty_root = tempfile::tempdir().unwrap();
        let mut o = opts(empty_root.path());
        o.cwd = root.path().to_path_buf();
        let eff = resolve_clean(&o).unwrap();
        assert_eq!(eff.fail_on, Severity::Critical);

        // Discovery off: defaults.
        let mut o = opts(root.path());
        o.discover = false;
        let eff = resolve_clean(&o).unwrap();
        assert_eq!(eff.fail_on, Severity::High);
        assert!(eff.sources.is_empty());
    }

    /// The core anti-evasion property: a policy shipped inside a tree you are
    /// auditing from outside cannot switch off the audit.
    #[test]
    fn a_policy_inside_a_scanned_tree_you_are_not_in_can_only_tighten() {
        let _g = ENV_LOCK.lock().unwrap();
        let skill = tempfile::tempdir().unwrap();
        std::fs::write(
            skill.path().join(".sigil.yml"),
            "fail_on: critical\ndisable_rules: ['*']\nignore_paths: ['**']\n\
             trusted_domains: [evil.example]\nbaseline: b.json\nmin_severity: critical\n\
             severity_overrides: {CODE-001: low, NET-001: high}\n",
        )
        .unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let mut o = opts(skill.path());
        o.cwd = elsewhere.path().to_path_buf();
        let eff = resolve_clean(&o).unwrap();

        assert_eq!(eff.fail_on, Severity::High, "fail_on must not loosen");
        assert!(eff.disable_rules.is_empty());
        assert!(eff.ignore_paths.is_empty());
        assert!(eff.trusted_domains.is_empty());
        assert!(eff.baselines.is_empty());
        assert!(eff.min_severity.is_none());
        assert!(eff.sources[0].restricted.is_some());
        assert!(eff.refused.len() >= 6, "{:?}", eff.refused);
        assert!(
            eff.refused.iter().all(|r| r.contains("--config")),
            "{:?}",
            eff.refused
        );

        // Overrides survive raise-only: NET-001 may go up, CODE-001 may not go down.
        let mut r = result(vec![
            finding("CODE-001", "a.py", Severity::High, "x"),
            finding("NET-001", "a.py", Severity::Medium, "y"),
        ]);
        eff.apply(&mut r, &[]);
        let sev = |id: &str| r.findings.iter().find(|f| f.rule == id).unwrap().severity;
        assert_eq!(sev("CODE-001"), Severity::High);
        assert_eq!(sev("NET-001"), Severity::High);

        // Named explicitly, the same file is trusted.
        o.explicit_config = Some(skill.path().join(".sigil.yml"));
        let eff = resolve_clean(&o).unwrap();
        assert_eq!(eff.fail_on, Severity::Critical);
        assert_eq!(eff.disable_rules.len(), 1);
    }

    #[test]
    fn working_inside_the_tree_trusts_its_policy() {
        let _g = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join(".sigil.yml"), "disable_rules: [NET-012]\n").unwrap();
        let mut o = opts(root.path());
        o.cwd = root.path().join("sub");
        let eff = resolve_clean(&o).unwrap();
        assert_eq!(eff.disable_rules.len(), 1);
        assert!(eff.refused.is_empty());
    }

    #[test]
    fn locked_org_keys_can_only_be_tightened_by_project_and_flags() {
        let _g = ENV_LOCK.lock().unwrap();
        let org_dir = tempfile::tempdir().unwrap();
        let org = org_dir.path().join("org.yml");
        std::fs::write(
            &org,
            "fail_on: high\nfail_on_verdict: HIGH\ndisable_rules: [PROV-*]\n\
             locked: [fail_on, fail_on_verdict, disable_rules, baseline]\n",
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".sigil.yml"),
            "fail_on: critical\nfail_on_verdict: CRITICAL\ndisable_rules: [NET-*]\n\
             ignore_paths: [vendor/]\nbaseline: b.json\n",
        )
        .unwrap();
        std::env::set_var(ORG_POLICY_ENV, &org);
        let mut o = opts(root.path());
        let eff = resolve(&o);
        o.cli.fail_on = Some("medium".into());
        let tightened = resolve(&o);
        o.cli.fail_on = Some("critical".into());
        let loosened = resolve(&o);
        std::env::remove_var(ORG_POLICY_ENV);

        let eff = eff.unwrap();
        assert_eq!(eff.fail_on, Severity::High);
        assert_eq!(eff.fail_on_verdict, Some(Verdict::HighRisk));
        assert_eq!(
            eff.disable_rules
                .iter()
                .map(|d| d.value.as_str())
                .collect::<Vec<_>>(),
            vec!["PROV-*"],
            "the org's own list stays; the project's addition is refused"
        );
        assert_eq!(eff.ignore_paths.len(), 1, "unlocked keys still apply");
        assert!(eff.baselines.is_empty());
        assert_eq!(eff.refused.len(), 4, "{:?}", eff.refused);
        assert!(eff
            .refused
            .iter()
            .all(|r| r.contains("locked by the organisation policy")));

        assert_eq!(
            tightened.unwrap().fail_on,
            Severity::Medium,
            "tightening is allowed"
        );
        let loosened = loosened.unwrap();
        assert_eq!(loosened.fail_on, Severity::High);
        assert!(loosened
            .refused
            .iter()
            .any(|r| r.starts_with("fail_on: command line")));
    }

    #[test]
    fn org_can_make_every_project_file_tighten_only() {
        let _g = ENV_LOCK.lock().unwrap();
        let org_dir = tempfile::tempdir().unwrap();
        let org = org_dir.path().join("org.yml");
        std::fs::write(&org, "allow_project_policy: false\n").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".sigil.yml"),
            "fail_on: low\ndisable_rules: [X-1]\n",
        )
        .unwrap();
        std::env::set_var(ORG_POLICY_ENV, &org);
        let eff = resolve(&opts(root.path()));
        std::env::remove_var(ORG_POLICY_ENV);
        let eff = eff.unwrap();
        assert_eq!(eff.fail_on, Severity::Low, "tightening still applies");
        assert!(eff.disable_rules.is_empty());
        assert!(eff.refused[0].contains("allow_project_policy: false"));
    }

    #[test]
    fn a_missing_or_broken_org_policy_is_fatal_not_ignored() {
        let _g = ENV_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::env::set_var(ORG_POLICY_ENV, root.path().join("missing.yml"));
        let missing = resolve(&opts(root.path()));
        let bad = root.path().join("bad.yml");
        std::fs::write(&bad, "fail_on: nope\n").unwrap();
        std::env::set_var(ORG_POLICY_ENV, &bad);
        let broken = resolve(&opts(root.path()));
        std::env::remove_var(ORG_POLICY_ENV);
        assert!(missing.unwrap_err().contains("organisation policy"));
        assert!(broken.unwrap_err().contains("fail_on: 'nope'"));
    }

    #[test]
    fn apply_moves_findings_out_of_the_verdict_with_attribution() {
        let eff = EffectivePolicy {
            disable_rules: vec![Sourced {
                value: "prov-*".into(),
                source: ".sigil.yml".into(),
            }],
            ignore_paths: vec![Sourced {
                value: "tests/".into(),
                source: ".sigil.yml".into(),
            }],
            trusted_domains: vec![Sourced {
                value: "openai.com".into(),
                source: ".sigil.yml".into(),
            }],
            ..Default::default()
        };
        let mut r = result(vec![
            finding("PROV-003", "x.bin", Severity::Low, "binary"),
            finding("CODE-001", "tests/unit/t.py", Severity::High, "run(x)"),
            finding(
                "NET-001",
                "client.py",
                Severity::Medium,
                r#"requests.post("https://api.openai.com/v1/chat")"#,
            ),
            finding(
                "NET-001",
                "leak.py",
                Severity::Medium,
                r#"requests.post("https://api.openai.com.evil.example/x")"#,
            ),
            finding(
                "NET-001",
                "mix.py",
                Severity::Medium,
                r#"get("https://api.openai.com/" + "https://evil.example/")"#,
            ),
            finding("CODE-001", "src/main.py", Severity::High, "run(y)"),
        ]);
        let out = eff.apply(&mut r, &[]);
        let kept: Vec<&str> = r.findings.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(kept, vec!["leak.py", "mix.py", "src/main.py"]);
        assert_eq!(out.count(SuppressionKind::DisabledRule), 1);
        assert_eq!(out.count(SuppressionKind::IgnoredPath), 1);
        assert_eq!(out.count(SuppressionKind::TrustedDomain), 1);
        assert!(out.suppressed[0]
            .reason
            .contains("disable_rules prov-* (.sigil.yml)"));
        assert_eq!(
            r.score,
            crate::scanner::scoring::calculate_score(&r.findings)
        );
    }

    #[test]
    fn trusted_domains_never_excuse_critical_decoded_or_truncated_lines() {
        let eff = EffectivePolicy {
            trusted_domains: vec![Sourced {
                value: "github.com".into(),
                source: "p".into(),
            }],
            ..Default::default()
        };
        let mut critical = finding(
            "NET-007",
            "a.py",
            Severity::Critical,
            "post('https://github.com/x')",
        );
        critical.phase = Phase::NetworkExfil;
        let decoded = finding(
            "NET-001",
            "a.py",
            Severity::Medium,
            "[decoded base64] get('https://github.com/x')",
        );
        let truncated = finding(
            "NET-001",
            "a.py",
            Severity::Medium,
            "get('https://github.com/x' + aaaa ...",
        );
        let no_url = finding("NET-001", "a.py", Severity::Medium, "client.send(url)");
        let mut r = result(vec![critical, decoded, truncated, no_url]);
        let out = eff.apply(&mut r, &[]);
        assert!(out.suppressed.is_empty());
        assert_eq!(r.findings.len(), 4);
    }

    #[test]
    fn min_severity_and_overrides_feed_the_exit_code() {
        let eff = EffectivePolicy {
            min_severity: Some(Severity::Medium),
            severity_overrides: vec![SeverityOverride {
                pattern: "CODE-013".into(),
                severity: Severity::Low,
                raise_only: false,
                source: "p".into(),
            }],
            ..Default::default()
        };
        let mut r = result(vec![
            finding("CODE-013", "a.py", Severity::High, "subprocess.run"),
            finding("CRED-001", "a.py", Severity::Low, "os.environ"),
        ]);
        let before = r.findings.len();
        let out = eff.apply(&mut r, &[]);
        assert_eq!(out.severity_changed, 1);
        assert_eq!(out.hidden_below_min_severity, before);
        assert!(r.findings.is_empty());
        assert!(!eff.fails(&r));
    }

    #[test]
    fn fail_on_verdict_gates_independently_of_finding_severity() {
        let mut eff = EffectivePolicy {
            fail_on: Severity::Critical,
            ..Default::default()
        };
        let mut r = result(vec![finding("CODE-001", "a.py", Severity::Medium, "x")]);
        r.verdict = Verdict::MediumRisk;
        assert!(!eff.fails(&r));
        eff.fail_on_verdict = Some(Verdict::MediumRisk);
        assert!(eff.fails(&r));
        eff.fail_on_verdict = Some(Verdict::HighRisk);
        assert!(!eff.fails(&r));
    }

    #[test]
    fn fail_on_incomplete_gates_on_coverage_findings_only() {
        let mut eff = EffectivePolicy::default();
        let gap = crate::scanner::coverage::partial_finding("big.js", "only the ends".into());
        let r = result(vec![gap]);
        assert!(!eff.fails(&r), "off by default");
        eff.fail_on_incomplete = true;
        assert!(eff.fails(&r));
        assert!(eff.fails_on_incomplete(&r));
        let clean = result(vec![finding("CODE-007", "a.py", Severity::Low, "x")]);
        assert!(
            !eff.fails(&clean),
            "a Low observation is not a coverage gap"
        );
    }

    #[test]
    fn fail_on_incomplete_parses_and_locks_tighten_only() {
        let doc = parse_policy(
            "fail_on_incomplete: true\n",
            Path::new("."),
            Origin::Project,
        )
        .unwrap();
        assert_eq!(doc.fail_on_incomplete, Some(true));
        let errs = parse_policy(
            "fail_on_incomplete: sometimes\n",
            Path::new("."),
            Origin::Project,
        )
        .unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("fail_on_incomplete") && e.contains("boolean")),
            "{errs:?}"
        );

        let _g = ENV_LOCK.lock().unwrap();
        let org_dir = tempfile::tempdir().unwrap();
        let org = org_dir.path().join("org.yml");
        std::fs::write(
            &org,
            "fail_on_incomplete: true\nlocked: [fail_on_incomplete]\n",
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".sigil.yml"),
            "fail_on_incomplete: false\n",
        )
        .unwrap();
        std::env::set_var(ORG_POLICY_ENV, &org);
        let eff = resolve(&opts(root.path()));
        std::env::remove_var(ORG_POLICY_ENV);
        let eff = eff.unwrap();
        assert!(
            eff.fail_on_incomplete,
            "a locked true cannot be switched off"
        );
        assert!(
            eff.refused
                .iter()
                .any(|r| r.starts_with("fail_on_incomplete")),
            "{:?}",
            eff.refused
        );

        let mut o = opts(root.path());
        o.cli.fail_on_incomplete = true;
        let from_flag = resolve(&o).unwrap();
        assert!(
            from_flag.fail_on_incomplete,
            "the flag wins over the project's false"
        );
    }

    #[test]
    fn globs() {
        assert!(rule_glob_matches("NET-*", "NET-012"));
        assert!(rule_glob_matches("net-01?", "NET-012"));
        assert!(!rule_glob_matches("NET-*", "CODE-001"));
        assert!(rule_glob_matches("*", "ANY-1"));
        assert!(text_glob_matches(
            "*api.example*",
            "fetch https://api.example.com/x"
        ));
        assert!(!text_glob_matches("a*b", "acd"));

        let g = PathGlobs::new(&[
            "tests/".to_string(),
            "*.snap".to_string(),
            "docs/**/*.md".to_string(),
        ])
        .unwrap();
        assert_eq!(g.matching("tests/unit/a.py"), Some("tests/"));
        assert_eq!(g.matching("src/x.snap"), Some("*.snap"));
        assert_eq!(g.matching("docs/a/b/c.md"), Some("docs/**/*.md"));
        assert_eq!(g.matching("src/tests_helper.py"), None);
        // gitignore semantics, as in .sigilignore: `tests/` is any directory
        // named tests. An absolute path is matched as relative, never panics.
        assert_eq!(g.matching("pkg/tests/x.py"), Some("tests/"));
        assert_eq!(g.matching("/abs/x.py"), None);
    }

    #[test]
    fn verdict_names() {
        for (s, v) in [
            ("LOW", Verdict::LowRisk),
            ("medium", Verdict::MediumRisk),
            ("HIGH RISK", Verdict::HighRisk),
            ("critical_risk", Verdict::CriticalRisk),
        ] {
            assert_eq!(parse_verdict(s), Some(v), "{s}");
        }
        assert_eq!(parse_verdict("severe"), None);
    }
}
