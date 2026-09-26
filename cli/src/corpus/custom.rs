//! Custom rule packs named for one run: `--rules <file|dir>` and the
//! `rule_packs` key of a scan policy (`.sigil.yml`, `SIGIL_POLICY_FILE`).
//!
//! Two shapes are accepted, in JSON or YAML:
//!
//! - the **full pack schema** (`meta` + `rules` + optional `provenance_rules`
//!   and `correlation_rules`), exactly what `packs/core/v1/*.json` use;
//! - a **compact form** for the everyday case of an organisation adding a few
//!   of its own rules, converted to the full schema on load:
//!
//! ```yaml
//! pack: { id: acme-rules, name: ACME internal rules }   # optional
//! rules:
//!   - id: ACME-001
//!     pattern: 'internal-artifacts\.acme\.example'
//!     severity: medium
//!     description: Reference to the internal artifact mirror
//!     extensions: [py, js]
//!     remediation: Internal mirrors must not appear in published skills.
//! ```
//!
//! Custom packs are **additive**. A custom pack may not reuse the id of a
//! built-in, released or user pack, and a custom rule may not reuse any
//! existing rule id: a file named on the command line — or worse, by a policy
//! file — must never be able to replace a core pack and silently remove its
//! detections. Replacing a core pack remains possible, deliberately, only from
//! the machine-level `~/.sigil/packs/` directory.
//!
//! Every problem is reported with the file and the rule it belongs to, and a
//! pack with any error is refused as a whole. A rule that silently does not
//! run is a detection gap nobody notices, which is worse than a failed run.
//!
//! A third shape, YARA rule files (`.yar`, `.yara`), is read by
//! [`super::yara`] and becomes a pack of `YARA-<NAME>` rules evaluated over
//! raw file bytes.
//!
//! When `SIGIL_PACK_PUBLIC_KEY` is set, custom packs are held to the same rule
//! as `~/.sigil/packs/`: each must carry a valid Ed25519 `meta.signature`
//! (a YARA file: a detached `<file>.sig`). `sigil rules sign` produces both.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use regex::Regex;
use serde_json::Value;

use super::schema::{
    Evidence, FileFilter, PackMeta, PackRule, SignaturePack, SuppressionPredicates,
};
use crate::scanner::Phase;

/// Largest pack file read. The embedded corpus is ~1 MB in total; a custom
/// pack past this is a mistake or an attempt to exhaust memory.
pub const MAX_PACK_BYTES: u64 = 8 * 1024 * 1024;

/// Extensions a directory of packs is read for.
const PACK_EXTENSIONS: &[&str] = &["json", "yaml", "yml", "yar", "yara"];

/// Keys a full-schema rule may carry. Anything else is almost certainly a
/// misspelling (`supress`, `file_filters`) that serde would ignore silently.
const FULL_RULE_KEYS: &[&str] = &[
    "id",
    "phase",
    "severity",
    "pattern",
    "description",
    "weight",
    "file_filter",
    "suppress",
    "evidence",
    "remediation",
    "references",
    "tags",
];

/// Keys a correlation rule's `source` and `sink` selectors may carry. A
/// misspelt `rule_ids` would otherwise leave the selector empty, and the
/// chain would never fire.
const SELECTOR_KEYS: &[&str] = &["rule_prefixes", "rule_ids"];

/// Keys a correlation rule may carry. A misspelt `name_uses` would otherwise
/// fall back to the default without a word.
const CORRELATION_RULE_KEYS: &[&str] = &[
    "id",
    "phase",
    "severity",
    "description",
    "weight",
    "source",
    "sink",
    "window_lines",
    "sink_window_before",
    "name_uses",
    "max_line_length",
    "sink_excludes",
    "remediation",
    "references",
    "tags",
];

/// Keys a compact rule may carry.
const COMPACT_RULE_KEYS: &[&str] = &[
    "id",
    "pattern",
    "severity",
    "description",
    "title",
    "phase",
    "files",
    "extensions",
    "suffixes",
    "exclude_paths",
    "exclude_lines",
    "remediation",
    "references",
    "tags",
    "weight",
    "evidence",
];

/// Keys the compact form's optional `pack:` block may carry.
const COMPACT_PACK_KEYS: &[&str] = &["id", "name", "version", "author", "description"];

/// Whether a custom pack's signature was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// `SIGIL_PACK_PUBLIC_KEY` is set and the signature verified.
    Verified,
    /// No key configured and the pack carries no signature.
    Unsigned,
    /// The pack carries a signature but no key is configured to check it.
    SignedUnverified,
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignatureStatus::Verified => "verified",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::SignedUnverified => {
                "signed (not verified: SIGIL_PACK_PUBLIC_KEY unset)"
            }
        })
    }
}

/// Which shape a custom pack was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackForm {
    /// `meta` + `rules`, the schema of the built-in packs.
    Full,
    /// `rules:` (and an optional `pack:` block), converted on load.
    Compact,
    /// A YARA rule file.
    Yara,
}

impl std::fmt::Display for PackForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PackForm::Full => "full",
            PackForm::Compact => "compact",
            PackForm::Yara => "yara",
        })
    }
}

/// One custom pack, parsed, validated and converted to the full schema.
#[derive(Debug, Clone)]
pub struct CustomPack {
    pub pack: SignaturePack,
    /// The file it was read from.
    pub path: PathBuf,
    /// The shape the file was written in.
    pub form: PackForm,
    pub signature: SignatureStatus,
    /// Non-fatal observations, e.g. `evidence` on a non-critical rule.
    pub warnings: Vec<String>,
    /// Problems `sigil rules validate` and `sigil rules sign` reject but a
    /// scan only warns about, because packs carrying them loaded before
    /// the check existed: an unknown key on a correlation rule or its
    /// source or sink selector (the scan ignores the key), and a selector
    /// that names no rule (the chain never fires).
    pub ignored: Vec<String>,
}

// ---------------------------------------------------------------------------
// Registration: the packs this run adds to the corpus
// ---------------------------------------------------------------------------

/// Serialises tests that read or set `SIGIL_PACK_PUBLIC_KEY` — the loader's
/// signing tests and this module's. One process-wide variable needs one lock.
#[cfg(test)]
pub(crate) static PACK_KEY_ENV_LOCK: Mutex<()> = Mutex::new(());

static REGISTERED: Mutex<Vec<CustomPack>> = Mutex::new(Vec::new());
static CONSUMED: AtomicBool = AtomicBool::new(false);

/// Add packs to this run's corpus.
///
/// Must be called before the compiled corpus is first built: the corpus is
/// compiled once per process, so a pack registered afterwards would be
/// silently ignored. That is refused instead.
pub fn register(packs: Vec<CustomPack>) -> Result<(), String> {
    if CONSUMED.load(Ordering::SeqCst) {
        return Err(
            "custom rule packs were registered after the detection corpus was built".to_string(),
        );
    }
    let mut reg = REGISTERED
        .lock()
        .map_err(|_| "custom pack registry poisoned".to_string())?;
    for p in packs {
        // The same file named twice (by --rules and by a policy) is one pack.
        if reg
            .iter()
            .any(|r| r.path == p.path && r.pack.meta.id == p.pack.meta.id)
        {
            continue;
        }
        reg.push(p);
    }
    Ok(())
}

/// The packs registered so far, for `sigil rules` and `sigil corpus`.
pub fn registered() -> Vec<CustomPack> {
    REGISTERED.lock().map(|r| r.clone()).unwrap_or_default()
}

/// Append the registered packs to a loaded corpus. Called by the loader.
///
/// Additive only: a custom pack whose id is already present is an error, not
/// a replacement. [`check_against`] reports the same thing earlier and more
/// helpfully; this is the backstop.
pub(super) fn append_registered(packs: &mut Vec<SignaturePack>) -> Result<(), String> {
    CONSUMED.store(true, Ordering::SeqCst);
    for custom in registered() {
        if packs.iter().any(|p| p.meta.id == custom.pack.meta.id) {
            return Err(format!(
                "custom pack '{}' ({}) reuses the id of a loaded pack",
                custom.pack.meta.id,
                custom.path.display()
            ));
        }
        packs.push(custom.pack);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load every pack at `path`: one file, or each `.json`/`.yaml`/`.yml`/
/// `.yar`/`.yara` file directly inside a directory, in name order.
pub fn load_path(path: &Path) -> Result<Vec<CustomPack>, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("{}: cannot read rule pack: {e}", path.display()))?;
    if !meta.is_dir() {
        return load_file(path).map(|p| vec![p]);
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| format!("{}: cannot list rule pack directory: {e}", path.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| PACK_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "{}: no .json, .yaml, .yml, .yar or .yara rule packs in this directory",
            path.display()
        ));
    }
    let mut packs = Vec::with_capacity(files.len());
    let mut errors = Vec::new();
    for f in &files {
        match load_unchecked(f) {
            Ok(p) => packs.push(p),
            Err(e) => errors.push(e),
        }
    }
    // YARA files an external engine evaluates are checked by it, all of
    // this directory's at once (one engine run, not one per file).
    if let Err(mut e) = super::yara::external::validate_packs(&packs) {
        errors.append(&mut e);
    }
    if errors.is_empty() {
        Ok(packs)
    } else {
        Err(errors.join("\n"))
    }
}

/// Load, verify and validate one pack file.
pub fn load_file(path: &Path) -> Result<CustomPack, String> {
    let pack = load_unchecked(path)?;
    super::yara::external::validate_packs(std::slice::from_ref(&pack)).map_err(|e| e.join("\n"))?;
    Ok(pack)
}

/// [`load_file`], except that a YARA file an external engine evaluates is
/// not yet checked by that engine (the caller does, for a batch).
fn load_unchecked(path: &Path) -> Result<CustomPack, String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("{}: cannot read rule pack: {e}", path.display()))?;
    if meta.len() > MAX_PACK_BYTES {
        return Err(format!(
            "{}: rule pack is {} bytes; the limit is {} bytes",
            path.display(),
            meta.len(),
            MAX_PACK_BYTES
        ));
    }
    if super::yara::is_yara_path(path) {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("{}: cannot read rule pack: {e}", path.display()))?;
        return super::yara::parse_pack(&bytes, path).map_err(|errs| errs.join("\n"));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read rule pack: {e}", path.display()))?;
    parse_pack(&text, path).map_err(|errs| {
        errs.iter()
            .map(|e| format!("{}: {e}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Parse a pack document to a JSON value, whichever syntax it was written in.
fn parse_document(text: &str, path: &Path) -> Result<Value, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let as_yaml = |t: &str| -> Result<Value, String> {
        let y: serde_yaml::Value =
            serde_yaml::from_str(t).map_err(|e| format!("YAML parse error: {e}"))?;
        serde_json::to_value(y).map_err(|e| format!("YAML is not representable as a pack: {e}"))
    };
    match ext.as_deref() {
        Some("json") => serde_json::from_str(text).map_err(|e| format!("JSON parse error: {e}")),
        Some("yaml") | Some("yml") => as_yaml(text),
        // Unknown extension: JSON is a subset of YAML, so YAML parses both,
        // but a JSON error message is more useful for a JSON-looking file.
        _ => serde_json::from_str(text).or_else(|_| as_yaml(text)),
    }
}

/// Parse, signature-check and validate pack text. Every problem found is
/// returned, not just the first.
pub fn parse_pack(text: &str, path: &Path) -> Result<CustomPack, Vec<String>> {
    let doc = parse_document(text, path).map_err(|e| vec![e])?;
    let compact = !doc.get("meta").is_some_and(|m| m.is_object());

    let signature = signature_status(&doc, compact).map_err(|e| vec![e])?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut ignored = Vec::new();
    let pack = if compact {
        compact_to_pack(&doc, path, &mut errors)
    } else {
        full_to_pack(&doc, &mut errors, &mut ignored)
    };
    if let Some(pack) = &pack {
        validate_pack(pack, &mut errors, &mut warnings);
    }
    match pack {
        Some(pack) if errors.is_empty() => Ok(CustomPack {
            pack,
            path: path.to_path_buf(),
            form: if compact {
                PackForm::Compact
            } else {
                PackForm::Full
            },
            signature,
            warnings,
            ignored,
        }),
        _ => Err(errors),
    }
}

/// Check the signature under the `SIGIL_PACK_PUBLIC_KEY` policy that already
/// governs `~/.sigil/packs/` (see `loader::verify_pack_if_keyed`).
fn signature_status(doc: &Value, compact: bool) -> Result<SignatureStatus, String> {
    let keyed = std::env::var("SIGIL_PACK_PUBLIC_KEY").is_ok_and(|k| !k.is_empty());
    let has_sig = doc
        .get("meta")
        .and_then(|m| m.get("signature"))
        .and_then(|s| s.as_str())
        .is_some_and(|s| !s.is_empty());
    if keyed && compact {
        return Err(
            "[SECURITY] SIGIL_PACK_PUBLIC_KEY is set, so rule packs must be signed, and a \
             compact pack cannot carry a signature — convert and sign it with \
             `sigil rules sign <file> --key <private-key>`"
                .to_string(),
        );
    }
    if !keyed {
        return Ok(if has_sig {
            SignatureStatus::SignedUnverified
        } else {
            SignatureStatus::Unsigned
        });
    }
    // Canonical JSON of the value, whichever syntax the file used, so a
    // signed YAML pack verifies the same way a signed JSON pack does.
    let raw = serde_json::to_string(doc).map_err(|e| format!("cannot canonicalise pack: {e}"))?;
    super::loader::verify_pack_if_keyed(&raw)?;
    Ok(SignatureStatus::Verified)
}

/// Convert a full-schema document, checking each rule separately so an error
/// names the rule it is in. What a scan only warns about goes to `ignored`
/// (see [`CustomPack::ignored`]).
fn full_to_pack(
    doc: &Value,
    errors: &mut Vec<String>,
    ignored: &mut Vec<String>,
) -> Option<SignaturePack> {
    let Some(obj) = doc.as_object() else {
        errors.push("a pack must be a mapping with `meta` and `rules`".to_string());
        return None;
    };
    for key in obj.keys() {
        if !["meta", "rules", "provenance_rules", "correlation_rules"].contains(&key.as_str()) {
            errors.push(unknown_key(
                "top level",
                key,
                &["meta", "rules", "provenance_rules", "correlation_rules"],
            ));
        }
    }
    let meta: Option<PackMeta> = match serde_json::from_value(obj["meta"].clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            errors.push(format!(
                "meta: {e} (a full pack needs meta.id, name, version, updated_at, author, description)"
            ));
            None
        }
    };
    let mut rules = Vec::new();
    if let Some(list) = obj.get("rules") {
        let Some(list) = list.as_array() else {
            errors.push("rules: must be a list".to_string());
            return None;
        };
        for (i, raw) in list.iter().enumerate() {
            let label = rule_label(i, raw);
            if let Some(map) = raw.as_object() {
                for key in map.keys() {
                    if !FULL_RULE_KEYS.contains(&key.as_str()) {
                        errors.push(unknown_key(&label, key, FULL_RULE_KEYS));
                    }
                }
            }
            match serde_json::from_value::<PackRule>(raw.clone()) {
                Ok(r) => rules.push(r),
                Err(e) => errors.push(format!("{label}: {e}")),
            }
        }
    }
    let provenance_rules = match obj.get("provenance_rules") {
        Some(v) => serde_json::from_value(v.clone()).unwrap_or_else(|e| {
            errors.push(format!("provenance_rules: {e}"));
            Vec::new()
        }),
        None => Vec::new(),
    };
    // Earlier versions read a correlation rule without checking its keys, so
    // a pack with an extra one loaded, and may be signed as it is: a scan
    // warns and ignores the key, validation and signing refuse it.
    if let Some(list) = obj.get("correlation_rules").and_then(Value::as_array) {
        for (i, raw) in list.iter().enumerate() {
            let label = format!(
                "correlation_rules[{i}] ({})",
                raw.get("id").and_then(Value::as_str).unwrap_or("?")
            );
            for key in raw.as_object().map(|m| m.keys()).into_iter().flatten() {
                if !CORRELATION_RULE_KEYS.contains(&key.as_str()) {
                    ignored.push(unknown_key(&label, key, CORRELATION_RULE_KEYS));
                }
            }
            for side in ["source", "sink"] {
                let Some(sel) = raw.get(side).and_then(Value::as_object) else {
                    continue;
                };
                for key in sel.keys() {
                    if !SELECTOR_KEYS.contains(&key.as_str()) {
                        ignored.push(unknown_key(&format!("{label}.{side}"), key, SELECTOR_KEYS));
                    }
                }
                let names_one = SELECTOR_KEYS.iter().any(|k| {
                    sel.get(*k)
                        .and_then(Value::as_array)
                        .is_some_and(|a| !a.is_empty())
                });
                if !names_one {
                    ignored.push(format!(
                        "{label}.{side}: names no rule (rule_ids and rule_prefixes are empty), so \
                         the chain never fires"
                    ));
                }
            }
        }
    }
    // An unknown `name_uses` value fails here, naming the values it accepts.
    let correlation_rules = match obj.get("correlation_rules") {
        Some(v) => serde_json::from_value(v.clone()).unwrap_or_else(|e| {
            errors.push(format!("correlation_rules: {e}"));
            Vec::new()
        }),
        None => Vec::new(),
    };
    Some(SignaturePack {
        meta: meta?,
        rules,
        provenance_rules,
        correlation_rules,
        // Structural checks are implemented in Rust; a custom pack cannot
        // declare engine rules.
        engine_rules: Vec::new(),
        yara: None,
    })
}

/// Convert the compact form to the full schema.
fn compact_to_pack(doc: &Value, path: &Path, errors: &mut Vec<String>) -> Option<SignaturePack> {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "rules".to_string());

    // Either a bare list of rules, or a mapping with `rules` and `pack`.
    let (rules_value, pack_block) = match doc {
        Value::Array(_) => (doc.clone(), None),
        Value::Object(obj) => {
            for key in obj.keys() {
                if !["rules", "pack"].contains(&key.as_str()) {
                    errors.push(unknown_key("top level", key, &["rules", "pack", "meta"]));
                }
            }
            match obj.get("rules") {
                Some(r) => (r.clone(), obj.get("pack").cloned()),
                None => {
                    errors.push(
                        "no `rules:` list (a compact pack is `rules: [...]`; a full pack also \
                         needs `meta:`)"
                            .to_string(),
                    );
                    return None;
                }
            }
        }
        Value::Null => {
            errors.push("the file is empty".to_string());
            return None;
        }
        _ => {
            errors.push("a rule pack must be a mapping or a list of rules".to_string());
            return None;
        }
    };

    let mut meta = PackMeta {
        id: format!("custom.{stem}"),
        name: stem.clone(),
        version: "0.0.0".to_string(),
        updated_at: String::new(),
        author: String::new(),
        description: format!("Custom rules from {}", path.display()),
    };
    if let Some(block) = pack_block {
        match block.as_object() {
            Some(obj) => {
                for (k, v) in obj {
                    let Some(s) = v.as_str() else {
                        errors.push(format!("pack.{k}: must be a string"));
                        continue;
                    };
                    match k.as_str() {
                        "id" => meta.id = s.to_string(),
                        "name" => meta.name = s.to_string(),
                        "version" => meta.version = s.to_string(),
                        "author" => meta.author = s.to_string(),
                        "description" => meta.description = s.to_string(),
                        other => errors.push(unknown_key("pack", other, COMPACT_PACK_KEYS)),
                    }
                }
            }
            None => errors.push("pack: must be a mapping (id, name, version, ...)".to_string()),
        }
    }

    let Some(list) = rules_value.as_array() else {
        errors.push("rules: must be a list".to_string());
        return None;
    };
    let mut rules = Vec::with_capacity(list.len());
    for (i, raw) in list.iter().enumerate() {
        if let Some(rule) = compact_rule(i, raw, errors) {
            rules.push(rule);
        }
    }
    Some(SignaturePack {
        meta,
        rules,
        provenance_rules: Vec::new(),
        correlation_rules: Vec::new(),
        engine_rules: Vec::new(),
        yara: None,
    })
}

fn compact_rule(i: usize, raw: &Value, errors: &mut Vec<String>) -> Option<PackRule> {
    let label = rule_label(i, raw);
    let Some(map) = raw.as_object() else {
        errors.push(format!("{label}: a rule must be a mapping"));
        return None;
    };
    for key in map.keys() {
        if !COMPACT_RULE_KEYS.contains(&key.as_str()) {
            errors.push(unknown_key(&label, key, COMPACT_RULE_KEYS));
        }
    }
    let before = errors.len();
    let string = |key: &str, errors: &mut Vec<String>| -> Option<String> {
        match map.get(key) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                errors.push(format!("{label}: `{key}` must be a string"));
                None
            }
        }
    };
    let list = |key: &str, errors: &mut Vec<String>| -> Vec<String> {
        match map.get(key) {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => {
                        errors.push(format!("{label}: every `{key}` entry must be a string"));
                        None
                    }
                })
                .collect(),
            Some(_) => {
                errors.push(format!("{label}: `{key}` must be a list of strings"));
                Vec::new()
            }
        }
    };

    let id = string("id", errors);
    let pattern = string("pattern", errors);
    let severity = string("severity", errors);
    let description = string("description", errors).or_else(|| string("title", errors));
    for (name, value) in [
        ("id", &id),
        ("pattern", &pattern),
        ("severity", &severity),
        ("description", &description),
    ] {
        if value.is_none() {
            errors.push(format!("{label}: missing required `{name}`"));
        }
    }
    let phase = string("phase", errors).unwrap_or_else(|| "code_patterns".to_string());
    let weight = match map.get("weight") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(w) if w <= u32::MAX as u64 => Some(w as u32),
            _ => {
                errors.push(format!("{label}: `weight` must be a non-negative integer"));
                None
            }
        },
    };
    let evidence = match string("evidence", errors).as_deref() {
        None | Some("standalone") => Evidence::Standalone,
        Some("corroborate") => Evidence::Corroborate,
        Some(other) => {
            errors.push(format!(
                "{label}: evidence '{other}' is not one of standalone, corroborate"
            ));
            Evidence::Standalone
        }
    };
    let extensions: Vec<String> = list("extensions", errors)
        .into_iter()
        .map(|e| e.trim_start_matches('.').to_string())
        .collect();
    let rule = PackRule {
        id: id.unwrap_or_default(),
        phase,
        severity: severity.unwrap_or_default(),
        pattern: pattern.unwrap_or_default(),
        description: description.unwrap_or_default(),
        weight,
        file_filter: FileFilter {
            filename_exact: list("files", errors),
            extensions,
            filename_suffix: list("suffixes", errors),
        },
        suppress: SuppressionPredicates {
            path_contains: list("exclude_paths", errors),
            line_contains: list("exclude_lines", errors),
            ..Default::default()
        },
        evidence,
        remediation: string("remediation", errors),
        references: list("references", errors),
        tags: list("tags", errors),
    };
    (errors.len() == before).then_some(rule)
}

fn rule_label(i: usize, raw: &Value) -> String {
    match raw.get("id").and_then(|v| v.as_str()) {
        Some(id) => format!("rules[{i}] ({id})"),
        None => format!("rules[{i}]"),
    }
}

/// The id shape `sigil:ignore` markers and policy globs can refer to.
pub(crate) fn id_shape() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+$").expect("id regex"))
}

/// Semantic checks shared by both forms.
fn validate_pack(pack: &SignaturePack, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    if pack.meta.id.trim().is_empty() {
        errors.push("meta.id must not be empty".to_string());
    }
    let mut seen = std::collections::HashSet::new();
    let all_ids = pack
        .rules
        .iter()
        .map(|r| r.id.as_str())
        .chain(pack.provenance_rules.iter().map(|r| r.id.as_str()))
        .chain(pack.correlation_rules.iter().map(|r| r.id.as_str()));
    for id in all_ids {
        if !seen.insert(id.to_string()) {
            errors.push(format!("rule id {id} appears more than once in this pack"));
        }
        if !id_shape().is_match(id) {
            errors.push(format!(
                "rule id '{id}' must look like PREFIX-NAME (letters and digits joined by '-'), \
                 so `sigil:ignore` markers and policy globs can refer to it"
            ));
        }
    }
    for (i, rule) in pack.rules.iter().enumerate() {
        let label = format!("rules[{i}] ({})", rule.id);
        if Phase::from_name(&rule.phase).is_none() {
            let names: Vec<&str> = Phase::ALL.iter().map(|p| p.canonical_name()).collect();
            errors.push(format!(
                "{label}: unknown phase '{}' (one of: {})",
                rule.phase,
                names.join(", ")
            ));
        }
        check_severity(&label, &rule.severity, errors);
        check_weight(&label, rule.weight, errors);
        if rule.description.trim().is_empty() {
            errors.push(format!("{label}: description must not be empty"));
        }
        if rule.pattern.is_empty() {
            errors.push(format!("{label}: pattern must not be empty"));
        } else {
            match Regex::new(&rule.pattern) {
                Ok(re) => {
                    if re.is_match("") {
                        errors.push(format!(
                            "{label}: pattern '{}' matches the empty string, so it would fire on \
                             every line",
                            rule.pattern
                        ));
                    }
                    if let Err(e) = super::exempt::validate(&rule.pattern, &rule.suppress) {
                        errors.push(format!("{label}: suppress: {e}"));
                    }
                }
                Err(e) => errors.push(format!(
                    "{label}: pattern is not a valid Rust regex (no look-around or \
                     backreferences): {}",
                    last_line(&e.to_string())
                )),
            }
        }
        if rule.evidence == Evidence::Corroborate && !rule.severity.eq_ignore_ascii_case("critical")
        {
            warnings.push(format!(
                "{label}: evidence: corroborate only changes anything on a critical rule"
            ));
        }
        if rule.remediation.is_none() {
            warnings.push(format!(
                "{label}: no remediation — reviewers will not be told what to check"
            ));
        }
    }
    for (i, rule) in pack.provenance_rules.iter().enumerate() {
        let label = format!("provenance_rules[{i}] ({})", rule.id);
        check_severity(&label, &rule.severity, errors);
        if let Some(p) = &rule.pattern {
            if let Err(e) = Regex::new(p) {
                errors.push(format!(
                    "{label}: pattern is not a valid regex: {}",
                    last_line(&e.to_string())
                ));
            }
        }
    }
    for (i, rule) in pack.correlation_rules.iter().enumerate() {
        let label = format!("correlation_rules[{i}] ({})", rule.id);
        check_severity(&label, &rule.severity, errors);
        check_weight(&label, rule.weight, errors);
        if Phase::from_name(&rule.phase).is_none() {
            errors.push(format!("{label}: unknown phase '{}'", rule.phase));
        }
        if rule.sink_window_before > MAX_SINK_WINDOW_BEFORE {
            errors.push(format!(
                "{label}: sink_window_before {} is too large (at most {MAX_SINK_WINDOW_BEFORE}; \
                 it is the height of one call's argument list)",
                rule.sink_window_before
            ));
        }
    }
}

/// Largest `sink_window_before` a custom correlation rule may set. The window
/// above a sink stands for the rest of one call's argument list; a window
/// the size of the file would link any use of a name anywhere above the sink.
pub const MAX_SINK_WINDOW_BEFORE: usize = 20;

/// Largest `weight` a custom rule may carry. Built-in rules use 1-10; the
/// score multiplies weight by a severity factor in `u32`, so an unbounded
/// weight could overflow it and wrap a High finding to a near-zero score.
pub const MAX_CUSTOM_WEIGHT: u32 = 100;

fn check_weight(label: &str, weight: Option<u32>, errors: &mut Vec<String>) {
    if let Some(w) = weight {
        if w > MAX_CUSTOM_WEIGHT {
            errors.push(format!(
                "{label}: weight {w} is too large (at most {MAX_CUSTOM_WEIGHT}; built-in rules use 1-10)"
            ));
        }
    }
}

fn check_severity(label: &str, severity: &str, errors: &mut Vec<String>) {
    if !["low", "medium", "high", "critical"].contains(&severity.to_ascii_lowercase().as_str()) {
        errors.push(format!(
            "{label}: severity '{severity}' is not one of low, medium, high, critical"
        ));
    }
}

/// The last non-empty line: regex errors put the actual complaint there.
fn last_line(s: &str) -> String {
    s.lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or(s)
        .trim()
        .to_string()
}

/// Check custom packs against the packs already loaded and against each other.
///
/// Returns one message per collision. Custom packs are additive: they may not
/// replace a loaded pack or redefine a rule id, because either would let a
/// file named at scan time remove detections without anyone noticing.
pub fn check_against(base: &[SignaturePack], custom: &[CustomPack]) -> Vec<String> {
    use std::collections::HashMap;
    let mut errors = Vec::new();
    let mut rule_owner: HashMap<String, String> = HashMap::new();
    for p in base {
        for id in pack_rule_ids(p) {
            rule_owner.insert(id, format!("built-in pack '{}'", p.meta.id));
        }
    }
    let mut pack_owner: HashMap<String, String> = base
        .iter()
        .map(|p| (p.meta.id.clone(), "a built-in pack".to_string()))
        .collect();
    for c in custom {
        let here = c.path.display().to_string();
        if let Some(owner) = pack_owner.get(&c.pack.meta.id) {
            errors.push(format!(
                "{here}: pack id '{}' is already used by {owner}; custom packs are additive and \
                 cannot replace another pack (to replace a core pack, install it in \
                 ~/.sigil/packs/)",
                c.pack.meta.id
            ));
        } else {
            pack_owner.insert(c.pack.meta.id.clone(), here.clone());
        }
        for id in pack_rule_ids(&c.pack) {
            if let Some(owner) = rule_owner.get(&id) {
                errors.push(format!(
                    "{here}: rule id {id} is already defined by {owner}; choose a new id \
                     (use severity_overrides in a policy to change a built-in rule)"
                ));
            } else {
                rule_owner.insert(id, format!("'{here}'"));
            }
        }
    }
    errors
}

/// Every id a pack defines — content, provenance, correlation, engine and
/// YARA rules alike: a custom rule reusing any of them would be reported,
/// suppressed and overridden as if it were the other rule.
fn pack_rule_ids(p: &SignaturePack) -> Vec<String> {
    p.rule_ids()
}

fn unknown_key(context: &str, key: &str, known: &[&str]) -> String {
    match closest(key, known) {
        Some(s) => format!("{context}: unknown key '{key}' (did you mean '{s}'?)"),
        None => format!(
            "{context}: unknown key '{key}' (known keys: {})",
            known.join(", ")
        ),
    }
}

/// The closest known word within a small edit distance, for "did you mean".
pub fn closest<'a>(word: &str, known: &[&'a str]) -> Option<&'a str> {
    let word = word.to_ascii_lowercase();
    known
        .iter()
        .map(|k| (edit_distance(&word, &k.to_ascii_lowercase()), *k))
        .filter(|(d, k)| *d <= 2.max(k.len() / 4))
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

// ---------------------------------------------------------------------------
// Signing (`sigil rules sign`)
// ---------------------------------------------------------------------------

/// DER prefix of an Ed25519 PKCS#8 v1 private key (RFC 8410): the 32-byte
/// seed follows it. This is what `openssl genpkey -algorithm ed25519` writes.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    // sigil:ignore-next-line OBFUSC-007 -- RFC 8410 ASN.1 header, a published constant, not a payload
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// PEM label of an unencrypted PKCS#8 private key, used to recognise the
/// signing-key file. A label, not key material.
const PEM_PRIVATE_KEY_LABEL: &str = "-----BEGIN PRIVATE KEY-----"; // sigil:ignore CRED-006 -- PEM label used to parse the signing key; no key material

/// Read an Ed25519 signing key from a PKCS#8 PEM file (`openssl genpkey
/// -algorithm ed25519`) or a file holding the 32-byte seed as 64 hex chars.
pub fn read_signing_key(path: &Path) -> Result<ed25519_dalek::SigningKey, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read signing key: {e}", path.display()))?;
    let trimmed = text.trim();
    let seed: Vec<u8> = if trimmed.starts_with("-----BEGIN") {
        if !trimmed.starts_with(PEM_PRIVATE_KEY_LABEL) {
            return Err(format!(
                "{}: expected an unencrypted PKCS#8 Ed25519 key ({PEM_PRIVATE_KEY_LABEL})",
                path.display()
            ));
        }
        let body: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(|l| l.trim())
            .collect();
        let der = BASE64
            .decode(body.as_bytes())
            .map_err(|e| format!("{}: PEM body is not base64: {e}", path.display()))?;
        if der.len() != 48 || der[..16] != PKCS8_ED25519_PREFIX {
            return Err(format!(
                "{}: not an Ed25519 private key (generate one with `openssl genpkey -algorithm \
                 ed25519 -out key.pem`)",
                path.display()
            ));
        }
        der[16..].to_vec()
    } else {
        if trimmed.len() != 64 {
            return Err(format!(
                "{}: expected a PEM key or 64 hex characters (a 32-byte seed), found {} characters",
                path.display(),
                trimmed.len()
            ));
        }
        hex::decode(trimmed).map_err(|e| format!("{}: invalid hex: {e}", path.display()))?
    };
    let bytes: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| format!("{}: key seed must be 32 bytes", path.display()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Sign a pack file: validate it, convert a compact pack to the full schema,
/// and return the signed pack as pretty JSON.
///
/// The signature covers the canonical form `loader::verify_pack_if_keyed`
/// checks: the compact JSON serialisation of the document without
/// `meta.signature`.
pub fn sign_file(path: &Path, key: &ed25519_dalek::SigningKey) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::Signer;
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: cannot read rule pack: {e}", path.display()))?;
    let doc = parse_document(&text, path).map_err(|e| format!("{}: {e}", path.display()))?;
    let compact = !doc.get("meta").is_some_and(|m| m.is_object());
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut ignored = Vec::new();
    let pack = if compact {
        compact_to_pack(&doc, path, &mut errors)
    } else {
        full_to_pack(&doc, &mut errors, &mut ignored)
    };
    // A signed pack is a new pack: what a scan would ignore is refused.
    errors.append(&mut ignored);
    if let Some(p) = &pack {
        validate_pack(p, &mut errors, &mut warnings);
    }
    let pack = match pack {
        Some(p) if errors.is_empty() => p,
        _ => {
            return Err(errors
                .iter()
                .map(|e| format!("{}: {e}", path.display()))
                .collect::<Vec<_>>()
                .join("\n"))
        }
    };
    let mut value = serde_json::to_value(&pack).map_err(|e| e.to_string())?;
    if let Some(meta) = value.get_mut("meta").and_then(|m| m.as_object_mut()) {
        meta.remove("signature");
    }
    let canonical = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    let signature = key.sign(canonical.as_bytes());
    value["meta"]["signature"] = Value::String(BASE64.encode(signature.to_bytes()));
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::PACK_KEY_ENV_LOCK as ENV_LOCK;
    use super::*;
    use crate::corpus::schema::NameUses;

    fn parse(name: &str, text: &str) -> Result<CustomPack, Vec<String>> {
        parse_pack(text, Path::new(name))
    }

    const COMPACT: &str = r#"
pack:
  id: acme-rules
  name: ACME internal rules
rules:
  - id: ACME-001
    pattern: 'internal-artifacts\.acme\.example'
    severity: medium
    description: Reference to the internal artifact mirror
    extensions: [py, .js]
    exclude_paths: [tests/]
    remediation: Internal mirrors must not appear in published skills.
    tags: [acme]
"#;

    #[test]
    fn compact_yaml_converts_to_the_full_schema() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let p = parse("acme.yaml", COMPACT).expect("compact pack parses");
        assert_eq!(p.form, PackForm::Compact);
        assert_eq!(p.pack.meta.id, "acme-rules");
        let r = &p.pack.rules[0];
        assert_eq!(r.id, "ACME-001");
        assert_eq!(r.phase, "code_patterns", "phase defaults to code_patterns");
        assert_eq!(r.file_filter.extensions, vec!["py", "js"]);
        assert_eq!(r.suppress.path_contains, vec!["tests/"]);
        assert_eq!(p.signature, SignatureStatus::Unsigned);
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }

    #[test]
    fn a_bare_list_of_rules_is_a_compact_pack_named_after_the_file() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let text = "- id: ORG-1\n  pattern: 'foo\\d+'\n  severity: low\n  title: foo\n";
        let p = parse("org.yml", text).expect("parses");
        assert_eq!(p.pack.meta.id, "custom.org");
        assert_eq!(p.pack.rules[0].description, "foo");
    }

    #[test]
    fn full_schema_json_and_yaml_both_load() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let json = r#"{"meta":{"id":"org-pack","name":"Org","version":"1.0.0","updated_at":"2026-09-01","author":"sec","description":"d"},
            "rules":[{"id":"ORG-100","phase":"network_exfil","severity":"high","pattern":"exfil\\.example","description":"d","remediation":"r"}]}"#;
        let p = parse("org.json", json).expect("json parses");
        assert_eq!(p.form, PackForm::Full);
        assert_eq!(p.pack.rules[0].phase, "network_exfil");

        let yaml = "meta: {id: org-pack, name: Org, version: 1.0.0, updated_at: '2026-09-01', author: sec, description: d}\nrules:\n  - {id: ORG-100, phase: credentials, severity: low, pattern: 'x\\d', description: d, remediation: r}\n";
        let p = parse("org.yaml", yaml).expect("yaml parses");
        assert_eq!(p.pack.rules[0].severity, "low");
    }

    #[test]
    fn every_error_is_reported_with_the_rule_it_belongs_to() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let text = r#"
rules:
  - id: ACME-001
    patern: 'x'
    severity: medium
    description: d
  - id: acme_2
    pattern: '(unclosed'
    severity: severe
    description: d
    phase: networking
  - id: ACME-003
    pattern: 'a*'
    severity: low
    description: d
"#;
        let errs = parse("bad.yaml", text).expect_err("must fail");
        let all = errs.join("\n");
        assert!(
            all.contains("rules[0] (ACME-001): unknown key 'patern' (did you mean 'pattern'?)"),
            "{all}"
        );
        assert!(
            all.contains("rules[0] (ACME-001): missing required `pattern`"),
            "{all}"
        );
        assert!(all.contains("rule id 'acme_2' must look like"), "{all}");
        assert!(all.contains("pattern is not a valid Rust regex"), "{all}");
        assert!(all.contains("severity 'severe' is not one of"), "{all}");
        assert!(all.contains("unknown phase 'networking'"), "{all}");
        assert!(all.contains("matches the empty string"), "{all}");
    }

    #[test]
    fn an_oversized_weight_is_refused_so_the_score_cannot_wrap() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        // 3 (High) x 1431655766 wraps u32 to 2: a High rule that scores nothing.
        let text = "rules:\n  - {id: ACME-1, pattern: 'eval', severity: high, description: d, weight: 1431655766}\n";
        let errs = parse("w.yaml", text).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| e.contains("weight 1431655766 is too large")),
            "{errs:?}"
        );
        // The largest allowed weight, and the built-in range, load.
        let ok = format!(
            "rules:\n  - {{id: ACME-1, pattern: 'eval', severity: high, description: d, weight: {MAX_CUSTOM_WEIGHT}}}\n"
        );
        assert!(parse("w.yaml", &ok).is_ok());
    }

    #[test]
    fn a_correlation_window_above_the_sink_is_bounded() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let pack = |before: usize| {
            format!(
                r#"{{"meta":{{"id":"p","name":"p","version":"1","updated_at":"","author":"","description":""}},
                "correlation_rules":[{{"id":"P-CHAIN-1","phase":"network_exfil","severity":"high","description":"d",
                "source":{{"rule_ids":["P-1"]}},"sink":{{"rule_ids":["P-2"]}},"sink_window_before":{before}}}]}}"#
            )
        };
        let errs = parse("p.json", &pack(100_000)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| e.contains("sink_window_before 100000 is too large")),
            "{errs:?}"
        );
        let ok = parse("p.json", &pack(MAX_SINK_WINDOW_BEFORE)).expect("the limit loads");
        assert_eq!(
            ok.pack.correlation_rules[0].sink_window_before,
            MAX_SINK_WINDOW_BEFORE
        );
    }

    #[test]
    fn a_chain_can_read_names_as_values_and_the_digest_covers_it() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let pack = |extra: &str| {
            format!(
                r#"{{"meta":{{"id":"p","name":"p","version":"1","updated_at":"","author":"","description":""}},
                "correlation_rules":[{{"id":"P-CHAIN-1","phase":"network_exfil","severity":"high","description":"d",
                "source":{{"rule_ids":["P-1"]}},"sink":{{"rule_ids":["P-2"]}}{extra}}}]}}"#
            )
        };
        let word = parse("p.json", &pack("")).expect("the default loads");
        let value = parse("p.json", &pack(r#","name_uses":"value""#)).expect("value loads");
        assert_eq!(word.pack.correlation_rules[0].name_uses, NameUses::Word);
        assert_eq!(value.pack.correlation_rules[0].name_uses, NameUses::Value);
        let errs = parse("p.json", &pack(r#","name_uses":"values""#)).expect_err("must fail");
        assert!(
            errs.iter().any(|e| e.contains("correlation_rules")),
            "{errs:?}"
        );
        // A cached result is reused only under the same digest, and the two
        // readings link different code.
        let digest = |p: &CustomPack| {
            crate::corpus::compiled::CompiledCorpus::from_packs(std::slice::from_ref(&p.pack))
                .digest()
        };
        assert_ne!(digest(&word), digest(&value));
    }

    #[test]
    fn a_correlation_rule_states_how_it_reads_names() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let pack = |extra: &str| {
            format!(
                r#"{{"meta":{{"id":"p","name":"p","version":"1","updated_at":"","author":"","description":""}},
                "correlation_rules":[{{"id":"P-CHAIN-1","phase":"network_exfil","severity":"high","description":"d",
                "source":{{"rule_ids":["P-1"]}},"sink":{{"rule_ids":["P-2"]}}{extra}}}]}}"#
            )
        };
        for (extra, want) in [
            (r#","name_uses":"value""#, NameUses::Value),
            (r#","name_uses":"word""#, NameUses::Word),
            ("", NameUses::Word),
        ] {
            let ok = parse("p.json", &pack(extra)).expect("loads");
            assert_eq!(ok.pack.correlation_rules[0].name_uses, want, "{extra}");
        }
        let yaml =
            "meta: {id: p, name: p, version: '1', updated_at: '', author: '', description: ''}\n\
            correlation_rules:\n\
            \x20 - id: P-CHAIN-1\n\
            \x20   phase: network_exfil\n\
            \x20   severity: high\n\
            \x20   description: d\n\
            \x20   source: {rule_ids: [P-1]}\n\
            \x20   sink: {rule_ids: [P-2]}\n\
            \x20   name_uses: value\n";
        let ok = parse("p.yaml", yaml).expect("YAML loads");
        assert_eq!(ok.pack.correlation_rules[0].name_uses, NameUses::Value);
        // An unknown value is refused, naming the ones that exist.
        let errs = parse("p.json", &pack(r#","name_uses":"values""#)).expect_err("must fail");
        assert!(
            errs.iter()
                .any(|e| e.contains("unknown variant `values`") && e.contains("`value`")),
            "{errs:?}"
        );
        // A misspelt key would fall back to the default without a word. The
        // pack still loads (earlier versions accepted any key on a
        // correlation rule, and a signed pack cannot be edited without
        // re-signing), and the key is named with a hint for the warning
        // the scan prints and the error `sigil rules validate` reports.
        let ok = parse("p.json", &pack(r#","name_use":"value""#)).expect("still loads");
        assert_eq!(ok.pack.correlation_rules[0].name_uses, NameUses::Word);
        assert!(
            ok.ignored
                .iter()
                .any(|e| e.contains("correlation_rules[0] (P-CHAIN-1)")
                    && e.contains("did you mean 'name_uses'")),
            "{:?}",
            ok.ignored
        );
        assert!(ok.warnings.iter().all(|w| !w.contains("name_use")));
        // A pack without problems has nothing ignored.
        assert!(parse("p.json", &pack(""))
            .expect("loads")
            .ignored
            .is_empty());
    }

    /// `name_uses: null`, or `name_uses:` with no value in YAML, is the
    /// default, as leaving the field out is: a pack that carried it loaded
    /// before the field existed (the key was ignored), and refusing it would
    /// drop every rule in the pack.
    #[test]
    fn a_null_name_reading_is_the_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let json = r#"{"meta":{"id":"p","name":"p","version":"1","updated_at":"","author":"","description":""},
            "correlation_rules":[{"id":"P-CHAIN-1","phase":"network_exfil","severity":"high","description":"d",
            "source":{"rule_ids":["P-1"]},"sink":{"rule_ids":["P-2"]},"name_uses":null}]}"#;
        let ok = parse("p.json", json).expect("null loads");
        assert_eq!(ok.pack.correlation_rules[0].name_uses, NameUses::Word);
        assert!(ok.ignored.is_empty(), "{:?}", ok.ignored);
        let yaml =
            "meta: {id: p, name: p, version: '1', updated_at: '', author: '', description: ''}\n\
            correlation_rules:\n\
            \x20 - id: P-CHAIN-1\n\
            \x20   phase: network_exfil\n\
            \x20   severity: high\n\
            \x20   description: d\n\
            \x20   source: {rule_ids: [P-1]}\n\
            \x20   sink: {rule_ids: [P-2]}\n\
            \x20   name_uses:\n";
        let ok = parse("p.yaml", yaml).expect("an empty YAML value loads");
        assert_eq!(ok.pack.correlation_rules[0].name_uses, NameUses::Word);
        // Any other value that is not `word` or `value` is still refused.
        let bad = json.replace("\"name_uses\":null", "\"name_uses\":1");
        assert!(parse("p.json", &bad).is_err());
    }

    /// An extra key on a correlation rule (a note for the team that owns
    /// it) loaded before the keys were checked; it still loads, with the
    /// key ignored and named. So does a misspelt selector key, which leaves
    /// the selector empty: that chain never fires, and says so.
    #[test]
    fn unknown_correlation_keys_are_ignored_with_a_warning() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let extra = r#"{"meta":{"id":"acme","name":"acme","version":"1","updated_at":"2026-01-01","author":"a","description":"d"},
            "correlation_rules":[{"id":"ACME-CHAIN-001","phase":"network_exfil","severity":"high","description":"acme chain",
            "source":{"rule_prefixes":["CRED-"],"rule_ids":[]},"sink":{"rule_prefixes":[],"rule_ids":["NET-001"]},
            "window_lines":20,"sink_excludes":[],"notes":"owned by the platform team"}]}"#;
        let ok = parse("pack_extra.json", extra).expect("an extra key does not refuse the pack");
        assert_eq!(ok.pack.correlation_rules.len(), 1);
        assert_eq!(ok.ignored.len(), 1, "{:?}", ok.ignored);
        assert!(
            ok.ignored[0].contains("correlation_rules[0] (ACME-CHAIN-001): unknown key 'notes'")
        );
        let selector = extra
            .replace(r#""rule_ids":["NET-001"]"#, r#""rule_idz":["NET-001"]"#)
            .replace(r#","notes":"owned by the platform team""#, "");
        let ok = parse("pack_sel.json", &selector).expect("loads");
        assert!(
            ok.ignored.iter().any(|e| e
                .contains("correlation_rules[0] (ACME-CHAIN-001).sink: unknown key 'rule_idz'")
                && e.contains("did you mean 'rule_ids'")),
            "{:?}",
            ok.ignored
        );
        assert!(
            ok.ignored
                .iter()
                .any(|e| e.contains(".sink: names no rule")),
            "{:?}",
            ok.ignored
        );
        // Signing makes a new pack, and refuses what a scan would ignore.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("pack_extra.json");
        std::fs::write(&file, extra).expect("write");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let err = sign_file(&file, &key).expect_err("signing refuses an unknown key");
        assert!(err.contains("unknown key 'notes'"), "{err}");
    }

    #[test]
    fn misspelt_full_schema_keys_are_errors_not_silently_ignored() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let json = r#"{"meta":{"id":"p","name":"p","version":"1","updated_at":"","author":"","description":""},
            "rules":[{"id":"P-1","phase":"code_patterns","severity":"low","pattern":"x\\d","description":"d","supress":{}}]}"#;
        let errs = parse("p.json", json).expect_err("must fail");
        assert!(
            errs.iter().any(|e| e.contains("did you mean 'suppress'")),
            "{errs:?}"
        );
    }

    #[test]
    fn collisions_with_built_in_packs_and_rules_are_refused() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let base = super::super::loader::load_base_packs().expect("base packs");
        let core_pack = base[0].meta.id.clone();
        let core_rule = base[0].rules[0].id.clone();

        let replace = format!(
            "pack: {{id: {core_pack}}}\nrules:\n  - {{id: ACME-9, pattern: 'q\\d', severity: low, description: d}}\n"
        );
        let redefine = format!(
            "rules:\n  - {{id: {core_rule}, pattern: 'q\\d', severity: low, description: d}}\n"
        );
        let a = parse("replace.yaml", &replace).unwrap();
        let b = parse("redefine.yaml", &redefine).unwrap();
        let errs = check_against(&base, &[a, b]);
        assert!(
            errs.iter()
                .any(|e| e.contains(&core_pack) && e.contains("cannot replace")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains(&core_rule) && e.contains("already defined")),
            "{errs:?}"
        );

        // Two custom packs defining the same id also collide.
        let c1 = parse(
            "c1.yaml",
            "rules:\n  - {id: DUP-1, pattern: 'q\\d', severity: low, description: d}\n",
        )
        .unwrap();
        let c2 = parse(
            "c2.yaml",
            "rules:\n  - {id: DUP-1, pattern: 'z\\d', severity: low, description: d}\n",
        )
        .unwrap();
        let errs = check_against(&base, &[c1, c2]);
        assert!(errs.iter().any(|e| e.contains("DUP-1")), "{errs:?}");
    }

    #[test]
    fn a_directory_loads_every_pack_in_name_order() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("b.yaml"),
            "rules:\n  - {id: B-1, pattern: 'b\\d', severity: low, description: d}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("a.json"),
            r#"[{"id":"A-1","pattern":"a\\d","severity":"low","description":"d"}]"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "not a pack").unwrap();
        let packs = load_path(dir.path()).expect("dir loads");
        let ids: Vec<&str> = packs.iter().map(|p| p.pack.rules[0].id.as_str()).collect();
        assert_eq!(ids, vec!["A-1", "B-1"]);

        let empty = tempfile::tempdir().unwrap();
        assert!(
            load_path(empty.path()).is_err(),
            "an empty directory is an error"
        );
    }

    fn keypair() -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk = hex::encode(sk.verifying_key().to_bytes());
        (sk, vk)
    }

    #[test]
    fn signed_packs_verify_and_unsigned_ones_are_refused_when_keyed() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("acme.yaml");
        std::fs::write(&src, COMPACT).unwrap();
        let (sk, vk) = keypair();

        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let signed = sign_file(&src, &sk).expect("signs");
        let signed_path = dir.path().join("acme.signed.json");
        std::fs::write(&signed_path, &signed).unwrap();

        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", &vk);
        let verified = load_file(&signed_path);
        let unsigned = load_file(&src);
        // Tamper: change the pattern after signing.
        let tampered_path = dir.path().join("tampered.json");
        std::fs::write(
            &tampered_path,
            signed.replace("internal-artifacts", "internal-artefacts"),
        )
        .unwrap();
        let tampered = load_file(&tampered_path);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");

        let verified = verified.expect("signed pack verifies");
        assert_eq!(verified.signature, SignatureStatus::Verified);
        assert_eq!(verified.pack.rules[0].id, "ACME-001");
        assert!(unsigned.unwrap_err().contains("[SECURITY]"));
        assert!(tampered.unwrap_err().contains("[SECURITY]"));
    }

    #[test]
    fn signing_keys_load_from_pkcs8_pem_and_hex() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        let dir = tempfile::tempdir().unwrap();
        let seed = [9u8; 32];
        let mut der = PKCS8_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&seed);
        let pem = format!(
            "{PEM_PRIVATE_KEY_LABEL}\n{}\n-----END PRIVATE KEY-----\n",
            BASE64.encode(&der)
        );
        let pem_path = dir.path().join("k.pem");
        std::fs::write(&pem_path, pem).unwrap();
        let hex_path = dir.path().join("k.hex");
        std::fs::write(&hex_path, hex::encode(seed)).unwrap();
        let a = read_signing_key(&pem_path).expect("pem");
        let b = read_signing_key(&hex_path).expect("hex");
        assert_eq!(a.to_bytes(), b.to_bytes());

        let bad = dir.path().join("bad.txt");
        std::fs::write(&bad, "nope").unwrap();
        assert!(read_signing_key(&bad).is_err());
    }

    #[test]
    fn closest_suggests_near_misses_only() {
        assert_eq!(closest("patern", COMPACT_RULE_KEYS), Some("pattern"));
        assert_eq!(closest("sevrity", COMPACT_RULE_KEYS), Some("severity"));
        assert_eq!(closest("zzzzzz", COMPACT_RULE_KEYS), None);
    }
}
