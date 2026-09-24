//! YARA rule files (`.yar`, `.yara`) as Sigil custom rules.
//!
//! Security teams keep their detections in YARA. Sigil reads those files
//! natively: a parser and an evaluator for the string-matching core of the
//! language, built on the `regex-automata` engine the `regex` crate already
//! runs on — no libyara, no FFI, no new dependency, and linear-time matching
//! whatever the scanned bytes are.
//!
//! **Fail closed.** Anything outside the subset (modules and `import`,
//! `include`, `for` loops, `uint32()` and friends, `@a[i]`/`!a[i]`, string
//! operators, external variables, `xor`/`base64` modifiers, ...) is an error
//! naming the construct and its `file:line`. A pack with any error is refused
//! as a whole, exactly like a JSON or YAML pack: a rule that silently does not
//! run is a detection gap nobody notices. The subset is documented in
//! `docs/enterprise.md` ("YARA rules").
//!
//! **Identity.** Each rule becomes Sigil rule `YARA-<NAME>`: the rule name
//! upper-cased with `_` turned into `-`, so `sigil:ignore` markers, policy
//! globs (`YARA-*`) and `severity_overrides` address it like any other rule.
//! A file is one pack, `yara.<file stem>`; packs are additive, and an id that
//! collides with any loaded rule is refused (`custom::check_against`).
//!
//! **Signing.** A `.yar` file cannot carry a signature inside it, so it is
//! signed detached: `<file>.sig` beside it holds a base64 Ed25519 signature
//! over the file's exact bytes (domain-separated, see [`SIGNATURE_CONTEXT`]).
//! With `SIGIL_PACK_PUBLIC_KEY` set, an unsigned or badly signed `.yar` is
//! refused like any other custom pack.
//!
//! **Evaluation** ([`eval`]) is YARA's: raw bytes, whole file, binary files
//! included; see `scanner::run_scan` for which units are evaluated.

mod eval;
mod parse;
mod strings;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use eval::{scan, Segment, Subject};
pub use strings::CompiledString;

use super::custom::{CustomPack, PackForm, SignatureStatus};
use super::schema::{PackMeta, SignaturePack};
use crate::scanner::{Phase, Severity};

/// Phase a rule reports under when its meta names none.
pub const DEFAULT_PHASE: Phase = Phase::CodePatterns;

/// Severity a rule reports at when its meta names none.
pub const DEFAULT_SEVERITY: Severity = Severity::Medium;

/// Extension of the detached signature beside a rule file.
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Prefixed to the file's bytes before signing, so a signature over a YARA
/// file can never be replayed as the signature of anything else Sigil
/// verifies (a JSON pack's signature covers its canonical JSON, which can
/// never begin with these bytes).
pub const SIGNATURE_CONTEXT: &[u8] = b"sigil-yara-detached-signature-v1\n";

/// Meta keys Sigil reads. Any other key is carried by YARA for people and
/// ignored here, as YARA itself ignores it.
const KNOWN_META: &[&str] = &[
    "description",
    "author",
    "reference",
    "severity",
    "phase",
    "remediation",
];

// ---------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

/// How many strings of a set must match.
#[derive(Debug, Clone)]
pub enum Quant {
    Any,
    All,
    None,
    AtLeast(Box<Expr>),
    Percent(Box<Expr>),
}

/// A condition, with string and rule names resolved to indices.
#[derive(Debug, Clone)]
pub enum Expr {
    Bool(bool),
    Int(i64),
    Filesize,
    /// `$a`
    Str(usize),
    /// `$a at N`
    StrAt(usize, Box<Expr>),
    /// `$a in (N..M)`
    StrIn(usize, Box<Expr>, Box<Expr>),
    /// `#a`
    Count(usize),
    /// `any/all/none/N/N% of <set>`
    Of(Quant, Vec<usize>),
    /// A rule defined earlier in the same file.
    RuleRef(usize),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Arith(ArithOp, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
}

/// One `.yar` file, compiled. Rule references are file-scoped, so the file
/// is the unit of evaluation.
#[derive(Debug)]
pub struct YaraFile {
    pub path: PathBuf,
    pub rules: Vec<YaraRule>,
}

impl YaraFile {
    /// Rules that can produce a finding.
    pub fn public_rules(&self) -> impl Iterator<Item = &YaraRule> {
        self.rules.iter().filter(|r| !r.private)
    }
}

/// One rule, compiled.
#[derive(Debug)]
pub struct YaraRule {
    /// The YARA identifier as written.
    pub name: String,
    /// The Sigil rule id, `YARA-<NAME>`.
    pub id: String,
    pub line: usize,
    pub private: bool,
    pub global: bool,
    pub tags: Vec<String>,
    pub description: String,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub severity: Severity,
    pub phase: Phase,
    pub remediation: Option<String>,
    pub strings: Vec<CompiledString>,
    pub condition: Expr,
    /// The rule as written, for `sigil rules show` and the corpus digest.
    pub source: String,
}

impl YaraRule {
    /// The remediation shown with a finding: the rule's own, or a generic
    /// one naming where the rule came from.
    pub fn remediation_or_default(&self, file: &Path) -> String {
        self.remediation.clone().unwrap_or_else(|| {
            format!(
                "Review the matched content against the intent of YARA rule {} ({}); \
                 your security team owns this rule and its guidance.",
                self.name,
                file.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            )
        })
    }
}

/// Is this a YARA rule file (by extension)?
pub fn is_yara_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
}

/// The Sigil rule id for a YARA rule name: `YARA-` + the name upper-cased,
/// `_` to `-`, runs of `-` collapsed. `None` when nothing is left.
pub fn sigil_id(name: &str) -> Option<String> {
    let mut id = String::from("YARA");
    let mut dash = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if dash {
                id.push('-');
                dash = false;
            }
            id.push(c.to_ascii_uppercase());
        } else {
            dash = true;
        }
    }
    (id.len() > "YARA".len()).then_some(id)
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// A compiled file and its warnings, or every problem as `(line, message)`.
pub type Compiled = Result<(YaraFile, Vec<String>), Vec<(usize, String)>>;

/// Parse and compile YARA source. Warnings are messages about rules that
/// load but may not do what the author meant.
pub fn compile_rules(src: &str, path: &Path) -> Compiled {
    let parsed = parse::parse(src);
    let mut errors = parsed.errors;
    let mut warnings = Vec::new();

    let mut rules: Vec<YaraRule> = Vec::with_capacity(parsed.rules.len());
    for ast in parsed.rules {
        let mut strings = Vec::with_capacity(ast.strings.len());
        for s in &ast.strings {
            match strings::build(s) {
                Ok(c) => strings.push(c),
                Err(e) => errors.push((s.line, e)),
            }
        }

        let mut description: Option<String> = None;
        let mut author: Option<String> = None;
        let mut references: Vec<String> = Vec::new();
        let mut severity: Option<Severity> = None;
        let mut phase: Option<Phase> = None;
        let mut remediation: Option<String> = None;
        for m in &ast.meta {
            let text = match &m.value {
                parse::MetaValue::Str(s) => Some(s.clone()),
                _ => None,
            };
            let key = m.key.to_ascii_lowercase();
            match key.as_str() {
                "description" => description = text.filter(|s| !s.trim().is_empty()),
                "author" => author = text,
                "reference" => references.extend(text),
                "remediation" => remediation = text.filter(|s| !s.trim().is_empty()),
                "severity" => match text.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
                    Some(s) => match parse_severity(&s) {
                        Some(v) => severity = Some(v),
                        None => errors.push((
                            m.line,
                            format!(
                                "rule `{}`: severity \"{s}\" is not one of critical, high, \
                                 medium, low",
                                ast.name
                            ),
                        )),
                    },
                    None => errors.push((
                        m.line,
                        format!(
                            "rule `{}`: severity must be a text value: \"critical\", \"high\", \
                             \"medium\" or \"low\"",
                            ast.name
                        ),
                    )),
                },
                "phase" => match text.as_deref().map(Phase::from_name) {
                    Some(Some(p)) => phase = Some(p),
                    _ => {
                        let names: Vec<&str> =
                            Phase::ALL.iter().map(|p| p.canonical_name()).collect();
                        errors.push((
                            m.line,
                            format!(
                                "rule `{}`: phase must be one of {}",
                                ast.name,
                                names.join(", ")
                            ),
                        ));
                    }
                },
                other => {
                    // A near miss of a key Sigil reads is almost certainly a
                    // typo that would silently fall back to a default.
                    if let Some(k) = KNOWN_META
                        .iter()
                        .find(|k| other != **k && edit_distance_is_one(other, k))
                    {
                        warnings.push(format!(
                            "{}:{}: rule `{}`: meta `{}` is not read by Sigil (did you mean \
                             `{k}`?)",
                            path.display(),
                            m.line,
                            ast.name,
                            m.key
                        ));
                    }
                }
            }
        }

        let Some(id) = sigil_id(&ast.name) else {
            errors.push((
                ast.line,
                format!(
                    "rule `{}` has no letters or digits to form a Sigil id from",
                    ast.name
                ),
            ));
            continue;
        };
        if let Some(prev) = rules.iter().find(|r| r.id == id) {
            errors.push((
                ast.line,
                format!(
                    "rules `{}` (line {}) and `{}` both become Sigil id {id}; rename one",
                    prev.name, prev.line, ast.name
                ),
            ));
        }
        if strings.len() != ast.strings.len() {
            continue;
        }
        rules.push(YaraRule {
            description: description.unwrap_or_else(|| default_description(&ast.name)),
            name: ast.name,
            id,
            line: ast.line,
            private: ast.private,
            global: ast.global,
            tags: ast.tags,
            author,
            references,
            severity: severity.unwrap_or(DEFAULT_SEVERITY),
            phase: phase.unwrap_or(DEFAULT_PHASE),
            remediation,
            strings,
            condition: ast.condition,
            source: ast.source,
        });
    }

    if rules.is_empty() && errors.is_empty() {
        errors.push((1, "no rules in this file".to_string()));
    }
    if !errors.is_empty() {
        errors.sort_by_key(|(line, _)| *line);
        return Err(errors);
    }

    // A private rule nobody refers to can never contribute to a finding.
    let mut referenced = vec![false; rules.len()];
    for r in &rules {
        mark_refs(&r.condition, &mut referenced);
    }
    for (r, used) in rules.iter().zip(&referenced) {
        if r.private && !used && !r.global {
            warnings.push(format!(
                "{}:{}: private rule `{}` is not referenced by any rule, so it can never \
                 contribute to a finding",
                path.display(),
                r.line,
                r.name
            ));
        }
    }

    Ok((
        YaraFile {
            path: path.to_path_buf(),
            rules,
        },
        warnings,
    ))
}

/// The title of a rule whose meta has no `description`.
fn default_description(name: &str) -> String {
    format!("YARA rule {name}")
}

fn mark_refs(e: &Expr, out: &mut [bool]) {
    match e {
        Expr::RuleRef(j) => {
            if let Some(slot) = out.get_mut(*j) {
                *slot = true;
            }
        }
        Expr::Not(a) | Expr::Neg(a) | Expr::StrAt(_, a) => mark_refs(a, out),
        Expr::StrIn(_, a, b) | Expr::And(a, b) | Expr::Or(a, b) => {
            mark_refs(a, out);
            mark_refs(b, out);
        }
        Expr::Cmp(_, a, b) | Expr::Arith(_, a, b) => {
            mark_refs(a, out);
            mark_refs(b, out);
        }
        Expr::Of(Quant::AtLeast(a) | Quant::Percent(a), _) => mark_refs(a, out),
        _ => {}
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => return None,
    })
}

fn edit_distance_is_one(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (short, long) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    match long.len() - short.len() {
        0 => a.iter().zip(&b).filter(|(x, y)| x != y).count() == 1,
        1 => (0..long.len()).any(|skip| {
            long.iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, c)| c)
                .eq(short.iter())
        }),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Loading as a custom pack
// ---------------------------------------------------------------------------

/// Where the detached signature of `path` lives: `<path>.sig`.
pub fn signature_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(SIGNATURE_SUFFIX);
    PathBuf::from(s)
}

/// Verify, parse and compile one YARA file into a custom pack. Every error
/// is `path:line: message`, or `path: message` when no line applies.
pub fn parse_pack(bytes: &[u8], path: &Path) -> Result<CustomPack, Vec<String>> {
    let here = path.display();
    let signature = signature_status(bytes, path).map_err(|e| vec![format!("{here}: {e}")])?;
    let src = std::str::from_utf8(bytes)
        .map_err(|e| vec![format!("{here}: a YARA file must be UTF-8 text: {e}")])?;
    let (file, warnings) = compile_rules(src, path).map_err(|errs| {
        errs.into_iter()
            .map(|(line, msg)| format!("{here}:{line}: {msg}"))
            .collect::<Vec<_>>()
    })?;

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "rules".to_string());
    let mut authors: Vec<&str> = Vec::new();
    for a in file.rules.iter().filter_map(|r| r.author.as_deref()) {
        if !authors.contains(&a) {
            authors.push(a);
        }
    }
    let pack = SignaturePack {
        meta: PackMeta {
            id: format!("yara.{stem}"),
            name: path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or(stem),
            version: "0.0.0".to_string(),
            updated_at: String::new(),
            author: authors.join(", "),
            description: format!("YARA rules from {here}"),
        },
        rules: Vec::new(),
        provenance_rules: Vec::new(),
        correlation_rules: Vec::new(),
        engine_rules: Vec::new(),
        yara: Some(Arc::new(file)),
    };
    Ok(CustomPack {
        pack,
        path: path.to_path_buf(),
        form: PackForm::Yara,
        signature,
        warnings,
    })
}

/// Check the detached signature under the `SIGIL_PACK_PUBLIC_KEY` policy
/// every other custom pack is held to.
fn signature_status(bytes: &[u8], path: &Path) -> Result<SignatureStatus, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    let sig_path = signature_path(path);
    let sig_text = match std::fs::read_to_string(&sig_path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", sig_path.display())),
    };
    let key = match std::env::var("SIGIL_PACK_PUBLIC_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return Ok(if sig_text.is_some() {
                SignatureStatus::SignedUnverified
            } else {
                SignatureStatus::Unsigned
            })
        }
    };
    let Some(sig_text) = sig_text else {
        return Err(format!(
            "[SECURITY] SIGIL_PACK_PUBLIC_KEY is set, so rule packs must be signed, and this \
             YARA file has no detached signature {} — create it with `sigil rules sign {} \
             --key <private-key> -o {}`",
            sig_path.display(),
            path.display(),
            sig_path.display()
        ));
    };
    let key_bytes: [u8; 32] = hex::decode(key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            "SIGIL_PACK_PUBLIC_KEY must be 64 hex characters (a 32-byte Ed25519 public key)"
                .to_string()
        })?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("SIGIL_PACK_PUBLIC_KEY is not a valid Ed25519 public key: {e}"))?;
    let sig_bytes = BASE64.decode(sig_text.trim()).map_err(|e| {
        format!(
            "[SECURITY] {} is not a base64 signature: {e}",
            sig_path.display()
        )
    })?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        format!(
            "[SECURITY] {} is not an Ed25519 signature: {e}",
            sig_path.display()
        )
    })?;
    verifying
        .verify_strict(&signed_message(bytes), &signature)
        .map_err(|_| {
            format!(
                "[SECURITY] YARA signature verification failed: {} does not match this file \
                 under SIGIL_PACK_PUBLIC_KEY (edited after signing, or signed with another key)",
                sig_path.display()
            )
        })?;
    Ok(SignatureStatus::Verified)
}

fn signed_message(bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNATURE_CONTEXT.len() + bytes.len());
    msg.extend_from_slice(SIGNATURE_CONTEXT);
    msg.extend_from_slice(bytes);
    msg
}

/// Validate a YARA file and return its detached signature (base64, one
/// line) for `<file>.sig`. An invalid file is not signed.
pub fn sign_detached(path: &Path, key: &ed25519_dalek::SigningKey) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::Signer;
    let bytes = std::fs::read(path)
        .map_err(|e| format!("{}: cannot read rule file: {e}", path.display()))?;
    let src = std::str::from_utf8(&bytes)
        .map_err(|e| format!("{}: a YARA file must be UTF-8 text: {e}", path.display()))?;
    compile_rules(src, path).map_err(|errs| {
        errs.into_iter()
            .map(|(line, msg)| format!("{}:{line}: {msg}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    let signature = key.sign(&signed_message(&bytes));
    Ok(format!("{}\n", BASE64.encode(signature.to_bytes())))
}
