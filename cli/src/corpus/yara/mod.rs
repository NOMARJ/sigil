//! YARA rule files (`.yar`, `.yara`) as Sigil custom rules.
//!
//! Security teams keep their detections in YARA. Sigil reads those files
//! natively: a parser and an evaluator for the string-matching core of the
//! language, built on the `regex-automata` engine the `regex` crate already
//! runs on — no libyara, no FFI, no new dependency, and linear-time matching
//! whatever the scanned bytes are.
//!
//! **Full YARA** ([`external`]). A file that uses anything outside the
//! subset (modules and `import`, `for` loops, `uint32()` and friends,
//! `@a[i]`/`!a[i]`, string operators, `xor`/`base64` modifiers, ...) is
//! evaluated by an installed YARA-X (`yr`) or YARA (`yara`), as
//! `--yara-engine` selects ([`analyze`]); the built-in parser then reads only
//! its declarations (names, tags, meta) for ids and reporting. Each such
//! construct is a problem tagged `parse::NEEDS_ENGINE`, so it is told apart
//! from a rule YARA itself refuses.
//!
//! **Fail closed.** A problem YARA itself refuses (an undefined string,
//! `include`, an external variable), and under `--yara-engine builtin` any
//! construct outside the subset, is an error naming the construct and its
//! `file:line`. A pack with any error is refused as a whole, exactly like a
//! JSON or YAML pack: a rule that silently does not run is a detection gap
//! nobody notices. A file that needs an engine the machine does not have
//! loads unevaluated and every scan reports it as incomplete coverage. The
//! subset and the engines are documented in `docs/enterprise.md` ("YARA
//! rules", "Full YARA: external engines").
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
pub mod external;
mod parse;
mod strings;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use eval::{scan, Segment, Subject, CONTEXT_BYTES};
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
    /// What evaluates it.
    pub engine: FileEngine,
}

impl YaraFile {
    /// Rules that can produce a finding.
    pub fn public_rules(&self) -> impl Iterator<Item = &YaraRule> {
        self.rules.iter().filter(|r| !r.private)
    }

    /// Evaluated by the built-in engine ([`scan`]).
    pub fn is_builtin(&self) -> bool {
        matches!(self.engine, FileEngine::Builtin)
    }
}

/// What evaluates a YARA file (see `--yara-engine`, [`external`]).
#[derive(Debug, Clone)]
pub enum FileEngine {
    /// Sigil's built-in engine, over each file's bytes ([`eval`]).
    Builtin,
    /// An external engine, given the exact bytes Sigil verified and
    /// validated at load, never the file on disk again.
    External {
        engine: Arc<external::Engine>,
        source: Arc<[u8]>,
    },
    /// Nothing: the file needs an external engine and none can be used
    /// here. Every scan reports it as incomplete coverage
    /// (`PROV-INCOMPLETE-001`).
    Unevaluated {
        /// Why the built-in engine cannot evaluate it, one line each.
        reasons: Vec<String>,
        /// Why no external engine could take it (not installed, found only
        /// inside the scanned tree, or not usable), one clause per engine.
        unavailable: String,
    },
}

impl FileEngine {
    /// A short description, for `sigil rules`, `sigil corpus` and the
    /// corpus digest.
    pub fn label(&self) -> String {
        match self {
            FileEngine::Builtin => "built-in".to_string(),
            FileEngine::External { engine, .. } => engine.label(),
            FileEngine::Unevaluated { .. } => "not evaluated (no external engine)".to_string(),
        }
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
    /// Empty for a rule an external engine evaluates: its strings and
    /// condition are the engine's (see [`YaraFile::engine`]).
    pub strings: Vec<CompiledString>,
    /// `false` for a rule an external engine evaluates; never read then.
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
/// Line 0 is a problem with the file as a whole.
pub type Compiled = Result<(YaraFile, Vec<String>), Vec<(usize, String)>>;

/// What a rule's `meta:` section tells Sigil.
struct RuleMeta {
    description: Option<String>,
    author: Option<String>,
    references: Vec<String>,
    severity: Option<Severity>,
    phase: Option<Phase>,
    remediation: Option<String>,
}

/// Read the meta keys Sigil uses. A severity or phase Sigil cannot read is an
/// error whatever evaluates the rule; a near miss of a key is a warning.
fn read_meta(
    rule: &str,
    entries: &[parse::MetaEntry],
    path: &Path,
    errors: &mut Vec<(usize, String)>,
    warnings: &mut Vec<String>,
) -> RuleMeta {
    let mut m = RuleMeta {
        description: None,
        author: None,
        references: Vec::new(),
        severity: None,
        phase: None,
        remediation: None,
    };
    for e in entries {
        let text = match &e.value {
            parse::MetaValue::Str(s) => Some(s.clone()),
            _ => None,
        };
        let key = e.key.to_ascii_lowercase();
        match key.as_str() {
            "description" => m.description = text.filter(|s| !s.trim().is_empty()),
            "author" => m.author = text,
            "reference" => m.references.extend(text),
            "remediation" => m.remediation = text.filter(|s| !s.trim().is_empty()),
            "severity" => match text.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
                Some(s) => match parse_severity(&s) {
                    Some(v) => m.severity = Some(v),
                    None => errors.push((
                        e.line,
                        format!(
                            "rule `{rule}`: severity \"{s}\" is not one of critical, high, \
                             medium, low"
                        ),
                    )),
                },
                None => errors.push((
                    e.line,
                    format!(
                        "rule `{rule}`: severity must be a text value: \"critical\", \"high\", \
                         \"medium\" or \"low\""
                    ),
                )),
            },
            "phase" => match text.as_deref().map(Phase::from_name) {
                Some(Some(p)) => m.phase = Some(p),
                _ => {
                    let names: Vec<&str> = Phase::ALL.iter().map(|p| p.canonical_name()).collect();
                    errors.push((
                        e.line,
                        format!("rule `{rule}`: phase must be one of {}", names.join(", ")),
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
                        "{}:{}: rule `{rule}`: meta `{}` is not read by Sigil (did you mean \
                         `{k}`?)",
                        path.display(),
                        e.line,
                        e.key
                    ));
                }
            }
        }
    }
    m
}

/// The parts of a rule both engines share: its declaration and meta.
struct Declared {
    name: String,
    line: usize,
    private: bool,
    global: bool,
    tags: Vec<String>,
    source: String,
}

/// Turn a declaration into a rule, or record why it cannot be one.
fn declare(
    d: Declared,
    meta: RuleMeta,
    strings: Vec<CompiledString>,
    condition: Expr,
    rules: &[YaraRule],
    errors: &mut Vec<(usize, String)>,
) -> Option<YaraRule> {
    let Some(id) = sigil_id(&d.name) else {
        errors.push((
            d.line,
            format!(
                "rule `{}` has no letters or digits to form a Sigil id from",
                d.name
            ),
        ));
        return None;
    };
    if let Some(prev) = rules.iter().find(|r| r.id == id) {
        errors.push((
            d.line,
            format!(
                "rules `{}` (line {}) and `{}` both become Sigil id {id}; rename one",
                prev.name, prev.line, d.name
            ),
        ));
    }
    Some(YaraRule {
        description: meta
            .description
            .unwrap_or_else(|| default_description(&d.name)),
        name: d.name,
        id,
        line: d.line,
        private: d.private,
        global: d.global,
        tags: d.tags,
        author: meta.author,
        references: meta.references,
        severity: meta.severity.unwrap_or(DEFAULT_SEVERITY),
        phase: meta.phase.unwrap_or(DEFAULT_PHASE),
        remediation: meta.remediation,
        strings,
        condition,
        source: d.source,
    })
}

/// Parse and compile YARA source for the built-in engine. Warnings are
/// messages about rules that load but may not do what the author meant.
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
        let meta = read_meta(&ast.name, &ast.meta, path, &mut errors, &mut warnings);
        let complete = strings.len() == ast.strings.len();
        let declared = Declared {
            name: ast.name,
            line: ast.line,
            private: ast.private,
            global: ast.global,
            tags: ast.tags,
            source: ast.source,
        };
        if let Some(rule) = declare(declared, meta, strings, ast.condition, &rules, &mut errors) {
            if complete {
                rules.push(rule);
            }
        }
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
            engine: FileEngine::Builtin,
        },
        warnings,
    ))
}

/// A file whose strings and conditions another engine evaluates, or none
/// can: its rules as declared, from [`parse::outline`]. `include` and a
/// file that is not readable YARA are refused here, whatever the engine.
fn declared_rules(src: &str, path: &Path, engine: FileEngine) -> Compiled {
    let outline = parse::outline(src);
    let mut errors = outline.errors;
    let mut warnings = Vec::new();
    let mut rules: Vec<YaraRule> = Vec::with_capacity(outline.rules.len());
    for h in outline.rules {
        let meta = read_meta(&h.name, &h.meta, path, &mut errors, &mut warnings);
        let declared = Declared {
            name: h.name,
            line: h.line,
            private: h.private,
            global: h.global,
            tags: h.tags,
            source: h.source,
        };
        if let Some(rule) = declare(
            declared,
            meta,
            Vec::new(),
            Expr::Bool(false),
            &rules,
            &mut errors,
        ) {
            rules.push(rule);
        }
    }
    if rules.is_empty() && errors.is_empty() {
        errors.push((1, "no rules in this file".to_string()));
    }
    if !errors.is_empty() {
        errors.sort_by_key(|(line, _)| *line);
        return Err(errors);
    }
    Ok((
        YaraFile {
            path: path.to_path_buf(),
            rules,
            engine,
        },
        warnings,
    ))
}

/// Compile a YARA file for the engine `sel` chooses (`--yara-engine`):
///
/// - `builtin`: the built-in engine, which refuses what it cannot evaluate;
/// - `yara-x` / `yara`: that external engine, which must be installed;
/// - `auto`: the built-in engine when it can evaluate the whole file; when
///   every problem it has is valid YARA outside its subset, an installed
///   external engine (YARA-X first), or, with none installed, the file is
///   loaded unevaluated and every scan reports it as incomplete coverage. A
///   file with any other problem is refused, as before.
///
/// An external engine's own check of the file runs afterwards, over every
/// file of a load at once ([`external::validate_packs`]).
pub fn analyze(src: &str, bytes: &[u8], path: &Path, sel: &external::Selection) -> Compiled {
    let delegate = |engine: Arc<external::Engine>| {
        declared_rules(
            src,
            path,
            FileEngine::External {
                engine,
                source: Arc::from(bytes),
            },
        )
    };
    match sel.mode {
        external::EngineMode::Builtin => compile_rules(src, path),
        external::EngineMode::YaraX | external::EngineMode::Yara => {
            let kind = if sel.mode == external::EngineMode::YaraX {
                external::EngineKind::YaraX
            } else {
                external::EngineKind::Yara
            };
            let engine = sel.engine(kind).map_err(|e| {
                vec![(
                    0,
                    format!("--yara-engine {} ({}): {e}", sel.mode.name(), sel.source),
                )]
            })?;
            delegate(engine)
        }
        external::EngineMode::Auto | external::EngineMode::BestEffort => {
            match compile_rules(src, path) {
                Ok(compiled) => Ok(compiled),
                Err(problems) => {
                    if problems.iter().any(|(_, m)| !parse::needs_engine(m)) {
                        return Err(problems);
                    }
                    match sel.auto_engine() {
                        Some(engine) => delegate(engine),
                        // Fail closed: rules an organisation wrote must not stop
                        // running because this machine has no engine for them.
                        None if sel.mode == external::EngineMode::Auto => {
                            let mut refused = problems;
                            refused.push((
                                0,
                                format!(
                                "these rules need an external YARA engine and none can be used \
                                 here ({}). Install YARA-X or YARA, or set yara_engine: \
                                 best-effort (--yara-engine best-effort) to load them \
                                 unevaluated and report every scan as not fully inspected",
                                sel.unavailable()
                            ),
                            ));
                            Err(refused)
                        }
                        None => declared_rules(
                            src,
                            path,
                            FileEngine::Unevaluated {
                                reasons: problems
                                    .iter()
                                    .map(|(line, m)| {
                                        format!(
                                            "line {line}: {}",
                                            m.replace(parse::NEEDS_ENGINE, "").trim_end()
                                        )
                                    })
                                    .collect(),
                                unavailable: sel.unavailable(),
                            },
                        ),
                    }
                }
            }
        }
    }
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

/// Problems as `path:line: message` (`path: message` for line 0).
fn located(path: &Path, errs: Vec<(usize, String)>) -> Vec<String> {
    errs.into_iter()
        .map(|(line, msg)| {
            if line == 0 {
                format!("{}: {msg}", path.display())
            } else {
                format!("{}:{line}: {msg}", path.display())
            }
        })
        .collect()
}

/// Where the detached signature of `path` lives: `<path>.sig`.
pub fn signature_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(SIGNATURE_SUFFIX);
    PathBuf::from(s)
}

/// Verify, parse and compile one YARA file into a custom pack. Every error
/// is `path:line: message`, or `path: message` when no line applies.
///
/// The engine is the one `--yara-engine` (or the policy's `yara_engine`)
/// selects. A file handed to an external engine is not yet checked by it:
/// [`external::validate_packs`] does that for every file of a load at once,
/// and `custom::load_file`/`load_path` always call it.
pub fn parse_pack(bytes: &[u8], path: &Path) -> Result<CustomPack, Vec<String>> {
    parse_pack_with(bytes, path, &external::Selection::current())
}

/// [`parse_pack`] with an explicit engine selection.
pub fn parse_pack_with(
    bytes: &[u8],
    path: &Path,
    sel: &external::Selection,
) -> Result<CustomPack, Vec<String>> {
    let here = path.display();
    let signature = signature_status(bytes, path).map_err(|e| vec![format!("{here}: {e}")])?;
    let src = std::str::from_utf8(bytes)
        .map_err(|e| vec![format!("{here}: a YARA file must be UTF-8 text: {e}")])?;
    let (file, warnings) = analyze(src, bytes, path, sel).map_err(|errs| located(path, errs))?;

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
    // Checked by the engine that will evaluate it, as a load would.
    let (file, _) = analyze(src, &bytes, path, &external::Selection::current())
        .map_err(|errs| located(path, errs).join("\n"))?;
    if let FileEngine::Unevaluated {
        reasons,
        unavailable,
    } = &file.engine
    {
        return Err(format!(
            "{}: not signed: it needs an external YARA engine to be checked, and none can be \
             used here ({unavailable}; {})",
            path.display(),
            reasons.first().map(String::as_str).unwrap_or("")
        ));
    }
    external::validate_files(&[&file]).map_err(|errs| errs.join("\n"))?;
    let signature = key.sign(&signed_message(&bytes));
    Ok(format!("{}\n", BASE64.encode(signature.to_bytes())))
}
