//! `sigil rules`: list, inspect, validate, test and sign detection rules.
//!
//! The corpus is data (ADR-0005), and a reviewer should be able to answer
//! "which rules ran, what does this one match, and what is our policy doing to
//! it" without reading pack JSON by hand. Every listing reflects the active
//! corpus — built-in, released (`~/.sigil/corpus/`), user (`~/.sigil/packs/`)
//! and custom (`--rules`, policy `rule_packs`) — and the effective scan policy
//! (disabled rules, severity overrides).

use std::path::{Path, PathBuf};

use clap::Subcommand;
use colored::Colorize;
use serde_json::json;

use crate::corpus::custom;
use crate::corpus::loader::{self, PackOrigin};
use crate::corpus::schema::{FileFilter, SuppressionPredicates};
use crate::project_config::{rule_glob_matches, EffectivePolicy};
use crate::scanner::Phase;

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List every active rule (built-in, released, user and custom packs)
    List {
        /// Emit JSON (same as --format json)
        #[arg(long)]
        json: bool,
        /// Only rules of this phase, e.g. network_exfil or prompt-injection
        #[arg(long)]
        phase: Option<String>,
    },
    /// Show one rule: pattern, file filter, suppressions, remediation,
    /// references, and what the scan policy does to it
    Show {
        /// Rule id, e.g. CODE-001 (case-insensitive)
        id: String,
    },
    /// Validate a rule pack (JSON or YAML, full schema or compact form; or a
    /// YARA .yar/.yara file) without scanning anything. Exit 0 valid,
    /// 1 invalid, 2 unreadable.
    Validate {
        /// Pack file, or a directory of packs
        path: PathBuf,
    },
    /// Run only a pack's rules over a file or directory and print what fires
    Test {
        /// Pack file, or a directory of packs
        pack: PathBuf,
        /// File or directory to test the rules against
        target: PathBuf,
    },
    /// Sign a rule pack with an Ed25519 private key; writes signed JSON (for
    /// a .yar/.yara file: the detached signature for <file>.sig) to --output
    /// (or stdout) and prints the public key for SIGIL_PACK_PUBLIC_KEY
    Sign {
        /// Pack file to sign (a compact pack is converted to the full schema)
        path: PathBuf,
        /// PKCS#8 PEM key (`openssl genpkey -algorithm ed25519`) or a file
        /// holding the 32-byte seed as 64 hex characters
        #[arg(long)]
        key: PathBuf,
    },
}

/// One rule, whatever kind of entry it came from.
struct RuleRow {
    id: String,
    kind: &'static str,
    phase: String,
    severity: String,
    weight: Option<u32>,
    description: String,
    pack_id: String,
    pack_version: String,
    origin: PackOrigin,
    pattern: Option<String>,
    file_filter: Option<FileFilter>,
    suppress: Option<SuppressionPredicates>,
    evidence: Option<String>,
    remediation: Option<String>,
    references: Vec<String>,
    tags: Vec<String>,
    /// What evaluates a YARA rule (built-in, an external engine, or none).
    engine: Option<String>,
}

fn all_rules() -> Result<Vec<RuleRow>, String> {
    let mut rows = Vec::new();
    for (pack, origin) in loader::load_all_packs_with_origin()? {
        for r in &pack.rules {
            rows.push(RuleRow {
                id: r.id.clone(),
                kind: "content",
                phase: r.phase.clone(),
                severity: r.severity.to_ascii_uppercase(),
                weight: r.weight,
                description: r.description.clone(),
                pack_id: pack.meta.id.clone(),
                pack_version: pack.meta.version.clone(),
                origin,
                pattern: Some(r.pattern.clone()),
                file_filter: Some(r.file_filter.clone()),
                suppress: Some(r.suppress.clone()),
                evidence: Some(format!("{:?}", r.evidence).to_ascii_lowercase()),
                remediation: r.remediation.clone(),
                references: r.references.clone(),
                tags: r.tags.clone(),
                engine: None,
            });
        }
        for r in &pack.provenance_rules {
            rows.push(RuleRow {
                id: r.id.clone(),
                kind: "provenance",
                phase: "provenance".to_string(),
                severity: r.severity.to_ascii_uppercase(),
                weight: None,
                description: r.description.clone(),
                pack_id: pack.meta.id.clone(),
                pack_version: pack.meta.version.clone(),
                origin,
                pattern: r.pattern.clone(),
                file_filter: None,
                suppress: None,
                evidence: None,
                remediation: r.remediation.clone(),
                references: r.references.clone(),
                tags: r.tags.clone(),
                engine: None,
            });
        }
        if let Some(file) = &pack.yara {
            for r in &file.rules {
                rows.push(RuleRow {
                    id: r.id.clone(),
                    kind: if r.private { "yara-private" } else { "yara" },
                    phase: r.phase.canonical_name().to_string(),
                    severity: r.severity.to_string(),
                    weight: Some(r.phase.default_weight()),
                    description: if r.private {
                        format!("(private) {}", r.description)
                    } else {
                        r.description.clone()
                    },
                    pack_id: pack.meta.id.clone(),
                    pack_version: pack.meta.version.clone(),
                    origin,
                    pattern: Some(r.source.clone()),
                    file_filter: None,
                    suppress: None,
                    evidence: None,
                    remediation: Some(r.remediation_or_default(&file.path)),
                    references: r.references.clone(),
                    tags: r.tags.clone(),
                    engine: Some(file.engine.label()),
                });
            }
        }
        for r in &pack.correlation_rules {
            rows.push(RuleRow {
                id: r.id.clone(),
                kind: "correlation",
                phase: r.phase.clone(),
                severity: r.severity.to_ascii_uppercase(),
                weight: r.weight,
                description: r.description.clone(),
                pack_id: pack.meta.id.clone(),
                pack_version: pack.meta.version.clone(),
                origin,
                pattern: None,
                file_filter: None,
                suppress: None,
                evidence: None,
                remediation: r.remediation.clone(),
                references: r.references.clone(),
                tags: r.tags.clone(),
                engine: None,
            });
        }
    }
    Ok(rows)
}

/// What the effective policy does to a rule: (disabled by, effective severity).
fn policy_status(row: &RuleRow, policy: &EffectivePolicy) -> (Option<String>, String) {
    let disabled = policy
        .disable_rules
        .iter()
        .find(|d| rule_glob_matches(&d.value, &row.id))
        .map(|d| format!("{} ({})", d.value, d.source));
    let mut sev = crate::project_config::parse_severity(&row.severity);
    for o in &policy.severity_overrides {
        if rule_glob_matches(&o.pattern, &row.id) {
            sev = Some(match sev {
                Some(cur) if o.raise_only => cur.max(o.severity),
                _ => o.severity,
            });
        }
    }
    (
        disabled,
        sev.map(|s| s.to_string())
            .unwrap_or_else(|| row.severity.clone()),
    )
}

fn row_json(row: &RuleRow, policy: &EffectivePolicy) -> serde_json::Value {
    let (disabled, effective) = policy_status(row, policy);
    json!({
        "id": row.id,
        "kind": row.kind,
        "phase": row.phase,
        "severity": row.severity,
        "effective_severity": effective,
        "disabled_by": disabled,
        "weight": row.weight,
        "description": row.description,
        "pack": row.pack_id,
        "pack_version": row.pack_version,
        "origin": row.origin.to_string(),
        "pattern": row.pattern,
        "file_filter": row.file_filter,
        "suppress": row.suppress,
        "evidence": row.evidence,
        "remediation": row.remediation,
        "references": row.references,
        "tags": row.tags,
        "behavior": crate::scanner::profile::behavior_for(&row.id),
        "engine": row.engine,
    })
}

/// Entry point. `policy` is the resolved scan policy for the current
/// directory, with its rule packs already registered.
pub fn cmd_rules(action: RulesAction, format: &str, policy: &EffectivePolicy) -> i32 {
    match action {
        RulesAction::List { json, phase } => list(json || format == "json", phase, policy),
        RulesAction::Show { id } => show(&id, format == "json", policy),
        RulesAction::Validate { path } => validate(&path, format == "json"),
        RulesAction::Test { pack, target } => test(&pack, &target),
        RulesAction::Sign { path, key } => sign(&path, &key),
    }
}

fn list(as_json: bool, phase: Option<String>, policy: &EffectivePolicy) -> i32 {
    let mut rows = match all_rules() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {e}", "error:".bold().red());
            return 2;
        }
    };
    if let Some(p) = &phase {
        let Some(wanted) = Phase::from_name(p) else {
            let names: Vec<&str> = Phase::ALL.iter().map(|p| p.canonical_name()).collect();
            eprintln!(
                "{} unknown phase '{p}' (one of: {})",
                "error:".bold().red(),
                names.join(", ")
            );
            return 2;
        };
        rows.retain(|r| Phase::from_name(&r.phase) == Some(wanted));
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    if as_json {
        let doc = json!({
            "rule_count": rows.len(),
            "rules": rows.iter().map(|r| row_json(r, policy)).collect::<Vec<_>>(),
        });
        return write_out(&format!(
            "{}\n",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        ));
    }

    let custom = rows
        .iter()
        .filter(|r| r.origin == PackOrigin::Custom)
        .count();
    let disabled = rows
        .iter()
        .filter(|r| policy_status(r, policy).0.is_some())
        .count();
    let mut out = String::new();
    out.push_str(&format!(
        "\n  {} {} rule(s){}{}\n\n",
        "sigil rules".bold().cyan(),
        rows.len(),
        if custom > 0 {
            format!(", {custom} custom")
        } else {
            String::new()
        },
        if disabled > 0 {
            format!(", {disabled} disabled by policy")
        } else {
            String::new()
        }
    ));
    out.push_str(&format!(
        "  {:<22} {:<9} {:<19} {:<9} {}\n",
        "ID".bold(),
        "SEVERITY".bold(),
        "PHASE".bold(),
        "ORIGIN".bold(),
        "TITLE".bold()
    ));
    for r in &rows {
        let (disabled_by, effective) = policy_status(r, policy);
        let sev = if effective != r.severity {
            format!("{effective}*")
        } else {
            effective
        };
        let mut title: String = r.description.chars().take(64).collect();
        if r.description.chars().count() > 64 {
            title.push('…');
        }
        let status = match disabled_by {
            Some(by) => format!("  [disabled: {by}]").yellow().to_string(),
            None => String::new(),
        };
        out.push_str(&format!(
            "  {:<22} {:<9} {:<19} {:<9} {}{}\n",
            r.id,
            sev,
            r.phase,
            r.origin.to_string(),
            title,
            status
        ));
    }
    if rows
        .iter()
        .any(|r| policy_status(r, policy).1 != r.severity)
    {
        out.push_str("\n  * severity changed by severity_overrides in the scan policy\n");
    }
    out.push_str("\n  Details: sigil rules show <ID>\n\n");
    write_out(&out)
}

fn show(id: &str, as_json: bool, policy: &EffectivePolicy) -> i32 {
    let rows = match all_rules() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {e}", "error:".bold().red());
            return 2;
        }
    };
    let Some(row) = rows.iter().find(|r| r.id.eq_ignore_ascii_case(id)) else {
        let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        let hint = custom::closest(&id.to_ascii_uppercase(), &ids)
            .map(|s| format!(" (did you mean {s}?)"))
            .unwrap_or_default();
        eprintln!("{} no active rule {id}{hint}", "error:".bold().red());
        return 2;
    };
    if as_json {
        return write_out(&format!(
            "{}\n",
            serde_json::to_string_pretty(&row_json(row, policy)).unwrap_or_default()
        ));
    }
    let (disabled_by, effective) = policy_status(row, policy);
    let mut s = String::new();
    s.push_str(&format!("\n  {} — {}\n\n", row.id.bold(), row.description));
    let mut field = |k: &str, v: String| {
        if !v.is_empty() {
            s.push_str(&format!("  {:<12} {}\n", format!("{k}:").dimmed(), v));
        }
    };
    field(
        "pack",
        format!("{} {} ({})", row.pack_id, row.pack_version, row.origin),
    );
    field("kind", row.kind.to_string());
    if let Some(e) = &row.engine {
        field("engine", e.clone());
    }
    let phase_label = Phase::from_name(&row.phase)
        .map(|p| format!("{} ({})", row.phase, p.display_name()))
        .unwrap_or_else(|| row.phase.clone());
    field(
        "phase",
        match row.weight {
            Some(w) => format!("{phase_label}, weight {w}"),
            None => phase_label,
        },
    );
    field(
        "severity",
        if effective != row.severity {
            format!(
                "{} (effective {effective} under the scan policy)",
                row.severity
            )
        } else {
            row.severity.clone()
        },
    );
    if let Some(e) = &row.evidence {
        field("evidence", e.clone());
    }
    if let Some(b) = crate::scanner::profile::behavior_for(&row.id) {
        field("behaviour", b.to_string());
    }
    if let Some(p) = &row.pattern {
        if row.kind.starts_with("yara") {
            // A YARA rule is shown as written, one line per source line.
            field(
                "yara",
                p.lines()
                    .collect::<Vec<_>>()
                    .join(&format!("\n  {:<12} ", "")),
            );
        } else {
            field("pattern", p.clone());
        }
    }
    if let Some(ff) = &row.file_filter {
        let mut parts = Vec::new();
        if !ff.extensions.is_empty() {
            parts.push(format!("extensions {}", ff.extensions.join(", ")));
        }
        if !ff.filename_exact.is_empty() {
            parts.push(format!("names {}", ff.filename_exact.join(", ")));
        }
        if !ff.filename_suffix.is_empty() {
            parts.push(format!("suffixes {}", ff.filename_suffix.join(", ")));
        }
        field(
            "files",
            if parts.is_empty() {
                "all files".to_string()
            } else {
                parts.join("; ")
            },
        );
    }
    if let Some(sp) = &row.suppress {
        let mut parts = Vec::new();
        for (label, v) in [
            ("path contains", &sp.path_contains),
            ("filename suffix", &sp.filename_suffix),
            ("line contains", &sp.line_contains),
            ("nearby contains", &sp.nearby_contains),
            ("file header contains", &sp.file_header_contains),
            ("safe domains", &sp.safe_domains),
        ] {
            if !v.is_empty() {
                parts.push(format!("{label} {}", v.join(", ")));
            }
        }
        field("not when", parts.join("; "));
    }
    if let Some(r) = &row.remediation {
        field("remediation", r.clone());
    }
    field("references", row.references.join(", "));
    field("tags", row.tags.join(", "));
    if let Some(by) = disabled_by {
        field("policy", format!("disabled by disable_rules {by}"));
    }
    s.push('\n');
    write_out(&s)
}

fn validate(path: &Path, as_json: bool) -> i32 {
    if !path.exists() {
        eprintln!(
            "{} {}: no such file or directory",
            "error:".bold().red(),
            path.display()
        );
        return 2;
    }
    let loaded = custom::load_path(path);
    let (packs, mut errors) = match loaded {
        Ok(p) => (p, Vec::new()),
        Err(e) => (
            Vec::new(),
            e.lines().map(str::to_string).collect::<Vec<_>>(),
        ),
    };
    if errors.is_empty() {
        match loader::load_base_packs() {
            Ok(base) => errors.extend(custom::check_against(&base, &packs)),
            Err(e) => {
                eprintln!(
                    "{} cannot load the built-in corpus: {e}",
                    "error:".bold().red()
                );
                return 2;
            }
        }
    }
    // A YARA file no engine here can evaluate is not refused by a scan (it
    // is reported as incomplete coverage), but it cannot be called valid
    // either: nothing here has checked its strings and conditions.
    for p in &packs {
        if let Some(file) = &p.pack.yara {
            if let crate::corpus::yara::FileEngine::Unevaluated { reasons } = &file.engine {
                errors.push(format!(
                    "{}: not checked: it needs an external YARA engine and neither YARA-X \
                     (`yr`) nor YARA (`yara`) is installed ({}); a scan would not evaluate it",
                    file.path.display(),
                    reasons.first().map(String::as_str).unwrap_or("")
                ));
            }
        }
    }
    let ok = errors.is_empty();
    if as_json {
        let doc = json!({
            "valid": ok,
            "errors": errors,
            "packs": packs.iter().map(|p| json!({
                "path": p.path.display().to_string(),
                "id": p.pack.meta.id,
                "form": p.form.to_string(),
                "rules": p.pack.rule_count(),
                "signature": p.signature.to_string(),
                "engine": p.pack.yara.as_ref().map(|y| y.engine.label()),
                "warnings": p.warnings,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    } else {
        for p in &packs {
            println!(
                "  {} {}: pack '{}' — {} rule(s), {} form, signature {}",
                if ok { "✓".green() } else { "·".dimmed() },
                p.path.display(),
                p.pack.meta.id,
                p.pack.rule_count(),
                p.form,
                p.signature
            );
            if let Some(y) = &p.pack.yara {
                println!("      engine: {}", y.engine.label());
            }
            for w in &p.warnings {
                println!("      {} {w}", "warning:".yellow());
            }
        }
        for e in &errors {
            println!("  {} {e}", "✗".red());
        }
        if ok {
            println!("  {} valid", "sigil:".bold().green());
        } else {
            println!(
                "  {} {} problem(s); the pack would be refused",
                "sigil:".bold().red(),
                errors.len()
            );
        }
    }
    if ok {
        0
    } else {
        1
    }
}

fn test(pack: &Path, target: &Path) -> i32 {
    // The samples are untrusted: no YARA engine is looked for among them.
    crate::corpus::yara::external::exclude_from_search(target);
    let packs = match custom::load_path(pack) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {e}", "error:".bold().red());
            return 1;
        }
    };
    if !target.exists() {
        eprintln!(
            "{} {}: no such file or directory",
            "error:".bold().red(),
            target.display()
        );
        return 2;
    }
    let sig_packs: Vec<_> = packs.iter().map(|p| p.pack.clone()).collect();
    let compiled = crate::corpus::compiled::CompiledCorpus::from_packs(&sig_packs);
    // The same per-file budget as a scan (SIGIL_FILE_BUDGET_SECS, 0 for
    // none): a crafted sample must not hang a rule test either.
    let budget_limit = crate::scanner::budget::configured_budget();
    let base = if target.is_file() {
        target.parent().unwrap_or(Path::new("."))
    } else {
        target
    };
    let files = crate::scanner::collect_files(target);
    let mut hits = 0usize;
    let rel_of = |file: &Path| {
        file.strip_prefix(base)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string()
    };
    // Rules an external engine evaluates run once over every file.
    let external: Vec<_> = compiled
        .yara()
        .iter()
        .filter(|f| !f.is_builtin())
        .cloned()
        .collect();
    if !external.is_empty() {
        use crate::corpus::yara::external::{self, Source, Unit};
        let units: Vec<Unit<'_>> = files
            .iter()
            .map(|f| Unit {
                rel_path: rel_of(f),
                source: Source::Disk(f),
            })
            .collect();
        let mut found: Vec<crate::scanner::Finding> =
            external::unevaluated_findings(&external, &|_| true);
        let ev = external::evaluate(&external, &units, &|_| true, None);
        found.extend(ev.global);
        found.extend(ev.per_unit.into_iter().flatten());
        for f in found {
            let note = crate::scanner::coverage::is_coverage_rule(&f.rule);
            if !note {
                hits += 1;
            }
            println!(
                "  {:<8} [{}] {}{}\n           {}",
                if note {
                    "note".to_string()
                } else {
                    f.severity.to_string()
                },
                f.rule,
                f.file,
                f.line.map(|l| format!(":{l}")).unwrap_or_default(),
                f.snippet.dimmed()
            );
        }
    }
    for file in &files {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let rel = file
            .strip_prefix(base)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        let binary = bytes.contains(&0);
        if !compiled.yara().is_empty() {
            let subject = crate::corpus::yara::Subject::whole(&bytes, !binary);
            let budget = crate::scanner::budget::FileBudget::start(budget_limit);
            let found =
                crate::corpus::yara::scan(compiled.yara(), &subject, &rel, &|_| true, &budget);
            if budget.expired() {
                println!(
                    "  {:<8} [{}] {rel}\n           {}",
                    "note",
                    crate::scanner::budget::BUDGET_RULE_ID,
                    format!(
                        "YARA evaluation ran out of time; rules not finished are not shown \
                         (raise or disable with {}=<seconds>, 0 to disable)",
                        crate::scanner::budget::BUDGET_ENV
                    )
                    .dimmed()
                );
            }
            for f in found {
                hits += 1;
                println!(
                    "  {:<8} [{}] {}{}\n           {}",
                    f.severity.to_string(),
                    f.rule,
                    f.file,
                    f.line.map(|l| format!(":{l}")).unwrap_or_default(),
                    f.snippet.dimmed()
                );
            }
        }
        if binary {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        for phase in Phase::ALL {
            for f in compiled.scan_phase(phase, &rel, &name, &text) {
                hits += 1;
                println!(
                    "  {:<8} [{}] {}:{}\n           {}",
                    f.severity.to_string(),
                    f.rule,
                    f.file,
                    f.line.unwrap_or(0),
                    f.snippet.dimmed()
                );
            }
        }
    }
    println!(
        "\n  {} {hit} match(es) in {} file(s) from {} rule(s)",
        "sigil:".bold().cyan(),
        files.len(),
        sig_packs
            .iter()
            .map(|p| p.rules.len() + p.yara.as_ref().map_or(0, |y| y.public_rules().count()))
            .sum::<usize>(),
        hit = hits
    );
    0
}

fn sign(path: &Path, key: &Path) -> i32 {
    let signing_key = match custom::read_signing_key(key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} {e}", "error:".bold().red());
            return 2;
        }
    };
    if crate::corpus::yara::is_yara_path(path) {
        // A YARA file cannot hold its own signature: the signature is a
        // separate file that travels beside it.
        let signature = match crate::corpus::yara::sign_detached(path, &signing_key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{} {e}", "error:".bold().red());
                return 1;
            }
        };
        let code = write_out(&signature);
        eprintln!(
            "{} signed. Keep the signature beside the rule file as {}, and verify on every \
             machine with:\n  export SIGIL_PACK_PUBLIC_KEY={}",
            "sigil:".bold().green(),
            crate::corpus::yara::signature_path(path).display(),
            hex::encode(signing_key.verifying_key().to_bytes())
        );
        return code;
    }
    let signed = match custom::sign_file(path, &signing_key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {e}", "error:".bold().red());
            return 1;
        }
    };
    let code = write_out(&format!("{signed}\n"));
    eprintln!(
        "{} signed. Verify on every machine with:\n  export SIGIL_PACK_PUBLIC_KEY={}",
        "sigil:".bold().green(),
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    code
}

/// Write to `--output` or stdout.
fn write_out(text: &str) -> i32 {
    match crate::report::output_path() {
        Some(p) => match std::fs::write(p, text) {
            Ok(()) => {
                eprintln!("{} written to {}", "sigil:".bold().green(), p.display());
                0
            }
            Err(e) => {
                eprintln!(
                    "{} cannot write {}: {e}",
                    "error:".bold().red(),
                    p.display()
                );
                2
            }
        },
        None => {
            print!("{text}");
            0
        }
    }
}
