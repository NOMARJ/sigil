//! Scan report formats and delivery.
//!
//! Every scan-report format goes through [`emit`]: `text` (the terminal
//! report), `json` (the ADR-0010 contract), `sarif` (2.1.0), `html`, and the
//! two this module adds — `markdown` (a PR comment or CI job summary) and
//! `junit` (one testcase per finding, for CI test-report tabs). With the
//! global `--output FILE` the report is written to the file instead of stdout;
//! the text report is then written without colour codes.
//!
//! Content in a report comes from the scanned tree — file paths and matched
//! lines are attacker-controlled. Markdown puts them in code spans with pipes
//! escaped, JUnit escapes XML and drops characters XML 1.0 cannot carry, and
//! neither lets a scanned file inject markup into a PR comment or break the
//! document a CI system parses.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use colored::Colorize;

use crate::project_config::{EffectivePolicy, PolicyOutcome, SuppressionKind};
use crate::scanner::{profile, Finding, ScanResult, Severity, Verdict};

/// Formats a scan report can be rendered in.
pub const REPORT_FORMATS: &[&str] = &["text", "json", "sarif", "html", "markdown", "md", "junit"];

static OUTPUT_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the global `--output` path. Called once, from `main`.
pub fn set_output_path(path: Option<PathBuf>) {
    let _ = OUTPUT_PATH.set(path);
}

/// Where the report goes: `None` is stdout.
pub fn output_path() -> Option<&'static Path> {
    OUTPUT_PATH.get().and_then(|p| p.as_deref())
}

/// Refuse an unknown report format up front instead of silently printing text.
pub fn validate_format(format: &str) -> Result<(), String> {
    if REPORT_FORMATS.contains(&format) {
        Ok(())
    } else {
        Err(format!(
            "unknown --format '{format}' (use text, json, sarif, html, markdown or junit)"
        ))
    }
}

/// The policy a report was produced under, when there is one.
#[derive(Clone, Copy)]
pub struct PolicyView<'a> {
    pub policy: &'a EffectivePolicy,
    pub outcome: &'a PolicyOutcome,
}

impl PolicyView<'_> {
    fn active(&self) -> bool {
        self.policy.is_active() || !self.outcome.suppressed.is_empty()
    }
}

/// The exit gate a report describes: `fail_on` and `fail_on_verdict`.
fn gate(view: Option<PolicyView>) -> (Severity, Option<Verdict>) {
    match view {
        Some(v) => (v.policy.fail_on, v.policy.fail_on_verdict),
        None => (Severity::High, None),
    }
}

/// Render and deliver a scan report.
pub fn emit(
    result: &ScanResult,
    target: &str,
    format: &str,
    view: Option<PolicyView>,
) -> Result<(), String> {
    match output_path() {
        None if format == "text" => {
            print_text(result, target, view);
            Ok(())
        }
        None => {
            // With no policy in play and a single skill (or none), the machine
            // formats go through exactly the printers they always did.
            let active = view.is_some_and(|v| v.active());
            let multi_skill = format == "json"
                && !crate::skillmap::breakdown(result, std::path::Path::new(target))
                    .skills
                    .is_empty();
            match format {
                "json" if !active && !multi_skill => crate::output::print_scan_result_json(result),
                "sarif" if !active => crate::output::print_scan_sarif(result, target),
                _ => print!("{}", render(result, target, format, view)),
            }
            Ok(())
        }
        Some(path) => {
            let doc = render(result, target, format, view);
            std::fs::write(path, doc)
                .map_err(|e| format!("cannot write report to {}: {e}", path.display()))?;
            eprintln!(
                "{} {} report written to {}",
                "sigil:".bold().green(),
                format,
                path.display()
            );
            Ok(())
        }
    }
}

/// Render a report to a string. `text` renders the uncoloured file form.
pub fn render(result: &ScanResult, target: &str, format: &str, view: Option<PolicyView>) -> String {
    match format {
        "json" => {
            let mut doc = json_document(result, view);
            // Per-skill breakdown when the tree holds 2+ SKILL.md skills
            // (reporting only; the verdict is already decided). Sorts after
            // `findings`, so the first-`[` contract holds.
            let skills = crate::skillmap::breakdown(result, std::path::Path::new(target));
            if !skills.skills.is_empty() {
                doc["skills"] = crate::skillmap::to_json(&skills);
            }
            format!(
                "{}\n",
                serde_json::to_string_pretty(&doc).unwrap_or_default()
            )
        }
        "sarif" => {
            let external: Vec<(&Finding, String)> = view
                .map(|v| {
                    v.outcome
                        .suppressed
                        .iter()
                        .map(|s| (&s.finding, s.reason.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let doc = crate::output::scan_sarif_document(result, target, &external);
            format!(
                "{}\n",
                serde_json::to_string_pretty(&doc).unwrap_or_default()
            )
        }
        "html" => crate::html_report::render(result, target),
        "markdown" | "md" => render_markdown(result, target, view),
        "junit" => render_junit(result, target, view),
        _ => render_plain(result, target, view),
    }
}

/// The JSON document: the ADR-0010 contract plus, when a policy is active, a
/// `policy` block and two summary scalars. `policy` sorts after `findings`,
/// so the findings array stays the first `[` in the document.
pub fn json_document(result: &ScanResult, view: Option<PolicyView>) -> serde_json::Value {
    let mut doc = crate::output::scan_result_document(result);
    if let Some(v) = view.filter(|v| v.active()) {
        doc["policy"] = v.policy.to_json(v.outcome);
        doc["summary"]["policy_suppressed_count"] = serde_json::json!(v.outcome.suppressed.len());
        doc["summary"]["baseline_suppressed_count"] =
            serde_json::json!(v.outcome.count(SuppressionKind::Baseline));
        doc["summary"]["gate"] = serde_json::json!(if v.policy.fails(result) {
            "fail"
        } else {
            "pass"
        });
    }
    doc
}

// ---------------------------------------------------------------------------
// Terminal text
// ---------------------------------------------------------------------------

/// The coloured terminal report: the existing layout, plus the policy lines
/// when a policy is active.
fn print_text(result: &ScanResult, target: &str, view: Option<PolicyView>) {
    use crate::output;
    output::print_scan_summary(result);
    output::print_findings(&result.findings);
    output::print_profile(result);
    crate::skillmap::print_text(&crate::skillmap::breakdown(
        result,
        std::path::Path::new(target),
    ));
    if !result.inline_suppressed.is_empty() {
        println!(
            "  {} {} finding{} suppressed by sigil:ignore markers:",
            "[*]".green(),
            result.inline_suppressed.len(),
            plural(result.inline_suppressed.len()),
        );
        for note in &result.inline_suppressions {
            println!("       {}", note.dimmed());
        }
    }
    if let Some(by) = &result.suppressed_by {
        println!(
            "  {} {} finding{} suppressed by ledger approval ({})",
            "[*]".green(),
            result.suppressed_findings.len(),
            plural(result.suppressed_findings.len()),
            by
        );
    }
    if let Some(v) = view.filter(|v| v.active()) {
        for line in policy_lines(v) {
            println!("  {} {}", "[*]".green(), line);
        }
        let (fail_on, verdict_gate) = gate(Some(v));
        let failing = result
            .findings
            .iter()
            .filter(|f| f.severity >= fail_on)
            .count();
        let gate_line = if v.policy.fails(result) {
            let mut why = Vec::new();
            if failing > 0 {
                why.push(format!(
                    "{failing} finding{} at or above {fail_on}",
                    plural(failing)
                ));
            }
            if v.policy.fails_on_verdict(result) {
                why.push(format!(
                    "verdict {} at or above fail_on_verdict {}",
                    result.verdict,
                    verdict_gate.map(|g| g.to_string()).unwrap_or_default()
                ));
            }
            format!("Gate: FAIL ({})", why.join("; "))
                .red()
                .bold()
                .to_string()
        } else {
            format!("Gate: PASS (no active finding at or above {fail_on})")
                .green()
                .to_string()
        };
        println!("  {gate_line}");
    }
    output::print_verdict(
        &result.verdict,
        profile::grade(result.verdict, result.score),
    );
}

/// One line per kind of policy suppression, plus stale-baseline notes.
fn policy_lines(v: PolicyView) -> Vec<String> {
    let mut lines = Vec::new();
    let out = v.outcome;
    for (kind, label) in [
        (SuppressionKind::Baseline, "matched the baseline"),
        (
            SuppressionKind::DisabledRule,
            "from rules disabled by policy",
        ),
        (SuppressionKind::IgnoredPath, "in paths ignored by policy"),
        (SuppressionKind::TrustedDomain, "to trusted domains"),
        (
            SuppressionKind::ConfigFile,
            "in Sigil's own policy or baseline files",
        ),
    ] {
        let n = out.count(kind);
        if n > 0 {
            lines.push(format!(
                "{n} finding{} {label} — kept in the report, excluded from score and verdict",
                plural(n)
            ));
        }
    }
    if out.hidden_below_min_severity > 0 {
        lines.push(format!(
            "{} finding{} below min_severity {} not shown",
            out.hidden_below_min_severity,
            plural(out.hidden_below_min_severity),
            v.policy
                .min_severity
                .map(|s| s.to_string())
                .unwrap_or_default()
        ));
    }
    if out.severity_changed > 0 {
        lines.push(format!(
            "{} finding severit{} changed by severity_overrides",
            out.severity_changed,
            if out.severity_changed == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    lines.extend(out.notes.iter().cloned());
    lines
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn severity_counts(findings: &[Finding]) -> [usize; 4] {
    let mut c = [0usize; 4];
    for f in findings {
        c[match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
        }] += 1;
    }
    c
}

/// Findings ordered most severe first, then by location.
fn ordered(findings: &[Finding]) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = findings.iter().collect();
    v.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    v
}

fn location(f: &Finding) -> String {
    match f.line {
        Some(l) => format!("{}:{l}", f.file),
        None => f.file.clone(),
    }
}

/// Drop control characters (terminal escapes included) from untrusted text.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Plain text (the `--output` form of `text`)
// ---------------------------------------------------------------------------

fn render_plain(result: &ScanResult, target: &str, view: Option<PolicyView>) -> String {
    let mut s = String::new();
    let grade = profile::grade(result.verdict, result.score);
    let _ = writeln!(s, "Sigil scan report: {}", clean(target));
    let _ = writeln!(
        s,
        "Verdict: {}   Grade: {grade}   Score: {}   Files: {}   Findings: {}",
        result.verdict,
        result.score,
        result.files_scanned,
        result.findings.len()
    );
    let [c, h, m, l] = severity_counts(&result.findings);
    let _ = writeln!(s, "Breakdown: {c} critical, {h} high, {m} medium, {l} low");
    let _ = writeln!(s);
    for f in ordered(&result.findings) {
        let _ = writeln!(
            s,
            "{:<8} [{}] {}",
            f.severity.to_string(),
            f.rule,
            clean(&location(f))
        );
        let _ = writeln!(s, "         {}", clean(&f.snippet));
        if f.severity >= Severity::High {
            if let Some(fix) = rule_remediation(&f.rule) {
                let _ = writeln!(s, "         fix: {fix}");
            }
        }
    }
    if !result.inline_suppressed.is_empty() {
        let _ = writeln!(
            s,
            "\n{} finding(s) suppressed by sigil:ignore markers",
            result.inline_suppressed.len()
        );
    }
    if let Some(by) = &result.suppressed_by {
        let _ = writeln!(
            s,
            "{} finding(s) suppressed ({by})",
            result.suppressed_findings.len()
        );
    }
    if let Some(v) = view.filter(|v| v.active()) {
        let _ = writeln!(s);
        for line in policy_lines(v) {
            let _ = writeln!(s, "{line}");
        }
        let _ = writeln!(
            s,
            "Gate: {}",
            if v.policy.fails(result) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    s
}

fn rule_remediation(rule: &str) -> Option<String> {
    crate::corpus::compiled::corpus()
        .rule_meta(rule)
        .and_then(|m| m.remediation.clone())
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

/// Escape text for a Markdown table cell outside a code span.
fn md_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in clean(s).chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '!' | '~' | '&'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A code span that cannot be broken out of: the fence is one backtick longer
/// than the longest run inside, and table pipes are escaped (GFM honours `\|`
/// inside code spans in tables).
fn md_code(s: &str) -> String {
    let body = clean(s).replace('|', "\\|");
    let run = body.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(run + 1);
    if body.starts_with('`') || body.ends_with('`') {
        format!("{fence} {body} {fence}")
    } else {
        format!("{fence}{body}{fence}")
    }
}

fn render_markdown(result: &ScanResult, target: &str, view: Option<PolicyView>) -> String {
    let mut s = String::new();
    let grade = profile::grade(result.verdict, result.score);
    let icon = match result.verdict {
        Verdict::LowRisk => "🟢",
        Verdict::MediumRisk => "🟡",
        Verdict::HighRisk => "🟠",
        Verdict::CriticalRisk => "🔴",
    };
    let _ = writeln!(s, "## {icon} Sigil scan: {}\n", result.verdict);
    let _ = writeln!(
        s,
        "**Target:** {} · **Grade:** {grade} · **Score:** {} · **Files scanned:** {} · **Findings:** {}\n",
        md_code(target),
        result.score,
        result.files_scanned,
        result.findings.len()
    );
    if let Some(v) = view.filter(|v| v.active()) {
        let _ = writeln!(
            s,
            "**Gate:** {} (fail_on {}{})\n",
            if v.policy.fails(result) {
                "❌ FAIL"
            } else {
                "✅ PASS"
            },
            v.policy.fail_on,
            v.policy
                .fail_on_verdict
                .map(|g| format!(", fail_on_verdict {g}"))
                .unwrap_or_default()
        );
    }
    let [c, h, m, l] = severity_counts(&result.findings);
    let _ = writeln!(s, "| Critical | High | Medium | Low |");
    let _ = writeln!(s, "|---:|---:|---:|---:|");
    let _ = writeln!(s, "| {c} | {h} | {m} | {l} |\n");

    let behaviors = profile::behaviors(&result.findings);
    if !behaviors.is_empty() {
        let _ = writeln!(
            s,
            "**Behaviour profile:** {}\n",
            md_text(&behaviors.join(", "))
        );
    }

    if result.findings.is_empty() {
        let _ = writeln!(s, "No active findings.\n");
    } else {
        let _ = writeln!(s, "### Findings\n");
        let _ = writeln!(s, "| Severity | Rule | Location | Finding |");
        let _ = writeln!(s, "|---|---|---|---|");
        const MAX_ROWS: usize = 200;
        let rows = ordered(&result.findings);
        for f in rows.iter().take(MAX_ROWS) {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {}<br>{} |",
                f.severity,
                md_code(&f.rule),
                md_code(&location(f)),
                md_text(&profile::title_of(f)),
                md_code(&truncate(&crate::baseline::matched_text(f), 160)),
            );
        }
        if rows.len() > MAX_ROWS {
            let _ = writeln!(
                s,
                "\n_{} more finding(s) not shown; see the JSON or SARIF report._",
                rows.len() - MAX_ROWS
            );
        }
        let _ = writeln!(s);

        // Remediation for the rules that gate the build.
        let mut seen = std::collections::BTreeSet::new();
        let mut fixes = Vec::new();
        for f in rows.iter().filter(|f| f.severity >= Severity::High) {
            if seen.insert(f.rule.clone()) {
                if let Some(fix) = rule_remediation(&f.rule) {
                    fixes.push(format!("- {} — {}", md_code(&f.rule), md_text(&fix)));
                }
            }
        }
        if !fixes.is_empty() {
            let _ = writeln!(s, "### What to check\n");
            for line in fixes {
                let _ = writeln!(s, "{line}");
            }
            let _ = writeln!(s);
        }
    }

    let mut suppressed = Vec::new();
    if !result.inline_suppressed.is_empty() {
        suppressed.push(format!(
            "{} by `sigil:ignore` markers",
            result.inline_suppressed.len()
        ));
    }
    if let Some(by) = &result.suppressed_by {
        suppressed.push(format!(
            "{} by {}",
            result.suppressed_findings.len(),
            md_text(by)
        ));
    }
    if let Some(v) = view.filter(|v| v.active()) {
        for line in policy_lines(v) {
            suppressed.push(md_text(&line));
        }
    }
    if !suppressed.is_empty() {
        let _ = writeln!(s, "### Suppressed and policy\n");
        for line in suppressed {
            let _ = writeln!(s, "- {line}");
        }
        if let Some(v) = view {
            for src in &v.policy.sources {
                let _ = writeln!(
                    s,
                    "- policy file {}{}",
                    md_code(&src.path),
                    if src.restricted.is_some() {
                        " (tighten-only)"
                    } else {
                        ""
                    }
                );
            }
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(
        s,
        "<sub>Sigil {}{}</sub>",
        env!("CARGO_PKG_VERSION"),
        result
            .scanner
            .as_ref()
            .map(|i| format!(
                " · corpus {} ({} rules)",
                i.corpus_digest.chars().take(19).collect::<String>(),
                i.corpus_rule_count
            ))
            .unwrap_or_default()
    );
    s
}

// ---------------------------------------------------------------------------
// JUnit XML
// ---------------------------------------------------------------------------

/// Escape for XML text and attributes, dropping characters XML 1.0 forbids.
fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

fn render_junit(result: &ScanResult, target: &str, view: Option<PolicyView>) -> String {
    let (fail_on, verdict_gate) = gate(view);
    let mut cases = String::new();
    let mut tests = 0usize;
    let mut failures = 0usize;
    let mut skipped = 0usize;

    let case_head = |f: &Finding| {
        format!(
            "    <testcase classname=\"sigil.{}\" name=\"{} {}\" file=\"{}\"{} time=\"0\">",
            xml(f.phase.canonical_name()),
            xml(&f.rule),
            xml(&location(f)),
            xml(&f.file),
            f.line.map(|l| format!(" line=\"{l}\"")).unwrap_or_default()
        )
    };

    for f in ordered(&result.findings) {
        tests += 1;
        let head = case_head(f);
        let detail = format!(
            "{}\n{}{}",
            profile::title_of(f),
            crate::baseline::matched_text(f),
            rule_remediation(&f.rule)
                .map(|r| format!("\nfix: {r}"))
                .unwrap_or_default()
        );
        if f.severity >= fail_on {
            failures += 1;
            let _ = writeln!(
                cases,
                "{head}\n      <failure type=\"{}\" message=\"{}: {}\">{}</failure>\n    </testcase>",
                xml(&f.rule),
                f.severity,
                xml(&profile::title_of(f)),
                xml(&detail)
            );
        } else {
            let _ = writeln!(
                cases,
                "{head}\n      <system-out>{}: {}</system-out>\n    </testcase>",
                f.severity,
                xml(&detail)
            );
        }
    }

    let mut skip = |f: &Finding, why: &str, cases: &mut String| {
        tests += 1;
        skipped += 1;
        let _ = writeln!(
            cases,
            "{}\n      <skipped message=\"{}\"/>\n    </testcase>",
            case_head(f),
            xml(why)
        );
    };
    for (f, note) in result
        .inline_suppressed
        .iter()
        .zip(result.inline_suppressions.iter())
    {
        skip(f, &format!("suppressed inline: {note}"), &mut cases);
    }
    if let Some(by) = &result.suppressed_by {
        for f in &result.suppressed_findings {
            skip(f, &format!("suppressed: {by}"), &mut cases);
        }
    }
    if let Some(v) = view {
        for s in &v.outcome.suppressed {
            skip(
                &s.finding,
                &format!("suppressed by policy: {}", s.reason),
                &mut cases,
            );
        }
    }

    // The verdict is its own test when a verdict gate is set, so a build that
    // fails on the verdict shows why in the test report.
    if let Some(g) = verdict_gate {
        tests += 1;
        let fails = view.is_some_and(|v| v.policy.fails_on_verdict(result));
        let _ = write!(
            cases,
            "    <testcase classname=\"sigil\" name=\"verdict below {g}\" time=\"0\">"
        );
        if fails {
            failures += 1;
            let _ = write!(
                cases,
                "\n      <failure type=\"verdict\" message=\"verdict {} (score {}) is at or above fail_on_verdict {g}\"/>\n    ",
                result.verdict, result.score
            );
        }
        let _ = writeln!(cases, "</testcase>");
    }
    if tests == 0 {
        tests = 1;
        let _ = writeln!(
            cases,
            "    <testcase classname=\"sigil\" name=\"scan: no findings\" time=\"0\"/>"
        );
    }

    let secs = result.duration_ms as f64 / 1000.0;
    let mut s = String::new();
    let _ = writeln!(s, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = writeln!(
        s,
        "<testsuites name=\"sigil\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\" skipped=\"{skipped}\" time=\"{secs:.3}\">"
    );
    let _ = writeln!(
        s,
        "  <testsuite name=\"sigil scan {}\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\" skipped=\"{skipped}\" time=\"{secs:.3}\">",
        xml(target)
    );
    let _ = writeln!(s, "    <properties>");
    for (k, v) in [
        ("verdict", result.verdict.to_string()),
        ("score", result.score.to_string()),
        (
            "grade",
            profile::grade(result.verdict, result.score).to_string(),
        ),
        ("files_scanned", result.files_scanned.to_string()),
        ("fail_on", fail_on.to_string()),
        ("sigil_version", env!("CARGO_PKG_VERSION").to_string()),
    ] {
        let _ = writeln!(s, "      <property name=\"{k}\" value=\"{}\"/>", xml(&v));
    }
    let _ = writeln!(s, "    </properties>");
    s.push_str(&cases);
    let _ = writeln!(s, "  </testsuite>");
    let _ = writeln!(s, "</testsuites>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_config::{PolicySuppressed, Sourced};
    use crate::scanner::Phase;

    fn f(rule: &str, sev: Severity, file: &str, snippet: &str) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity: sev,
            file: file.to_string(),
            line: Some(4),
            snippet: snippet.to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: "fp".to_string(),
            locator: None,
            evidence: Default::default(),
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            findings,
            score: 15,
            verdict: Verdict::MediumRisk,
            files_scanned: 2,
            duration_ms: 1500,
            suppressed_findings: Vec::new(),
            suppressed_by: None,
            scanner: None,
            inline_suppressed: Vec::new(),
            inline_suppressions: Vec::new(),
            platform: String::new(),
        }
    }

    #[test]
    fn junit_has_one_testcase_per_finding_and_fails_at_fail_on() {
        let r = result(vec![
            f("CODE-001", Severity::High, "a.py", "eval: x"),
            f("NET-001", Severity::Medium, "b.py", "requests: y"),
        ]);
        let xml_doc = render_junit(&r, "repo", None);
        assert!(xml_doc.starts_with("<?xml"));
        assert!(xml_doc.contains("tests=\"2\" failures=\"1\""), "{xml_doc}");
        assert_eq!(xml_doc.matches("<testcase ").count(), 2);
        assert!(xml_doc.contains("<failure type=\"CODE-001\""));
        assert!(xml_doc.contains("line=\"4\""));
    }

    #[test]
    fn junit_escapes_hostile_content_and_drops_invalid_xml_chars() {
        let r = result(vec![f(
            "CODE-001",
            Severity::Critical,
            "a\"<b>.py",
            "x: </failure><injected/>\u{1b}[31m\u{0}",
        )]);
        let doc = render_junit(&r, "t&t", None);
        assert!(!doc.contains("<injected/>"));
        assert!(doc.contains("&lt;/failure&gt;&lt;injected/&gt;"));
        assert!(!doc.contains('\u{1b}') && !doc.contains('\u{0}'));
        assert!(doc.contains("t&amp;t"));
        assert!(doc.contains("a&quot;&lt;b&gt;.py"));
    }

    #[test]
    fn junit_reports_policy_suppressions_as_skipped_and_the_verdict_gate() {
        let r = result(vec![f("NET-001", Severity::Medium, "b.py", "requests: y")]);
        let policy = EffectivePolicy {
            fail_on_verdict: Some(Verdict::MediumRisk),
            ..Default::default()
        };
        let outcome = PolicyOutcome {
            suppressed: vec![PolicySuppressed {
                finding: f("CODE-013", Severity::High, "t.py", "subprocess: z"),
                kind: SuppressionKind::Baseline,
                reason: "baseline b.json: adopted".into(),
            }],
            ..Default::default()
        };
        let doc = render_junit(
            &r,
            "repo",
            Some(PolicyView {
                policy: &policy,
                outcome: &outcome,
            }),
        );
        assert!(
            doc.contains("tests=\"3\" failures=\"1\" errors=\"0\" skipped=\"1\""),
            "{doc}"
        );
        assert!(
            doc.contains("<skipped message=\"suppressed by policy: baseline b.json: adopted\"/>")
        );
        assert!(doc.contains("name=\"verdict below MEDIUM RISK\""));
    }

    #[test]
    fn markdown_cannot_be_broken_out_of() {
        let r = result(vec![f(
            "CODE-001",
            Severity::High,
            "evil|`name`<img src=x>.py",
            "x: ``` | [link](http://evil) <script>",
        )]);
        let md = render_markdown(&r, "repo", None);
        // Every table row still has exactly four cells.
        for row in md.lines().filter(|l| l.starts_with("| HIGH")) {
            let unescaped_pipes = row.matches('|').count() - row.matches("\\|").count();
            assert_eq!(unescaped_pipes, 5, "row broke the table: {row}");
        }
        assert!(md.contains("### Findings"));
        assert!(!md.contains("\n<script>"));
    }

    #[test]
    fn md_code_fences_longer_than_any_backtick_run() {
        assert_eq!(md_code("a"), "`a`");
        assert_eq!(md_code("a`b"), "``a`b``");
        assert_eq!(md_code("``x"), "``` ``x ```");
    }

    #[test]
    fn json_is_unchanged_without_a_policy_and_extended_with_one() {
        let r = result(vec![f("CODE-001", Severity::High, "a.py", "eval: x")]);
        let plain = json_document(&r, None);
        assert!(plain.get("policy").is_none());
        assert!(plain["summary"].get("policy_suppressed_count").is_none());
        assert_eq!(plain, crate::output::scan_result_document(&r));

        let policy = EffectivePolicy {
            disable_rules: vec![Sourced {
                value: "NET-*".into(),
                source: ".sigil.yml".into(),
            }],
            ..Default::default()
        };
        let outcome = PolicyOutcome::default();
        let doc = json_document(
            &r,
            Some(PolicyView {
                policy: &policy,
                outcome: &outcome,
            }),
        );
        assert_eq!(doc["summary"]["policy_suppressed_count"], 0);
        assert_eq!(doc["summary"]["gate"], "fail");
        // The findings array is still the first array in the document.
        let text = serde_json::to_string(&doc).unwrap();
        assert!(text.find("\"findings\":").unwrap() < text.find('[').unwrap());
    }

    #[test]
    fn sarif_marks_policy_suppressions_external() {
        let r = result(vec![]);
        let policy = EffectivePolicy::default();
        let outcome = PolicyOutcome {
            suppressed: vec![PolicySuppressed {
                finding: f("CODE-013", Severity::High, "t.py", "subprocess: z"),
                kind: SuppressionKind::DisabledRule,
                reason: "disable_rules CODE-013 (.sigil.yml)".into(),
            }],
            ..Default::default()
        };
        let text = render(
            &r,
            "repo",
            "sarif",
            Some(PolicyView {
                policy: &policy,
                outcome: &outcome,
            }),
        );
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = &doc["runs"][0]["results"][0];
        assert_eq!(res["suppressions"][0]["kind"], "external");
        assert_eq!(
            doc["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "CODE-013"
        );
    }

    #[test]
    fn unknown_formats_are_refused() {
        assert!(validate_format("junit").is_ok());
        assert!(validate_format("md").is_ok());
        assert!(validate_format("xml")
            .unwrap_err()
            .contains("unknown --format 'xml'"));
    }
}
