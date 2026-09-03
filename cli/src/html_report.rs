//! Self-contained HTML report for a scan result (`--format html`).
//!
//! One file, no external assets, no script: the report must open from a
//! ticket attachment or an artifact store years later and still render, and
//! it must not be able to phone home. Everything user-controlled — file
//! paths, matched lines, suppression reasons — is HTML-escaped; the snippet
//! is exactly what the scanner matched, so it is attacker-controlled text.

use crate::corpus::compiled::corpus;
use crate::scanner::profile::{self, ScanProfile};
use crate::scanner::{Finding, Phase, ScanResult, Severity};

/// Render the report.
pub fn render(result: &ScanResult, target: &str) -> String {
    let p = profile::build(result);
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!(
        "<title>Sigil scan — {} — grade {}</title>\n",
        esc(target),
        p.grade
    ));
    out.push_str("<style>\n");
    out.push_str(CSS);
    out.push_str("</style>\n</head>\n<body>\n<main>\n");

    header(&mut out, result, target, &p);
    profile_section(&mut out, &p);
    findings_section(&mut out, &result.findings);
    suppressed_sections(&mut out, result);
    footer(&mut out, result);

    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn header(out: &mut String, result: &ScanResult, target: &str, p: &ScanProfile) {
    let grade_class = match p.grade {
        "A" => "a",
        "B" => "b",
        "C" => "c",
        "D" => "d",
        _ => "f",
    };
    out.push_str("<header class=\"hero\">\n");
    out.push_str(&format!(
        "<div class=\"grade {}\" aria-label=\"Grade {}\">{}</div>\n",
        grade_class, p.grade, p.grade
    ));
    out.push_str("<div class=\"hero-text\">\n");
    out.push_str("<p class=\"eyebrow\">Sigil security scan</p>\n");
    out.push_str(&format!("<h1>{}</h1>\n", esc(target)));
    out.push_str(&format!(
        "<p class=\"verdict {}\">{}</p>\n",
        grade_class,
        esc(&result.verdict.to_string())
    ));
    out.push_str(&format!(
        "<p class=\"recommendation\">{}</p>\n",
        esc(p.recommendation)
    ));
    out.push_str("</div>\n</header>\n");

    let (critical, high, medium, low) = severity_counts(&result.findings);
    out.push_str("<section class=\"stats\">\n");
    stat(out, "Risk score", &result.score.to_string());
    stat(out, "Findings", &result.findings.len().to_string());
    stat(out, "Critical", &critical.to_string());
    stat(out, "High", &high.to_string());
    stat(out, "Medium", &medium.to_string());
    stat(out, "Low", &low.to_string());
    stat(out, "Files scanned", &result.files_scanned.to_string());
    stat(out, "Duration", &format!("{} ms", result.duration_ms));
    out.push_str("</section>\n");
}

fn stat(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!(
        "<div class=\"stat\"><span class=\"stat-value\">{}</span><span class=\"stat-label\">{}</span></div>\n",
        esc(value),
        esc(label)
    ));
}

fn profile_section(out: &mut String, p: &ScanProfile) {
    if p.behaviors.is_empty() && p.key_risks.is_empty() {
        return;
    }
    out.push_str("<section>\n<h2>What this code does</h2>\n");
    if !p.behaviors.is_empty() {
        out.push_str("<p class=\"chips\">");
        for b in &p.behaviors {
            out.push_str(&format!("<span class=\"chip\">{}</span>", esc(b)));
        }
        out.push_str("</p>\n");
    }
    if !p.key_risks.is_empty() {
        out.push_str("<h3>Key risks</h3>\n<ol class=\"risks\">\n");
        for r in &p.key_risks {
            out.push_str(&format!("<li>{}</li>\n", esc(r)));
        }
        out.push_str("</ol>\n");
    }
    out.push_str("</section>\n");
}

fn findings_section(out: &mut String, findings: &[Finding]) {
    out.push_str("<section>\n<h2>Findings</h2>\n");
    if findings.is_empty() {
        out.push_str("<p class=\"empty\">No findings.</p>\n</section>\n");
        return;
    }
    for phase in Phase::ALL {
        let in_phase: Vec<&Finding> = findings.iter().filter(|f| f.phase == phase).collect();
        if in_phase.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "<details open class=\"phase\">\n<summary><span class=\"phase-name\">{}</span> <span class=\"count\">{} finding{}</span></summary>\n",
            esc(phase.display_name()),
            in_phase.len(),
            if in_phase.len() == 1 { "" } else { "s" }
        ));
        for f in in_phase {
            finding_row(out, f, None);
        }
        out.push_str("</details>\n");
    }
    out.push_str("</section>\n");
}

fn finding_row(out: &mut String, f: &Finding, suppressed_note: Option<&str>) {
    let sev_class = match f.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    };
    let location = match f.line {
        Some(line) => format!("{}:{}", f.file, line),
        None => f.file.clone(),
    };
    out.push_str("<details class=\"finding\">\n<summary>");
    out.push_str(&format!(
        "<span class=\"sev {}\">{}</span> <code class=\"rule\">{}</code> <span class=\"title\">{}</span> <span class=\"loc\">{}</span>",
        sev_class,
        esc(&f.severity.to_string()),
        esc(&f.rule),
        esc(&profile::title_of(f)),
        esc(&location)
    ));
    out.push_str("</summary>\n<div class=\"body\">\n");
    out.push_str(&format!("<pre><code>{}</code></pre>\n", esc(&f.snippet)));
    if let Some(locator) = &f.locator {
        out.push_str(&format!(
            "<p class=\"meta\"><strong>Locator</strong> <code>{}</code></p>\n",
            esc(locator)
        ));
    }
    if let Some(meta) = corpus().rule_meta(&f.rule) {
        if let Some(fix) = &meta.remediation {
            out.push_str(&format!(
                "<p class=\"fix\"><strong>Fix</strong> {}</p>\n",
                esc(fix)
            ));
        }
        if !meta.references.is_empty() {
            out.push_str("<p class=\"meta\"><strong>References</strong> ");
            let refs: Vec<String> = meta.references.iter().map(|r| esc(r)).collect();
            out.push_str(&refs.join(", "));
            out.push_str("</p>\n");
        }
        if !meta.tags.is_empty() {
            out.push_str("<p class=\"chips\">");
            for t in &meta.tags {
                out.push_str(&format!("<span class=\"chip small\">{}</span>", esc(t)));
            }
            out.push_str("</p>\n");
        }
    }
    if f.kev || f.epss > 0.0 {
        out.push_str(&format!(
            "<p class=\"meta\"><strong>Exploitation</strong> {}EPSS {:.2}</p>\n",
            if f.kev { "in CISA KEV; " } else { "" },
            f.epss
        ));
    }
    if let Some(note) = suppressed_note {
        out.push_str(&format!(
            "<p class=\"meta\"><strong>Suppressed</strong> {}</p>\n",
            esc(note)
        ));
    }
    out.push_str(&format!(
        "<p class=\"meta fingerprint\">fingerprint {}</p>\n",
        esc(&f.fingerprint)
    ));
    out.push_str("</div>\n</details>\n");
}

fn suppressed_sections(out: &mut String, result: &ScanResult) {
    if !result.inline_suppressed.is_empty() {
        out.push_str(&format!(
            "<section>\n<h2>Suppressed by <code>sigil:ignore</code> markers ({})</h2>\n<p class=\"note\">Excluded from the score and verdict. Each carries the reviewer's reason.</p>\n",
            result.inline_suppressed.len()
        ));
        for (f, note) in result
            .inline_suppressed
            .iter()
            .zip(result.inline_suppressions.iter())
        {
            finding_row(out, f, Some(note));
        }
        out.push_str("</section>\n");
    }
    if let Some(by) = &result.suppressed_by {
        out.push_str(&format!(
            "<section>\n<h2>Suppressed by trust ledger / known-good corpus ({})</h2>\n<p class=\"note\">{}</p>\n",
            result.suppressed_findings.len(),
            esc(by)
        ));
        for f in &result.suppressed_findings {
            finding_row(out, f, Some(by));
        }
        out.push_str("</section>\n");
    }
}

fn footer(out: &mut String, result: &ScanResult) {
    out.push_str("<footer>\n");
    if let Some(info) = &result.scanner {
        out.push_str(&format!(
            "<p>Sigil {} · corpus {} · {} rules</p>\n",
            esc(&info.engine_version),
            esc(&info.corpus_digest),
            info.corpus_rule_count
        ));
    } else {
        out.push_str(&format!("<p>Sigil {}</p>\n", env!("CARGO_PKG_VERSION")));
    }
    out.push_str("<p>Static analysis detects known malicious patterns. A low-risk result is not a guarantee of safety; review code before use.</p>\n");
    out.push_str("</footer>\n");
}

fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
        }
    }
    c
}

/// HTML-escape a string for text and attribute contexts.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const CSS: &str = r#"
:root { color-scheme: dark; --bg:#0f1117; --panel:#171a23; --line:#262a36; --text:#e6e8ee; --muted:#9aa1b3;
  --a:#2ed573; --b:#7bed9f; --c:#ffa502; --d:#ff6b35; --f:#ff4757; --accent:#7aa2f7; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
main { max-width:1000px; margin:0 auto; padding:32px 20px 64px; }
.hero { display:flex; gap:24px; align-items:center; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:24px; }
.grade { flex:0 0 96px; height:96px; border-radius:50%; display:grid; place-items:center; font-size:48px; font-weight:800; border:4px solid; }
.grade.a { color:var(--a); border-color:var(--a); } .grade.b { color:var(--b); border-color:var(--b); }
.grade.c { color:var(--c); border-color:var(--c); } .grade.d { color:var(--d); border-color:var(--d); } .grade.f { color:var(--f); border-color:var(--f); }
.eyebrow { margin:0; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:12px; }
h1 { margin:4px 0; font-size:22px; word-break:break-all; }
.verdict { margin:4px 0; font-weight:700; } .verdict.a,.verdict.b { color:var(--a);} .verdict.c { color:var(--c);} .verdict.d { color:var(--d);} .verdict.f { color:var(--f);}
.recommendation { margin:0; color:var(--muted); }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:12px; margin:16px 0 24px; }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px; display:flex; flex-direction:column; }
.stat-value { font-size:22px; font-weight:700; } .stat-label { color:var(--muted); font-size:12px; }
section { margin:24px 0; }
h2 { font-size:18px; margin:0 0 8px; } h3 { font-size:15px; margin:12px 0 6px; }
.chips { margin:6px 0; } .chip { display:inline-block; background:#1f2433; border:1px solid var(--line); border-radius:999px; padding:2px 10px; margin:2px 4px 2px 0; font-size:13px; }
.chip.small { font-size:12px; padding:1px 8px; }
.risks li { margin:4px 0; }
.phase { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:8px 12px; margin:10px 0; }
.phase > summary { cursor:pointer; font-weight:700; } .count { color:var(--muted); font-weight:400; }
.finding { border-top:1px solid var(--line); padding:8px 0; }
.finding > summary { cursor:pointer; display:flex; flex-wrap:wrap; gap:8px; align-items:baseline; }
.sev { font-size:11px; font-weight:800; padding:2px 8px; border-radius:6px; color:#0b0d12; }
.sev.critical { background:var(--f);} .sev.high { background:var(--d);} .sev.medium { background:var(--c);} .sev.low { background:#747d8c;}
.rule { color:var(--accent); } .title { font-weight:600; } .loc { color:var(--muted); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
.body { padding:8px 0 4px; }
pre { background:#0b0d12; border:1px solid var(--line); border-radius:8px; padding:10px; overflow-x:auto; font-size:13px; }
.fix { background:#12241a; border-left:3px solid var(--a); padding:8px 10px; border-radius:6px; }
.meta { color:var(--muted); font-size:13px; margin:4px 0; } .fingerprint { font-family:ui-monospace,Menlo,monospace; font-size:11px; }
.note { color:var(--muted); } .empty { color:var(--a); font-weight:600; }
footer { margin-top:40px; color:var(--muted); font-size:13px; border-top:1px solid var(--line); padding-top:12px; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Phase, ScannerInfo, Verdict};

    fn finding(rule: &str, severity: Severity, snippet: &str) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity,
            file: "src/<x>.py".to_string(),
            line: Some(7),
            snippet: snippet.to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: "deadbeef".to_string(),
            locator: None,
            evidence: Default::default(),
        }
    }

    #[test]
    fn escapes_attacker_controlled_text() {
        let result = ScanResult {
            findings: vec![finding(
                "CODE-001",
                Severity::High,
                "eval() call: <script>alert('x')</script> & \"quotes\"", // sigil:ignore CODE-001 -- test input string, not a call
            )],
            score: 15,
            verdict: Verdict::MediumRisk,
            files_scanned: 1,
            duration_ms: 2,
            suppressed_findings: vec![],
            suppressed_by: None,
            scanner: Some(ScannerInfo {
                engine_version: "1.0.0".to_string(),
                corpus_digest: "sha256:abc".to_string(),
                corpus_rule_count: 3,
                rule_ids: vec![],
            }),
            inline_suppressed: vec![],
            inline_suppressions: vec![],
            platform: String::new(),
        };
        let html = render(&result, "evil <pkg>");
        assert!(
            !html.contains("<script>alert"),
            "script tag leaked into the page"
        );
        assert!(html
            .contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;quotes&quot;"));
        assert!(html.contains("<h1>evil &lt;pkg&gt;</h1>"));
        assert!(html.contains("src/&lt;x&gt;.py:7"));
        // Grade, verdict, and rule metadata are rendered.
        assert!(html.contains("aria-label=\"Grade C\""));
        assert!(html.contains("MEDIUM RISK"));
        assert!(html.contains("eval() call — arbitrary code execution")); // sigil:ignore CODE-001 -- rule title in a test expectation
        assert!(html.contains("sha256:abc"));
        // No external resources and no script: the report is inert.
        assert!(!html.contains("<script"));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("href=\"http"));
    }

    #[test]
    fn empty_result_renders_grade_a() {
        let result = ScanResult {
            findings: vec![],
            score: 0,
            verdict: Verdict::LowRisk,
            files_scanned: 0,
            duration_ms: 0,
            suppressed_findings: vec![],
            suppressed_by: None,
            scanner: None,
            inline_suppressed: vec![],
            inline_suppressions: vec![],
            platform: String::new(),
        };
        let html = render(&result, ".");
        assert!(html.contains("aria-label=\"Grade A\""));
        assert!(html.contains("No findings."));
    }
}
