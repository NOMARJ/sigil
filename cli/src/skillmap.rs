//! Per-skill breakdown for trees that hold more than one agent skill.
//!
//! A skills repository (`anthropics/skills`, a plugin marketplace, a
//! `~/.claude/skills` directory) is scanned as one tree and gets one verdict.
//! That verdict is the right answer to "is this tree safe to install" — and
//! the wrong granularity for "which skill do I need to look at". This module
//! attributes every finding to the skill directory that contains it and
//! computes each skill's verdict with the same scoring code a standalone
//! `sigil scan <skill>` would use.
//!
//! It only *reports*: the overall score, verdict and exit code are computed
//! before this runs and are not changed by it.
//!
//! A skill is a directory holding a `SKILL.md`, at any depth (SkillSpector
//! looks only at immediate children, and only when asked). A file belongs to
//! the deepest skill directory that contains it. Findings are rebased onto
//! the skill directory before scoring, so path-sensitive scoring (tests/,
//! docs/, vendor/ are secondary) judges `skills/pdf/tests/x.py` exactly as a
//! scan of `skills/pdf` would judge `tests/x.py`. Two things can differ from
//! a standalone scan: a correlation rule that joined files across two
//! skills is attributed to the skill holding the reported file, and
//! skill-local `.sigilignore` files are honoured only as the tree walk
//! honours them.

use std::path::Path;

use crate::scanner::{self, Finding, ScanResult, Severity, Verdict};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSummary {
    /// Skill directory relative to the scan root, `/`-separated; `.` for a
    /// `SKILL.md` at the root.
    pub path: String,
    /// `name:` from the SKILL.md front matter, else the directory name.
    pub name: String,
    pub verdict: Verdict,
    pub score: u32,
    pub findings: usize,
    pub files: usize,
    pub max_severity: Option<Severity>,
    /// Distinct rule ids, sorted.
    pub rules: Vec<String>,
}

/// Findings that live outside every skill directory (a repository README,
/// a shared script folder).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Breakdown {
    pub skills: Vec<SkillSummary>,
    pub unattributed_findings: usize,
}

fn rel_slash(p: &Path, root: &Path) -> Option<String> {
    let rel = p.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// The deepest skill root containing `rel` (roots are `/`-separated, `""`
/// for the scan root).
fn owner<'a>(roots: &'a [String], rel: &str) -> Option<&'a String> {
    roots
        .iter()
        .filter(|r| r.is_empty() || rel == r.as_str() || rel.starts_with(&format!("{r}/")))
        .max_by_key(|r| r.len())
}

fn front_matter_name(skill_md: &Path) -> Option<String> {
    let text = std::fs::read_to_string(skill_md).ok()?;
    let mut lines = text.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    for line in lines.take(40) {
        let t = line.trim();
        if t == "---" {
            break;
        }
        if let Some(v) = t.strip_prefix("name:") {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            if !v.is_empty() {
                return Some(v.chars().take(80).collect());
            }
        }
    }
    None
}

/// Build the breakdown. Empty unless the tree holds at least two skills.
pub fn breakdown(result: &ScanResult, root: &Path) -> Breakdown {
    if !root.is_dir() {
        return Breakdown::default();
    }
    let files = scanner::collect_files(root);
    let mut roots: Vec<String> = files
        .iter()
        .filter(|f| f.file_name().is_some_and(|n| n == "SKILL.md"))
        .filter_map(|f| rel_slash(f.parent()?, root))
        .collect();
    roots.sort();
    roots.dedup();
    if roots.len() < 2 {
        return Breakdown::default();
    }

    let mut file_counts = vec![0usize; roots.len()];
    for f in &files {
        if let Some(rel) = rel_slash(f, root) {
            if let Some(o) = owner(&roots, &rel) {
                let i = roots.iter().position(|r| r == o).unwrap_or(0);
                file_counts[i] += 1;
            }
        }
    }

    let mut per_skill: Vec<Vec<Finding>> = vec![Vec::new(); roots.len()];
    let mut unattributed = 0usize;
    for f in &result.findings {
        match owner(&roots, &f.file) {
            Some(o) => {
                let i = roots.iter().position(|r| r == o).unwrap_or(0);
                let mut rebased = f.clone();
                if !o.is_empty() {
                    rebased.file = f.file[o.len()..].trim_start_matches('/').to_string();
                }
                per_skill[i].push(rebased);
            }
            None => unattributed += 1,
        }
    }

    let skills = roots
        .iter()
        .zip(per_skill)
        .zip(file_counts)
        .map(|((r, fs), files)| {
            let score = scanner::scoring::calculate_score(&fs);
            let verdict = scanner::scoring::determine_verdict_with_size(&fs, score, files);
            let mut rules: Vec<String> = fs.iter().map(|f| f.rule.clone()).collect();
            rules.sort();
            rules.dedup();
            let dir = if r.is_empty() {
                root.to_path_buf()
            } else {
                root.join(r)
            };
            let name = front_matter_name(&dir.join("SKILL.md")).unwrap_or_else(|| {
                dir.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string())
            });
            SkillSummary {
                path: if r.is_empty() { ".".into() } else { r.clone() },
                name,
                verdict,
                score,
                findings: fs.len(),
                files,
                max_severity: fs.iter().map(|f| f.severity).max(),
                rules,
            }
        })
        .collect();

    Breakdown {
        skills,
        unattributed_findings: unattributed,
    }
}

/// The `skills` array of the JSON document. The key sorts after `findings`,
/// which keeps the "first `[` is the findings array" contract of
/// `output::print_scan_result_json`.
pub fn to_json(b: &Breakdown) -> serde_json::Value {
    serde_json::Value::Array(
        b.skills
            .iter()
            .map(|s| {
                serde_json::json!({
                    "path": s.path,
                    "name": s.name,
                    "verdict": s.verdict.to_string(),
                    "grade": scanner::profile::grade(s.verdict, s.score),
                    "score": s.score,
                    "findings_count": s.findings,
                    "files": s.files,
                    "max_severity": s.max_severity.map(|v| v.to_string()),
                    "rules": s.rules,
                })
            })
            .collect(),
    )
}

pub fn print_text(b: &Breakdown) {
    use colored::Colorize;
    if b.skills.is_empty() {
        return;
    }
    println!();
    println!("  {} ({} skills)", "Skills".bold(), b.skills.len());
    println!(
        "    {:<14} {:>6} {:>9} {:>6}  SKILL",
        "VERDICT", "SCORE", "FINDINGS", "FILES"
    );
    let mut ordered: Vec<&SkillSummary> = b.skills.iter().collect();
    // Worst first, then by path: the rows a reviewer needs are at the top.
    // A display order only — `Verdict` is deliberately not `Ord`, and
    // nothing here gates on it.
    let row_order = |v: Verdict| match v {
        Verdict::CriticalRisk => 0,
        Verdict::HighRisk => 1,
        Verdict::MediumRisk => 2,
        Verdict::LowRisk => 3,
    };
    ordered.sort_by(|a, c| {
        row_order(a.verdict)
            .cmp(&row_order(c.verdict))
            .then(a.path.cmp(&c.path))
    });
    for s in ordered {
        let v = format!("{:<14}", s.verdict.to_string());
        let v = match s.verdict {
            Verdict::LowRisk => v.green(),
            Verdict::MediumRisk => v.yellow(),
            Verdict::HighRisk => v.red(),
            Verdict::CriticalRisk => v.red().bold(),
        };
        let label = if s.name == s.path.rsplit('/').next().unwrap_or("") {
            s.path.clone()
        } else {
            format!("{} ({})", s.path, s.name)
        };
        println!(
            "    {} {:>6} {:>9} {:>6}  {}",
            v, s.score, s.findings, s.files, label
        );
    }
    if b.unattributed_findings > 0 {
        println!(
            "    {} finding{} outside any skill directory",
            b.unattributed_findings,
            if b.unattributed_findings == 1 {
                ""
            } else {
                "s"
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Phase;

    fn finding(rule: &str, file: &str, severity: Severity) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.into(),
            severity,
            file: file.into(),
            line: Some(1),
            snippet: String::new(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        let score = scanner::scoring::calculate_score(&findings);
        let verdict = scanner::scoring::determine_verdict(&findings, score);
        ScanResult {
            findings,
            score,
            verdict,
            files_scanned: 0,
            duration_ms: 0,
            suppressed_findings: vec![],
            suppressed_by: None,
            scanner: None,
            inline_suppressed: vec![],
            inline_suppressions: vec![],
            platform: String::new(),
        }
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, body) in files {
            let full = d.path().join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, body).unwrap();
        }
        d
    }

    #[test]
    fn one_skill_gets_no_breakdown() {
        let d = tree(&[("SKILL.md", "---\nname: solo\n---\n"), ("run.py", "")]);
        assert!(breakdown(&result(vec![]), d.path()).skills.is_empty());
    }

    #[test]
    fn findings_go_to_the_deepest_skill_and_are_scored_alone() {
        let d = tree(&[
            ("README.md", "# repo"),
            ("skills/pdf/SKILL.md", "---\nname: pdf-tools\n---\n"),
            ("skills/pdf/scripts/a.py", ""),
            ("skills/docx/SKILL.md", "# no front matter"),
            ("skills/docx/b.py", ""),
            ("skills/docx/nested/SKILL.md", "---\nname: 'inner'\n---\n"),
        ]);
        let r = result(vec![
            finding("CODE-001", "skills/pdf/scripts/a.py", Severity::Critical),
            finding("NET-001", "skills/docx/nested/SKILL.md", Severity::Low),
            finding("PROMPT-001", "README.md", Severity::Medium),
        ]);
        let before = (r.score, r.verdict);
        let b = breakdown(&r, d.path());
        assert_eq!((r.score, r.verdict), before, "overall result untouched");
        let paths: Vec<&str> = b.skills.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["skills/docx", "skills/docx/nested", "skills/pdf"]);

        let pdf = &b.skills[2];
        assert_eq!(pdf.name, "pdf-tools");
        assert_eq!(pdf.verdict, Verdict::CriticalRisk);
        assert_eq!(pdf.findings, 1);
        assert_eq!(pdf.files, 2);
        assert_eq!(pdf.rules, ["CODE-001"]);

        let docx = &b.skills[0];
        assert_eq!(docx.name, "docx");
        assert_eq!(docx.findings, 0);
        assert_eq!(docx.verdict, Verdict::LowRisk);
        assert_eq!(docx.files, 2, "the nested skill's files are not docx's");

        assert_eq!(b.skills[1].name, "inner");
        assert_eq!(b.skills[1].max_severity, Some(Severity::Low));
        assert_eq!(b.unattributed_findings, 1);

        let json = to_json(&b);
        assert_eq!(json[2]["verdict"], "CRITICAL RISK");
        assert_eq!(json[2]["findings_count"], 1);
    }

    #[test]
    fn findings_are_rebased_so_secondary_paths_match_a_standalone_scan() {
        // The same findings score the same, but a skill's own tests/ stay
        // secondary after the rebase, exactly as in a standalone scan.
        let d = tree(&[
            ("a/SKILL.md", "x"),
            ("a/tests/t.py", ""),
            ("b/SKILL.md", "x"),
            ("b/run.py", ""),
        ]);
        let heavy = |file: &str| {
            (0..3)
                .map(|i| finding(&format!("CODE-10{i}"), file, Severity::High))
                .collect::<Vec<_>>()
        };
        let mut fs = heavy("a/tests/t.py");
        fs.extend(heavy("b/run.py"));
        let b = breakdown(&result(fs), d.path());
        let a = b.skills.iter().find(|s| s.path == "a").unwrap();
        let bb = b.skills.iter().find(|s| s.path == "b").unwrap();
        assert_eq!(a.score, bb.score);
        assert_eq!(bb.verdict, Verdict::HighRisk);
        assert_eq!(a.verdict, Verdict::MediumRisk, "tests/ is secondary");
    }
}
