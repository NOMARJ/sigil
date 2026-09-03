//! Inline suppression markers: `sigil:ignore RULE-ID reason`.
//!
//! `.sigilignore` answers "never scan this path". The pack `suppress`
//! predicates answer "this rule is known to over-fire on this shape". Neither
//! lets a reviewer say, next to one specific line, "I looked at this, it is
//! fine, and here is why" — which is the everyday case in a repository that
//! legitimately shells out or reads an API key from the environment.
//!
//! A marker lives in a comment on the flagged line, or on the line before it
//! with `-next-line`, or anywhere in the first [`FILE_SCOPE_LINES`] lines
//! with `-file` to cover a whole file:
//!
//! ```text
//! subprocess.run(cmd)  # sigil:ignore CODE-013 -- argv list, no shell
//! // sigil:ignore-next-line NET-004 -- telemetry opt-in, documented in README
//! # sigil:ignore-file CRED-008 -- test fixtures with placeholder passwords
//! ```
//!
//! Suppression is by exact rule id only. There is deliberately no wildcard:
//! a marker that silences a family of rules is a path exclusion wearing a
//! comment, and `.sigilignore` already exists for that, with its own
//! written-rationale convention.
//!
//! Suppressed findings are never dropped. They move to
//! `ScanResult::inline_suppressed` with an attribution that records the file,
//! line, rule and reason, are excluded from score, verdict and exit code, and
//! are emitted in JSON and as SARIF `suppressions` so a reviewer can audit
//! every marker from the report alone.

use std::sync::OnceLock;

use regex::Regex;

use super::Finding;

/// How far into a file a `sigil:ignore-file` marker is honoured.
pub const FILE_SCOPE_LINES: usize = 50;

/// What a marker covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The line the marker is on.
    Line,
    /// The line after the marker.
    NextLine,
    /// The whole file.
    File,
}

/// One parsed marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// 1-based line the marker appears on.
    pub line: usize,
    pub scope: Scope,
    /// Rule ids, upper-cased.
    pub rules: Vec<String>,
    /// Free text after the ids, if any.
    pub reason: Option<String>,
}

fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"sigil:ignore(?P<scope>-next-line|-file)?[ \t]+(?P<rules>[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+(?:[ \t]*,[ \t]*[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)*)(?P<rest>.*)$",
        )
        .expect("marker regex compiles")
    })
}

/// Parse every marker in a file's contents.
pub fn parse_markers(contents: &str) -> Vec<Marker> {
    let re = marker_re();
    let mut out = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        // Cheap pre-filter: the regex is only run on lines that can match.
        if !line.contains("sigil:ignore") {
            continue;
        }
        let Some(caps) = re.captures(line) else {
            continue;
        };
        let scope = match caps.name("scope").map(|m| m.as_str()) {
            Some("-next-line") => Scope::NextLine,
            Some("-file") => Scope::File,
            _ => Scope::Line,
        };
        if scope == Scope::File && idx >= FILE_SCOPE_LINES {
            // A file-wide marker buried deep in a file is easy to miss in
            // review; it must sit near the top where a reader looks.
            continue;
        }
        let rules: Vec<String> = caps["rules"]
            .split(',')
            .map(|r| r.trim().to_ascii_uppercase())
            .filter(|r| !r.is_empty())
            .collect();
        let reason = clean_reason(&caps["rest"]);
        out.push(Marker {
            line: idx + 1,
            scope,
            rules,
            reason,
        });
    }
    out
}

/// Strip the separator and any trailing comment closer from the reason text.
fn clean_reason(rest: &str) -> Option<String> {
    let mut s = rest.trim();
    for sep in ["--", "—", ":"] {
        if let Some(stripped) = s.strip_prefix(sep) {
            s = stripped.trim();
            break;
        }
    }
    for closer in ["*/", "-->", "#}", "%>", "?>"] {
        if let Some(stripped) = s.strip_suffix(closer) {
            s = stripped.trim();
        }
    }
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// The marker that suppresses `finding`, if any.
pub fn matching_marker<'a>(markers: &'a [Marker], finding: &Finding) -> Option<&'a Marker> {
    let rule = finding.rule.to_ascii_uppercase();
    markers.iter().find(|m| {
        if !m.rules.contains(&rule) {
            return false;
        }
        match m.scope {
            Scope::File => true,
            Scope::Line => finding.line == Some(m.line),
            Scope::NextLine => finding.line == Some(m.line + 1),
        }
    })
}

/// Partition a file's findings into (kept, suppressed-with-attribution).
///
/// The attribution is what the report shows for the suppression:
/// `a.py:14 CODE-013 — argv list, no shell`.
pub fn apply(markers: &[Marker], findings: Vec<Finding>) -> (Vec<Finding>, Vec<(Finding, String)>) {
    if markers.is_empty() {
        return (findings, Vec::new());
    }
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for f in findings {
        match matching_marker(markers, &f) {
            Some(m) => {
                let location = match f.line {
                    Some(l) => format!("{}:{}", f.file, l),
                    None => f.file.clone(),
                };
                let note = match &m.reason {
                    Some(r) => format!("{location} {} — {r}", f.rule),
                    None => format!("{location} {} — (no reason given)", f.rule),
                };
                suppressed.push((f, note));
            }
            None => kept.push(f),
        }
    }
    (kept, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Phase, Severity};

    fn f(rule: &str, line: usize) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: rule.to_string(),
            severity: Severity::High,
            file: "a.py".to_string(),
            line: Some(line),
            snippet: "x".to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        }
    }

    #[test]
    fn parses_line_next_line_and_file_markers_with_reasons() {
        let src = "# sigil:ignore-file CRED-008 -- placeholder passwords\n\
                   x = 1\n\
                   subprocess.run(cmd)  # sigil:ignore CODE-013 -- argv list, no shell\n\
                   // sigil:ignore-next-line NET-004, net-005: documented telemetry\n\
                   fetch('https://x')\n\
                   /* sigil:ignore OBFUSC-001 */\n";
        let m = parse_markers(src);
        assert_eq!(m.len(), 4, "{m:#?}");
        assert_eq!(m[0].scope, Scope::File);
        assert_eq!(m[0].rules, vec!["CRED-008"]);
        assert_eq!(m[0].reason.as_deref(), Some("placeholder passwords"));
        assert_eq!(m[1].scope, Scope::Line);
        assert_eq!(m[1].line, 3);
        assert_eq!(m[1].reason.as_deref(), Some("argv list, no shell"));
        assert_eq!(m[2].scope, Scope::NextLine);
        assert_eq!(m[2].rules, vec!["NET-004", "NET-005"]);
        assert_eq!(m[2].reason.as_deref(), Some("documented telemetry"));
        assert_eq!(m[3].rules, vec!["OBFUSC-001"]);
        assert_eq!(m[3].reason, None, "comment closer is not a reason");
    }

    #[test]
    fn markers_without_a_rule_id_are_ignored() {
        assert!(parse_markers("# sigil:ignore\n# sigil:ignore everything\n").is_empty());
        // Words without a dash are not rule ids, so nothing is silenced.
        assert!(parse_markers("# sigil:ignore all -- please\n").is_empty());
    }

    #[test]
    fn file_scope_marker_must_be_near_the_top() {
        let mut src = String::new();
        for _ in 0..FILE_SCOPE_LINES {
            src.push_str("pass\n");
        }
        src.push_str("# sigil:ignore-file CODE-001\n");
        assert!(parse_markers(&src).is_empty());
    }

    #[test]
    fn apply_moves_only_matching_findings() {
        let src = "eval(a)  # sigil:ignore CODE-001 -- constant expression\n\
                   # sigil:ignore-next-line CODE-002\n\
                   exec(b)\n\
                   eval(c)\n"; // sigil:ignore CODE-001 -- test input, not a call
        let markers = parse_markers(src);
        let findings = vec![
            f("CODE-001", 1),
            f("CODE-002", 3),
            f("CODE-001", 4),
            f("NET-001", 1),
        ];
        let (kept, suppressed) = apply(&markers, findings);
        let kept_ids: Vec<(String, Option<usize>)> =
            kept.iter().map(|x| (x.rule.clone(), x.line)).collect();
        assert_eq!(
            kept_ids,
            vec![
                ("CODE-001".to_string(), Some(4)),
                ("NET-001".to_string(), Some(1))
            ]
        );
        assert_eq!(suppressed.len(), 2);
        assert_eq!(suppressed[0].1, "a.py:1 CODE-001 — constant expression");
        assert_eq!(suppressed[1].1, "a.py:3 CODE-002 — (no reason given)");
    }

    #[test]
    fn file_scope_suppresses_every_line_but_only_that_rule() {
        let markers = parse_markers("# sigil:ignore-file CRED-008 -- fixtures\n");
        let (kept, suppressed) = apply(&markers, vec![f("CRED-008", 40), f("CRED-007", 40)]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule, "CRED-007");
        assert_eq!(suppressed.len(), 1);
    }

    #[test]
    fn no_markers_is_a_no_op() {
        let (kept, suppressed) = apply(&[], vec![f("CODE-001", 1)]);
        assert_eq!(kept.len(), 1);
        assert!(suppressed.is_empty());
    }
}
