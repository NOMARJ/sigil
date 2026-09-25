//! Claude Code hook endpoints.
//!
//! `sigil hook pretooluse` reads a PreToolUse hook payload from stdin,
//! applies the quarantine-first acquisition policy, and prints a
//! `permissionDecision` JSON response.
//!
//! For a `Bash` call it judges `.tool_input.command`:
//!
//! - package installs and clones (`npm install x`, `pip install x`,
//!   `git clone`, ...) — the original policy;
//! - skill, plugin and MCP-server acquisition: `claude mcp add`,
//!   `claude plugin install` / `marketplace add`, `codex mcp add`,
//!   `gemini mcp add` / `extensions install|link`, `npx skills add`,
//!   `clawhub install`;
//! - remote execution: `npx`/`bunx`/`pnpm dlx`/`yarn dlx`/`npm exec`/
//!   `uvx`/`uv tool run`/`pipx run` of a registry package (and `pipx
//!   install`, `uv tool install`, `deno run npm:…|https://…`), a download
//!   piped or substituted into an interpreter (`curl … | sh`,
//!   `bash <(curl …)`, `iwr … | iex`), and a download saved to a file and
//!   run in the same command (`curl -o i.sh … && bash i.sh`);
//! - writes into agent tooling: downloading, unpacking or copying into
//!   `~/.claude/skills`, `.claude/plugins`, `~/.codex/skills`,
//!   `~/.gemini/extensions`, `.cursor/rules`, `.mcp.json`, ... .
//!
//! Every deny names the exact sigil command to run instead. Where that
//! command can gate the original one, the alternative is written as
//! `sigil … && <original>`, and that form is allowed: a command chained
//! with `&&` after a `sigil scan|clone|pip|npm` of the same target only runs
//! when the scan passed. "Same" includes the kind of target (see
//! [`Target`]): a scan of a directory named `evil` does not vet the npm
//! package `evil`. A download piped into an interpreter is never
//! gated this way — the server can serve the scanner and the shell
//! different bytes — so its alternative is download, scan, then run.
//!
//! A sigil invocation allows only its own segment. `sigil --version; npm
//! install evil` is judged segment by segment, so prefixing an acquisition
//! with a harmless sigil call does not launder it. Only the bare `sigil` on
//! PATH vets anything, a scan of a downloaded file counts only after the
//! last download to that path, and a command that defines its own `sigil`
//! (a function or alias) or changes PATH has no gates at all.
//!
//! Each stage is read the way the shell runs it
//! ([`cmdline::command_words`]): grouping, redirections, assignments and
//! wrapper commands (`sudo -u root`, `env -i`, `command`, `nohup`, ...) are
//! set aside first, interpreter options are read per interpreter, each
//! stage is also judged with the quoting inside its words removed, the
//! string of `bash -c '…'` is judged as a command line of its own, and a
//! backslash-newline continues the line.
//!
//! For `Write`/`Edit`/`MultiEdit` calls (when the hook is registered for
//! them) it judges edits to the agent's own tooling: content that pipes a
//! download into a shell or ships hook payloads off the machine is denied,
//! and edits to auto-running config (hooks, MCP server lists) are asked.
//!
//! This is the native implementation of the policy in
//! `plugins/claude-code/hooks/sigil-guard.sh`; the shell script delegates
//! here when the binary is available and falls back to its own patterns
//! when it is not.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::cmdline;

pub enum Decision {
    Allow(String),
    Ask(String),
    Deny(String),
}

impl Decision {
    fn rank(&self) -> u8 {
        match self {
            Decision::Allow(_) => 0,
            Decision::Ask(_) => 1,
            Decision::Deny(_) => 2,
        }
    }
}

/// The stricter of two decisions; on a tie the earlier reason stands,
/// except that a specific allow reason replaces the default one.
fn worse(a: Decision, b: Decision) -> Decision {
    let a_default = matches!(&a, Decision::Allow(r) if r == NO_MATCH);
    if b.rank() > a.rank() || (b.rank() == a.rank() && a_default) {
        b
    } else {
        a
    }
}

const NO_MATCH: &str = "No acquisition pattern matched";

// Left word boundary: start of string, a shell separator, or a quote (so
// `bash -c 'npm install evil'` is still seen).
const WB: &str = r#"(^|[\s;&|("'])"#;
// Any run of flag tokens, then at least one non-flag token (a package arg).
const FLAGS: &str = r"(\s+-\S+)*";
const PKG: &str = r"\s+[^-\s]";
// Modifier tokens between a tool name and its subcommand: runs of -flag
// tokens, each optionally followed by one non-flag argument. Covers forms
// like `git -C /tmp clone`, `npm --prefix ./x install`, `go -C x install`.
const MOD: &str = r"(\s+-\S+(\s+[^-\s]\S*)?)*";

/// `pattern`, compiled once per process. Every stage of a command is
/// checked against the same few dozen patterns; compiling them afresh for
/// each stage made a command of a few thousand stages take longer than a
/// hook's time limit (which a host may treat as an allow).
fn compiled(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }
    let re = Regex::new(pattern).ok()?;
    cache.insert(pattern.to_string(), re.clone());
    Some(re)
}

fn has(cmd: &str, pattern: &str) -> bool {
    // Patterns are static and known-valid; a compile failure is a bug, and
    // failing open here matches the shell guard's fail-open posture.
    compiled(pattern).is_some_and(|re| re.is_match(cmd))
}

/// Where a pattern first matches, for re-tokenising from the command word.
fn find_at(cmd: &str, pattern: &str) -> Option<usize> {
    let re = compiled(pattern)?;
    let m = re.captures(cmd)?;
    // Group 2 is the command word (group 1 is the left boundary).
    m.get(2).map(|g| g.start())
}

const BYPASS_HINT: &str = "Bypass: SIGIL_BYPASS=1";

/// Where the command runs, from the hook payload.
#[derive(Debug, Default, Clone)]
pub struct Context {
    pub cwd: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Segmentation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Start,
    And,
    Other,
    /// After a single `&`: the piece before it ran in the background, in a
    /// subshell of its own. Otherwise as `Other`.
    Bg,
    /// The piece after `$(` or `<(`: a subshell, which its first unmatched
    /// `)` ends. Its stdin is the stdin of the command around it.
    Subst,
    /// The piece after `>(`: as `Subst`, but its stdin is what the command
    /// around it writes there (`tee >(bash)`, `curl … > >(bash)`).
    OutSubst,
    /// The piece after an opening backtick: a subshell, like `$(`.
    Tick,
    /// The piece after a closing backtick: the subshell has ended.
    Untick,
}

/// Where each character of a command line stands: outside quotes, inside
/// single quotes (or `$'…'`), inside double quotes, in a `# comment`, or
/// in the body of a here-document (`<<EOF` … `EOF`), where quotes and `#`
/// are text. An opening quote belongs to the outside, a closing one to the
/// inside. Only what is outside can vet (see [`Walk::segment`]), open or
/// close a group, or start a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Q {
    Out,
    Single,
    Double,
    Comment,
    Heredoc,
}

/// The delimiter of a here-document whose operator (`<<` or `<<-`) starts
/// at `i`, and whether leading tabs are stripped from its lines. Not a
/// here-string (`<<<`), nor a shift in arithmetic (`$((1 << 2))`: a
/// delimiter that starts with a digit is not taken for one).
fn heredoc_at(chars: &[char], i: usize) -> Option<(String, bool)> {
    if chars.get(i..i + 2) != Some(&['<', '<'])
        || chars.get(i + 2) == Some(&'<')
        || i > 0 && chars[i - 1] == '<'
    {
        return None;
    }
    let mut j = i + 2;
    let tabs = chars.get(j) == Some(&'-');
    if tabs {
        j += 1;
    }
    while chars.get(j).is_some_and(|c| *c == ' ' || *c == '\t') {
        j += 1;
    }
    let mut delim = String::new();
    while let Some(&c) = chars.get(j) {
        if c.is_whitespace() || ";&|<>()".contains(c) {
            break;
        }
        if !matches!(c, '\'' | '"' | '\\') {
            delim.push(c);
        }
        j += 1;
    }
    let numeric = delim.starts_with(|c: char| c.is_ascii_digit());
    (!delim.is_empty() && !numeric).then_some((delim, tabs))
}

fn quote_map(chars: &[char]) -> Vec<Q> {
    let mut m = vec![Q::Out; chars.len()];
    // In $'…' a backslash escapes the next character, `\'` included.
    let mut ansi = false;
    let mut state = Q::Out;
    // Substitutions opened inside double quotes (`"$(cd "$d")"`): their
    // text is outside quotes until the `)` (or backtick) that closes them,
    // then the double quotes resume. Each entry: a backtick substitution,
    // and the `(` nesting of the one below it.
    let mut subst: Vec<(bool, u32)> = Vec::new();
    let mut parens = 0u32;
    // Here-documents opened on the current line.
    let mut pending: Vec<(String, bool)> = Vec::new();
    // Open `((` arithmetic, where `<<` is a shift.
    let mut arith = 0u32;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        m[i] = state;
        let escapes = state == Q::Double || state == Q::Single && ansi || state == Q::Out;
        if c == '\\' && escapes {
            if let Some(n) = m.get_mut(i + 1) {
                *n = state;
            }
            i += 2;
            continue;
        }
        match state {
            Q::Out => match c {
                '\'' => {
                    ansi = i > 0 && chars[i - 1] == '$';
                    state = Q::Single;
                }
                '"' => state = Q::Double,
                '#' if i == 0
                    || matches!(
                        chars[i - 1],
                        ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
                    ) =>
                {
                    state = Q::Comment;
                    m[i] = Q::Comment;
                }
                '(' if next == Some('(') => {
                    arith += 1;
                    m[i + 1] = state;
                    i += 2;
                    continue;
                }
                ')' if next == Some(')') && arith > 0 => {
                    arith -= 1;
                    m[i + 1] = state;
                    i += 2;
                    continue;
                }
                '(' if !subst.is_empty() => parens += 1,
                ')' if subst.last().is_some_and(|(tick, _)| !tick) => {
                    if parens > 0 {
                        parens -= 1;
                    } else if let Some((_, outer)) = subst.pop() {
                        parens = outer;
                        state = Q::Double;
                    }
                }
                '`' if subst.last().is_some_and(|(tick, _)| *tick) => {
                    if let Some((_, outer)) = subst.pop() {
                        parens = outer;
                        state = Q::Double;
                    }
                }
                _ => {}
            },
            Q::Single if c == '\'' => state = Q::Out,
            Q::Double => match (c, next) {
                ('"', _) => state = Q::Out,
                ('$', Some('(')) => {
                    m[i + 1] = Q::Double;
                    subst.push((false, parens));
                    parens = 0;
                    state = Q::Out;
                    i += 2;
                    continue;
                }
                ('`', _) => {
                    subst.push((true, parens));
                    parens = 0;
                    state = Q::Out;
                }
                _ => {}
            },
            Q::Comment if c == '\n' => {
                state = Q::Out;
                m[i] = Q::Out;
            }
            _ => {}
        }
        if state == Q::Out && c == '<' && arith == 0 {
            pending.extend(heredoc_at(chars, i));
        }
        // After the line that opened them, the here-document bodies, each
        // up to its delimiter line.
        if c == '\n' && state == Q::Out && !pending.is_empty() {
            let mut j = i + 1;
            for (delim, tabs) in pending.drain(..) {
                while j < chars.len() {
                    let end = chars[j..]
                        .iter()
                        .position(|c| *c == '\n')
                        .map_or(chars.len(), |p| j + p);
                    let line: String = chars[j..end].iter().collect();
                    let done = if tabs {
                        line.trim_start_matches('\t') == delim
                    } else {
                        line == delim
                    };
                    for k in m.iter_mut().take(end).skip(j) {
                        *k = Q::Heredoc;
                    }
                    if !done && end < chars.len() {
                        m[end] = Q::Heredoc;
                    }
                    j = end + 1;
                    if done {
                        break;
                    }
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    m
}

/// `text` (which starts at char index `start` of the command) without the
/// characters of a `# comment`.
fn uncommented(text: &str, start: usize, q: &[Q]) -> String {
    text.chars()
        .enumerate()
        .filter(|(i, _)| q.get(start + i) != Some(&Q::Comment))
        .map(|(_, c)| c)
        .collect()
}

/// `stage` (which starts at char index `start` of the command) split at the
/// first `)` outside quotes that closes nothing opened in it: the command of
/// the substitution the stage starts, and what follows it, with the char
/// index where that starts. `$(true) npm install evil` runs `true`, then
/// `npm install evil`; `>(bash) >/dev/null` runs `bash`.
fn split_close<'a>(stage: &'a str, start: usize, q: &[Q]) -> (&'a str, Option<(&'a str, usize)>) {
    let mut open = 0usize;
    for (n, (i, c)) in stage.char_indices().enumerate() {
        if q.get(start + n) != Some(&Q::Out) {
            continue;
        }
        match c {
            '(' => open += 1,
            ')' if open > 0 => open -= 1,
            ')' => {
                let rest = &stage[i + 1..];
                let lead = rest.chars().take_while(|c| c.is_whitespace()).count();
                let tail = rest.trim();
                let tail = (!tail.is_empty()).then_some((tail, start + n + 1 + lead));
                return (stage[..i].trim_end(), tail);
            }
            _ => {}
        }
    }
    (stage, None)
}

/// The groups and compound commands a stage (which starts at char index
/// `start` of the command) opens and closes: `{`, `if`, `while`, `until`,
/// `for`, `case`, `select` and `(` open, `}`, `fi`, `done`, `esac` and `)`
/// close. Quoted parentheses do not count.
fn compound_marks(stage: &str, start: usize, q: &[Q]) -> (i32, i32) {
    let first = cmdline::tokenize(stage)
        .into_iter()
        .next()
        .unwrap_or_default();
    let mut opens = i32::from(matches!(
        first.as_str(),
        "{" | "if" | "while" | "until" | "for" | "case" | "select"
    ));
    let mut closes = i32::from(matches!(first.as_str(), "}" | "fi" | "done" | "esac"));
    for (n, c) in stage.chars().enumerate() {
        if q.get(start + n) != Some(&Q::Out) {
            continue;
        }
        match c {
            '(' => opens += 1,
            ')' => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
}

/// A list segment of a command line: the operator in front of it, its
/// text, and the index (in chars) of the command line where the text
/// starts.
#[derive(Debug, Clone)]
struct Piece {
    op: Op,
    text: String,
    start: usize,
}

/// Split a command line into list segments on `;`, `&&`, `||`, `&`,
/// newlines and command/process substitution, recording the operator in
/// front of each. Quotes are not honoured: a separator inside quotes only
/// makes the pieces smaller, and every piece is still judged. The quote
/// map only tells an opening backtick from a closing one.
fn pieces(chars: &[char], q: &[Q]) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0;
    let mut op = Op::Start;
    let mut ticks = 0usize;
    let mut i = 0;
    let push = |out: &mut Vec<Piece>, cur: &mut String, op: Op, start: usize| {
        out.push(Piece {
            op,
            text: std::mem::take(cur),
            start,
        });
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        let (width, next_op) = match (c, next) {
            ('&', Some('&')) => (2, Op::And),
            ('|', Some('|')) => (2, Op::Other),
            // `2>&1`, `&>file`, `>&2` are redirections, not background, and
            // `|&` is a pipe.
            ('&', n) if prev != Some('>') && prev != Some('|') && n != Some('>') => (1, Op::Bg),
            (';', _) | ('\n', _) => (1, Op::Other),
            ('`', _) => {
                // A backtick in single quotes or a comment is a character;
                // otherwise they open and close substitutions in turn.
                let sub = !matches!(q.get(i), Some(Q::Single | Q::Comment));
                ticks += usize::from(sub);
                let op = match (sub, ticks % 2) {
                    (false, _) => Op::Other,
                    (true, 1) => Op::Tick,
                    _ => Op::Untick,
                };
                (1, op)
            }
            ('$', Some('(')) | ('<', Some('(')) => (2, Op::Subst),
            ('>', Some('(')) => (2, Op::OutSubst),
            _ => (0, op),
        };
        if width == 0 {
            cur.push(c);
            i += 1;
            continue;
        }
        push(&mut out, &mut cur, op, start);
        op = next_op;
        i += width;
        start = i;
    }
    push(&mut out, &mut cur, op, start);
    out
}

/// [`pieces`] as (operator, text) pairs.
#[cfg(test)]
fn segments(cmd: &str) -> Vec<(Op, String)> {
    let chars: Vec<char> = cmd.chars().collect();
    pieces(&chars, &quote_map(&chars))
        .into_iter()
        .map(|p| (p.op, p.text))
        .collect()
}

/// Pipeline stages of one segment, each with the offset (in chars) of its
/// text in the segment. `|&` pipes stderr too; `>|` is a redirection.
fn stage_spans(seg: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = seg.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i <= chars.len() {
        let split = i == chars.len() || chars[i] == '|' && (i == 0 || chars[i - 1] != '>');
        if !split {
            i += 1;
            continue;
        }
        out.push((start, chars[start..i].iter().collect()));
        i += 1;
        if chars.get(i) == Some(&'&') {
            i += 1;
        }
        start = i;
    }
    out
}

/// Stages with quotes, read whole: quotes are honoured here (outside a
/// quote, the usual separators and substitutions end a stage), so a
/// separator inside a quoted string does not cut the stage short. Keyed by
/// the index of the stage's first character, which is where [`pieces`]
/// starts the same stage.
#[derive(Default)]
struct WholeStages {
    /// The strings that `bash -c '…'`, `su -c '…'` and `eval '…'` stages
    /// hand to a shell.
    inner: HashMap<usize, String>,
    /// Stages whose inline code runs what they read on stdin
    /// ([`runs_read_code`]: `python3 -c "import sys; exec(sys.stdin.read())"`).
    reads_code: std::collections::HashSet<usize>,
}

fn inner_strings(chars: &[char], q: &[Q]) -> WholeStages {
    let mut out = WholeStages::default();
    let mut start = 0;
    let mut i = 0;
    let mut flush = |from: usize, to: usize| {
        let text: String = chars[from..to].iter().collect();
        if !text.contains(['\'', '"', '\\']) {
            return;
        }
        let lead = text.chars().take_while(|c| c.is_whitespace()).count();
        let words = cmdline::command_words(&text).words;
        if let Some(s) = inner_command(&words) {
            out.inner.insert(from + lead, s);
        }
        if runs_read_code(&words) {
            out.reads_code.insert(from + lead);
        }
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        let width = if q[i] != Q::Out {
            0
        } else {
            match (c, next) {
                ('&', Some('&')) | ('|', Some('|')) | ('|', Some('&')) => 2,
                ('$', Some('(')) | ('<', Some('(')) | ('>', Some('(')) => 2,
                ('&', n) if prev != Some('>') && prev != Some('|') && n != Some('>') => 1,
                ('|', _) if prev != Some('>') => 1,
                (';', _) | ('\n', _) | ('`', _) => 1,
                _ => 0,
            }
        };
        if width == 0 {
            i += 1;
            continue;
        }
        flush(start, i);
        i += width;
        start = i;
    }
    flush(start, chars.len());
    out
}

fn is_sigil(stage: &str) -> bool {
    has(
        stage,
        r"^\s*(\w+=\S*\s+)*(sudo(\s+-\S+)*\s+)?(\S*/)?sigil(\.exe)?(\s|$)",
    )
}

/// A sigil call that can vet what follows it: the command word is the bare
/// `sigil` found on PATH, not `./sigil` or `/tmp/x/sigil` (a file anyone can
/// write), and neither PATH, where sigil keeps its state and trust ledger
/// (`HOME`, `XDG_*`), any `SIGIL_*` setting (`SIGIL_POLICY_FILE` names an
/// organisation policy the scan trusts), nor the dynamic loader's
/// `LD_*`/`DYLD_*` (`LD_PRELOAD` loads code into sigil itself) is set for
/// it.
fn trusted_sigil(stage: &str) -> bool {
    has(
        stage,
        r"^\s*([A-Za-z0-9_]+=\S*\s+)*(sudo(\s+-\S+)*\s+)?sigil(\.exe)?(\s|$)",
    ) && !has(
        stage,
        r"^\s*([A-Za-z0-9_]+=\S*\s+)*(PATH|HOME|SIGIL_[A-Z_]*|XDG_[A-Z_]*|LD_[A-Z_]*|DYLD_[A-Z_]*)\+?=",
    )
}

/// The command can change what `sigil` runs or what its scan enforces: it
/// defines a `sigil` function or alias (`alias -- sigil=true` included),
/// loads a builtin named sigil, pins a path with `hash -p`, reassigns PATH,
/// HOME, a `SIGIL_*` setting or the loader's `LD_*`/`DYLD_*`, or names a
/// Sigil policy file (`.sigil.yml` in the working directory is trusted and
/// can raise `fail_on` past every High finding). So does one that changes
/// what a scan lets pass without a flag: `sigil approve` (an approved
/// artifact's content is allowlisted by digest), `sigil known-good` (an
/// installed index is recognised as published code), or a write into
/// sigil's state directory (`~/.sigil/`: cache, ledger, known-good
/// indexes). Then no `sigil` call in it vets anything. (A sourced file can
/// do the same; that counts from the `source` on, see [`Walk::stage`].)
fn redefines_sigil(cmd: &str) -> bool {
    has(
        cmd,
        r#"(^|[\s;&|(){}])(function\s+sigil(\s|\(|$)|sigil\s*\(\s*\)|alias(\s+[^\s;&|]+)*\s+['"]?sigil['"]?=|hash\s+-p\s|enable(\s+[^\s;&|]+)*\s+sigil(\s|$|[;&|])|((export|declare|typeset|local|readonly)\s+(-\S+\s+)*([^\s;&|]+\s+)*)?(PATH|HOME|SIGIL_[A-Z_]*|LD_[A-Z_]*|DYLD_[A-Z_]*)\+?=|(\S*/)?sigil(\.exe)?(\s+-\S+)*\s+(approve|known-good)(\s|$|[;&|)]))|(?i:sigil\.ya?ml)|\.sigil/"#,
    )
}

/// What a vetting `sigil` call checked, or what a stage acquires. A gate
/// counts only when the kind and the normalised name both agree: `sigil
/// npm evil` says nothing about the PyPI package `evil`, and a scan of a
/// local directory named `evil` says nothing about either registry package
/// (anyone can `mkdir evil` first).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// An npm package spec, as `sigil npm` takes it.
    Npm(String),
    /// A PyPI package spec, as `sigil pip` takes it.
    Pypi(String),
    /// A remote repository, canonicalised to `host/owner/repo`.
    Repo(String),
    /// A local file or directory, resolved against the working directory.
    Path(String),
    /// Something no sigil call vets by name (a crate, a gem, a Go module, a
    /// file on another host): a stage acquiring it is never gated.
    Unvettable,
}

/// Trim shell quotes from a token.
fn unquote(t: &str) -> &str {
    t.trim().trim_matches(['"', '\''])
}

/// Does this token name a remote repository rather than a local path?
fn is_remote(t: &str) -> bool {
    let t = unquote(t);
    t.contains("://") || t.starts_with("git@") || t.starts_with("github:")
}

/// `https://github.com/o/r.git`, `git@github.com:o/r`, `github:o/r` and
/// `http://www.github.com/o/r/` all become `github.com/o/r`.
fn canon_repo(t: &str) -> String {
    let mut s = unquote(t).to_string();
    if let Some(r) = s.strip_prefix("github:") {
        s = format!("github.com/{r}");
    }
    if let Some(r) = s.strip_prefix("git@") {
        s = r.replacen(':', "/", 1);
    }
    if let Some((_, r)) = s.split_once("://") {
        s = r.to_string();
    }
    // `user@host/...` credentials are not part of the identity.
    if let Some((_, r)) = s.split_once('@').filter(|(u, _)| !u.contains('/')) {
        s = r.to_string();
    }
    let s = s.trim_start_matches("www.").trim_end_matches('/');
    let s = s.strip_suffix(".git").unwrap_or(s);
    match s.split_once('/') {
        Some((host, rest)) => format!("{}/{rest}", host.to_ascii_lowercase()),
        None => s.to_ascii_lowercase(),
    }
}

/// A repository at a named branch or tag is a different artifact from its
/// default branch.
fn with_branch(repo: String, branch: &Option<String>) -> String {
    match branch {
        Some(b) => format!("{repo}#{}", unquote(b)),
        None => repo,
    }
}

/// A local path as the command would resolve it: `~`/`$HOME` expanded,
/// relative paths joined to the current directory (which follows `cd`),
/// `.` components and trailing slashes dropped, `..` applied.
fn canon_path(t: &str, ctx: &Context) -> String {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in expand(unquote(t), ctx).components() {
        match c {
            Component::CurDir => {}
            // `sub/../i.sh` is `i.sh`, read as text: symlinks are not
            // followed.
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => out.push(".."),
            },
            other => out.push(other),
        }
    }
    out.to_string_lossy().to_string()
}

/// A source argument (`npx skills add <src>`, `gemini extensions install
/// <src>`, `claude plugin marketplace add <src>`): a local path, a URL, or
/// GitHub `owner/repo` shorthand.
fn source_target(src: &str, ctx: &Context) -> Target {
    if is_local(src) {
        Target::Path(canon_path(src, ctx))
    } else {
        Target::Repo(canon_repo(&github_url(src)))
    }
}

/// Targets a `sigil scan|clone|pip|npm` invocation vets. `sigil skills`
/// inspects what is already installed and vets nothing by name.
fn vetting_targets(stage: &str, ctx: &Context) -> Option<Vec<Target>> {
    let toks = cmdline::tokenize(stage);
    let i = toks
        .iter()
        .position(|t| t.rsplit('/').next().unwrap_or(t).trim_end_matches(".exe") == "sigil")?;
    let sub = toks.get(i + 1)?.as_str();
    if !matches!(sub, "scan" | "clone" | "pip" | "npm") {
        return None;
    }
    // Options that take a value, read as clap reads them: a short one's
    // value attached (`-pnetwork`), after `=` (`-s=critical`) or the next
    // word, also at the end of a bundle (`-vp network`); a long one's
    // after `=` or the next word.
    const SHORT_VALUED: &str = "psfobV";
    const LONG_VALUED: &[&str] = &[
        "--format",
        "--phases",
        "--severity",
        "--fail-on",
        "--fail-on-verdict",
        "--branch",
        "--baseline",
        "--output",
        "--policy",
        "--rules",
        "--config",
        "--version",
    ];
    let mut names = Vec::new();
    // `sigil pip ruff -V 0.4.0` vets ruff==0.4.0, not whatever `ruff`
    // resolves to later.
    let mut version: Option<String> = None;
    // `sigil clone <url> -b dev` vets the dev branch, not the default one.
    let mut branch: Option<String> = None;
    // Options that let a scan of hostile code pass: help instead of a scan
    // (`-h`, also in a bundle: `-vh`), a threshold above the default, a
    // report threshold that hides High findings, a subset of phases, a
    // policy file or baseline of the command's choosing. Short options
    // are named by their letter here.
    let weakens = |flag: &str, value: Option<&str>| match flag {
        "h" | "--help" | "--config" | "--baseline" => true,
        "--fail-on" | "s" | "--severity" => !matches!(
            value.map(str::to_ascii_lowercase).as_deref(),
            Some("low" | "medium" | "high")
        ),
        "p" | "--phases" => value.map(str::to_ascii_lowercase).as_deref() != Some("all"),
        _ => false,
    };
    let args = &toks[i + 2..];
    let mut j = 0;
    let mut operands_only = false;
    while let Some(t) = args.get(j) {
        j += 1;
        if operands_only || t == "-" || !t.starts_with('-') {
            names.push(unquote(t).to_string());
            continue;
        }
        if t == "--" {
            operands_only = true;
            continue;
        }
        // The options this word holds, each with its value.
        let mut opts: Vec<(String, Option<String>)> = Vec::new();
        if t.starts_with("--") {
            match t.split_once('=') {
                Some((f, v)) => opts.push((f.to_string(), Some(v.to_string()))),
                None if LONG_VALUED.contains(&t.as_str()) => {
                    opts.push((t.clone(), args.get(j).cloned()));
                    j += 1;
                }
                None => opts.push((t.clone(), None)),
            }
        } else {
            let bundle: Vec<char> = t[1..].chars().collect();
            for (k, c) in bundle.iter().enumerate() {
                if !SHORT_VALUED.contains(*c) {
                    opts.push((c.to_string(), None));
                    continue;
                }
                let rest: String = bundle[k + 1..].iter().collect();
                let value = match rest.strip_prefix('=').unwrap_or(&rest) {
                    "" => {
                        j += 1;
                        args.get(j - 1).cloned()
                    }
                    v => Some(v.to_string()),
                };
                opts.push((c.to_string(), value));
                break;
            }
        }
        for (flag, value) in opts {
            if weakens(&flag, value.as_deref()) {
                return None;
            }
            match flag.as_str() {
                "V" | "--version" => version = value,
                "b" | "--branch" => branch = value,
                _ => {}
            }
        }
    }
    Some(
        names
            .into_iter()
            .map(|n| match (sub, &version) {
                ("npm", Some(v)) => Target::Npm(format!("{n}@{v}")),
                ("npm", None) => Target::Npm(n),
                ("pip", Some(v)) => Target::Pypi(format!("{n}=={v}")),
                ("pip", None) => Target::Pypi(n),
                _ if is_remote(&n) => Target::Repo(with_branch(canon_repo(&n), &branch)),
                _ => Target::Path(canon_path(&n, ctx)),
            })
            .collect(),
    )
}

/// A stage after `sigil … &&` is gated when *every* thing it acquires was
/// vetted by the chain, as the same kind of thing: `sigil npm a && npm
/// install a b` still installs an unvetted `b`, and `sigil npm a && pip
/// install a` installs a different package. A stage whose targets cannot
/// be named is never gated.
fn gated(gates: &[Vec<Target>], targets: &[Target]) -> bool {
    !targets.is_empty()
        && targets
            .iter()
            .all(|t| !matches!(t, Target::Unvettable) && gates.iter().flatten().any(|g| g == t))
}

// Command patterns shared by the classifiers and `stage_targets`. Group 2
// is the command word (see `find_at`).
fn mcp_add_pat() -> String {
    format!(r"{WB}((\S*/)?[\w.-]+\s+mcp\s+(add|add-json|add-from-claude-desktop))(\s|$)")
}
fn marketplace_pat() -> String {
    format!(r"{WB}((\S*/)?claude\s+plugins?\s+marketplace\s+add)\s")
}
fn extensions_pat() -> String {
    format!(r"{WB}((\S*/)?gemini\s+extensions?\s+(install|link))\s")
}
fn skills_cli_pat() -> String {
    format!(
        r"{WB}((npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+(-\S+\s+)*(skills|add-skill|@vercel/skills)(@\S+)?\s+(add|install))\s"
    )
}
/// Command position only: the start of the stage (after env assignments
/// and wrappers like sudo/exec/xargs), just inside a quote or paren
/// (`bash -c 'npx …'`), or after an argv separator (`some-cli add x --
/// npx -y pkg`). `echo npx is a runner` is not a run.
const RUNNER_PAT: &str = r#"(^\s*(?:\w+=\S*\s+)*(?:(?:sudo|exec|time|nohup|env|command|xargs)(?:\s+-\S+)*\s+)*|["'(]|\s--\s+)((\S*/)?(npx|bunx|uvx|pipx\s+run|pnpm\s+dlx|yarn\s+dlx|npm\s+(exec|x)|bun\s+x|uv\s+tool\s+run))(\s|$)"#;

fn first_non_flag(toks: &[String], skip: usize) -> Option<String> {
    toks.iter()
        .skip(skip)
        .find(|x| !x.starts_with('-'))
        .cloned()
}

/// The target a package runner fetches, in the registry it fetches from.
fn runner_target(r: &cmdline::Runner) -> Target {
    match r.ecosystem {
        cmdline::Ecosystem::Npm => Target::Npm(r.vet_target()),
        cmdline::Ecosystem::Pypi => Target::Pypi(r.vet_target()),
    }
}

/// Script files an MCP server command runs (`node ./server.js`), which
/// `sigil scan <file>` can vet.
fn mcp_script_args(command: &[String]) -> Vec<&String> {
    command
        .iter()
        .skip(1)
        .chain(command.first())
        .filter(|t| {
            !t.starts_with('-')
                && (t.contains('/')
                    || [".js", ".mjs", ".cjs", ".ts", ".py", ".sh"]
                        .iter()
                        .any(|e| t.ends_with(e)))
        })
        .collect()
}

/// Everything a stage would acquire, typed by what can vet it: packages,
/// repositories, archives, copied sources, the package or script an MCP
/// server runs. Empty when the stage acquires nothing the chain could have
/// vetted (a download, a bare lockfile restore, a remote MCP endpoint, a
/// container image).
fn stage_targets(stage: &str, ctx: &Context) -> Vec<Target> {
    let from = |pat: &str| find_at(stage, pat).map(|i| cmdline::tokenize(&stage[i..]));
    if let Some(t) = from(&mcp_add_pat()) {
        let m = parse_mcp_add(&t);
        if let Some(r) = cmdline::parse_runner(&m.command) {
            return vec![runner_target(&r)];
        }
        let remote = m.url.is_some()
            || m.command
                .first()
                .is_some_and(|c| c.starts_with("http://") || c.starts_with("https://"));
        if remote || cmdline::container_risk(&m.command).is_some() {
            return vec![];
        }
        let scripts = mcp_script_args(&m.command);
        return scripts
            .iter()
            .map(|s| Target::Path(canon_path(s, ctx)))
            .collect();
    }
    if let Some(t) = from(&marketplace_pat()) {
        return first_non_flag(&t, 4)
            .map(|s| source_target(&s, ctx))
            .into_iter()
            .collect();
    }
    if let Some(t) = from(&extensions_pat()) {
        return first_non_flag(&t, 3)
            .map(|s| source_target(&s, ctx))
            .into_iter()
            .collect();
    }
    if let Some(t) = from(&skills_cli_pat()) {
        let pos = t
            .iter()
            .position(|x| x == "add" || x == "install")
            .unwrap_or(t.len());
        return first_non_flag(&t, pos + 1)
            .map(|s| source_target(&s, ctx))
            .into_iter()
            .collect();
    }
    if let Some(r) = runner_at(stage) {
        return vec![runner_target(&r)];
    }
    if let Some(m) = deno_module(stage) {
        // A URL module is fetched at run time: nothing can vet it by name.
        return vec![match m.strip_prefix("npm:") {
            Some(spec) => Target::Npm(spec.to_string()),
            None => Target::Unvettable,
        }];
    }
    let toks = cmdline::command_words(stage).words;
    let Some(head) = toks
        .first()
        .map(|h| h.rsplit('/').next().unwrap_or(h).to_string())
    else {
        return vec![];
    };
    let positional = |skip_values: &[&str]| -> Vec<String> {
        let mut out = Vec::new();
        let mut skip = false;
        for t in toks.iter().skip(1) {
            if skip {
                skip = false;
            } else if skip_values.contains(&t.as_str()) {
                skip = true;
            } else if !t.starts_with('-') {
                out.push(t.clone());
            }
        }
        out
    };
    let paths = |v: Vec<String>| -> Vec<Target> {
        v.iter()
            .map(|p| {
                // `scp host:path`: a file on another machine, which no local
                // scan named `host:path` has seen.
                if head == "scp" && p.contains(':') && !p.starts_with('/') {
                    Target::Unvettable
                } else {
                    Target::Path(canon_path(p, ctx))
                }
            })
            .collect()
    };
    match head.as_str() {
        "cp" | "mv" | "rsync" | "ln" | "install" | "scp" => {
            let mut target_dir = None;
            let mut it = toks.iter();
            while let Some(t) = it.next() {
                if t == "-t" || t == "--target-directory" {
                    target_dir = it.next().cloned();
                }
            }
            let mut args = positional(&[
                "-t",
                "--target-directory",
                "-e",
                "--exclude",
                "-m",
                "-o",
                "-g",
                "-S",
            ]);
            if target_dir.is_none() {
                args.pop();
            }
            paths(args)
        }
        "unzip" => paths(positional(&["-d", "-x"]).into_iter().take(1).collect()),
        "7z" | "7za" => paths(positional(&[]).into_iter().skip(1).take(1).collect()),
        "tar" | "bsdtar" => {
            let mut it = toks.iter().skip(1);
            while let Some(t) = it.next() {
                if let Some(v) = t.strip_prefix("--file=") {
                    return paths(vec![v.to_string()]);
                }
                if t == "--file" || (t.starts_with('-') && !t.starts_with("--") && t.ends_with('f'))
                {
                    return paths(it.next().cloned().into_iter().collect());
                }
            }
            vec![]
        }
        "git" | "gh" => {
            let (branch, operands) = clone_operands(&toks);
            operands
                .into_iter()
                .next()
                .map(|u| {
                    if is_local(&u) {
                        Target::Path(canon_path(&u, ctx))
                    } else {
                        Target::Repo(with_branch(canon_repo(&github_url(&u)), &branch))
                    }
                })
                .into_iter()
                .collect()
        }
        _ => {
            // Package managers: every argument after the install verb, in
            // the registry that manager installs from. Crates, gems and Go
            // modules have no `sigil` subcommand that vets them by name.
            let npm = matches!(head.as_str(), "npm" | "yarn" | "pnpm" | "bun");
            let pypi = head.starts_with("pip")
                || head == "uv"
                || (head.starts_with("python") && toks.iter().any(|t| t == "pip"));
            match toks
                .iter()
                .position(|t| matches!(t.as_str(), "install" | "i" | "add" | "get"))
            {
                Some(i) => toks[i + 1..]
                    .iter()
                    .filter(|t| !t.starts_with('-'))
                    .map(|t| {
                        let t = unquote(t).to_string();
                        if (npm || pypi) && is_local(&t) {
                            Target::Path(canon_path(&t, ctx))
                        } else if npm {
                            Target::Npm(t)
                        } else if pypi {
                            // `uv tool install ruff@0.4.0` is ruff==0.4.0.
                            Target::Pypi(if t.contains("://") {
                                t
                            } else {
                                t.replacen('@', "==", 1)
                            })
                        } else {
                            Target::Unvettable
                        }
                    })
                    .collect(),
                None => vec![],
            }
        }
    }
}

/// A path as the shell would expand it: `~`, `$HOME` and `$PWD` (bare or
/// as a prefix) are known; a path starting with any other variable
/// (`$TMPDIR/i.sh`, `"$d"/i.sh`) is taken to be absolute under that
/// variable, since that is what such variables usually hold; the rest is
/// joined to the working directory.
fn expand(path: &str, ctx: &Context) -> PathBuf {
    let p = path.trim_matches(['"', '\'']);
    for (pre, val) in [
        ("~", &ctx.home),
        ("$HOME", &ctx.home),
        ("${HOME}", &ctx.home),
        ("$PWD", &ctx.cwd),
        ("${PWD}", &ctx.cwd),
    ] {
        let Some(v) = val else { continue };
        if p == pre {
            return v.clone();
        }
        if let Some(r) = p.strip_prefix(pre).and_then(|r| r.strip_prefix('/')) {
            return v.join(r);
        }
    }
    let pb = PathBuf::from(p);
    if pb.is_absolute() || p.starts_with('$') {
        return pb;
    }
    match &ctx.cwd {
        Some(c) => c.join(pb),
        None => pb,
    }
}

// ---------------------------------------------------------------------------
// Agent tooling paths
// ---------------------------------------------------------------------------

/// Directories and files an agent loads and runs from on its own.
fn agent_path(p: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let dirs = [
            r"\.claude/(skills|plugins|agents|commands|hooks)",
            r"\.codex/(skills|prompts)",
            r"\.agents/skills",
            r"\.gemini/(extensions|skills|commands)",
            r"\.cursor/(rules|skills)",
            r"\.windsurf/(rules|workflows)",
            r"\.codeium/windsurf",
            r"\.openclaw/(skills|workspace[^/]*)",
            r"\.(clawdbot|moltbot)/skills",
            r"\.config/opencode/(skills?|agents?|commands?|plugins?)",
            r"\.opencode/(skills?|agents?|commands?|plugins?)",
            r"\.github/(skills|prompts|instructions)",
            r"\.continue/(mcpServers|rules)",
            r"\.roo/rules",
            r"\.config/goose",
        ];
        let files = [
            r"\.claude/settings(\.local)?\.json",
            r"\.claude\.json",
            r"\.mcp\.json",
            r"\.codex/config\.toml",
            r"\.gemini/settings\.json",
            r"\.cursor/(mcp|hooks)\.json",
            r"\.vscode/mcp\.json",
            r"claude_desktop_config\.json",
            r"mcp_config\.json",
            r"\.clinerules",
        ];
        // In any case: the default macOS and Windows file systems ignore it
        // (`~/.CLAUDE/skills` is `~/.claude/skills` there).
        Regex::new(&format!(
            r"(?i)(^|/)(({})(/|$)|({})$)",
            dirs.join("|"),
            files.join("|")
        ))
        .expect("static pattern compiles")
    })
    .is_match(p)
}

fn is_agent_dest(raw: &str, ctx: &Context) -> bool {
    agent_path(raw.trim_matches(['"', '\''])) || agent_path(&expand(raw, ctx).to_string_lossy())
}

// ---------------------------------------------------------------------------
// Stage classifiers
// ---------------------------------------------------------------------------

fn github_url(src: &str) -> String {
    let s = src.trim_matches(['"', '\'']);
    if s.contains("://") || s.starts_with("git@") {
        s.to_string()
    } else {
        format!("https://github.com/{}", s.trim_start_matches("github:"))
    }
}

/// `git clone`'s branch and operands (the repository, then the directory),
/// with the values of the options that take one set aside: in
/// `git clone -b dev URL` or `git clone --depth 1 URL` the repository is
/// `URL`, not `dev` or `1`.
fn clone_operands(toks: &[String]) -> (Option<String>, Vec<String>) {
    let i = toks.iter().position(|t| t == "clone").unwrap_or(toks.len());
    let mut branch = None;
    let mut operands = Vec::new();
    let mut it = toks.iter().skip(i + 1);
    while let Some(t) = it.next() {
        if t == "-b" || t == "--branch" {
            branch = it.next().cloned();
        } else if let Some(b) = t.strip_prefix("--branch=") {
            branch = Some(b.to_string());
        } else if matches!(
            t.as_str(),
            "--depth" | "-o" | "--origin" | "-c" | "--config"
        ) {
            it.next();
        } else if !t.starts_with('-') {
            operands.push(t.clone());
        }
    }
    (branch, operands)
}

fn is_local(src: &str) -> bool {
    let s = src.trim_matches(['"', '\'']);
    s.starts_with('.') || s.starts_with('/') || s.starts_with('~') || s.starts_with("$HOME")
}

/// `sigil clone <url>` for a repository, `sigil scan <path>` for a local
/// directory.
fn vet_source(src: &str) -> String {
    if is_local(src) {
        format!("sigil scan {src}")
    } else {
        format!("sigil clone {}", github_url(src))
    }
}

/// `<tool> mcp add …` as parsed: transport, URL and the server command.
struct McpAdd {
    transport: Option<String>,
    url: Option<String>,
    command: Vec<String>,
}

fn parse_mcp_add(toks: &[String]) -> McpAdd {
    let sub = toks.get(2).map(String::as_str).unwrap_or("");
    const VALUED: &[&str] = &[
        "-s",
        "--scope",
        "-t",
        "--transport",
        "-e",
        "--env",
        "-H",
        "--header",
        "--client-id",
        "--client-secret",
        "--callback-port",
        "--bearer-token-env-var",
        "--timeout",
        "--include-tools",
        "--exclude-tools",
        "-a",
        "--description",
    ];
    let mut transport: Option<String> = None;
    let mut url: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 3;
    while i < toks.len() {
        let t = toks[i].as_str();
        if t == "--" {
            positional.extend(toks[i + 1..].iter().cloned());
            break;
        }
        if let Some((f, v)) = t.split_once('=').filter(|_| t.starts_with("--")) {
            match f {
                "--transport" => transport = Some(v.to_string()),
                "--url" => url = Some(v.to_string()),
                _ => {}
            }
            i += 1;
            continue;
        }
        if t == "--url" {
            url = toks.get(i + 1).cloned();
            i += 2;
            continue;
        }
        if VALUED.contains(&t) {
            if matches!(t, "-t" | "--transport") {
                transport = toks.get(i + 1).cloned();
            }
            i += 2;
            continue;
        }
        if t.starts_with('-') && positional.is_empty() {
            i += 1;
            continue;
        }
        positional.push(t.to_string());
        i += 1;
    }
    // add-json <name> '<json>'
    let mut command: Vec<String> = positional.iter().skip(1).cloned().collect();
    if sub == "add-json" {
        if let Some(v) = positional
            .get(1)
            .and_then(|j| serde_json::from_str::<Value>(j).ok())
        {
            command.clear();
            match v.get("command") {
                Some(Value::String(c)) => command.push(c.clone()),
                Some(Value::Array(a)) => {
                    command.extend(a.iter().filter_map(Value::as_str).map(str::to_string))
                }
                _ => {}
            }
            if let Some(Value::Array(a)) = v.get("args") {
                command.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
            }
            url = v
                .get("url")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or(url);
        }
    }
    McpAdd {
        transport,
        url,
        command,
    }
}

fn mcp_add(tool: &str, toks: &[String], original: &str) -> Decision {
    let sub = toks.get(2).map(String::as_str).unwrap_or("");
    if sub == "add-from-claude-desktop" {
        return Decision::Ask(
            "Imports every MCP server from Claude Desktop's config without review. Audit them first: sigil skills scan --tool claude-desktop".into(),
        );
    }
    let McpAdd {
        transport,
        url,
        command,
    } = parse_mcp_add(toks);
    let remote = url.clone().or_else(|| {
        let first = command.first()?;
        (first.starts_with("http://") || first.starts_with("https://")).then(|| first.clone())
    });
    let is_remote_transport = transport
        .as_deref()
        .is_some_and(|t| matches!(t, "http" | "sse" | "streamable-http"));
    if let Some(u) = remote.filter(|_| is_remote_transport || url.is_some() || !command.is_empty())
    {
        let host = reqwest::Url::parse(&u)
            .ok()
            .and_then(|p| p.host_str().map(str::to_string))
            .unwrap_or_default();
        if cmdline::capture_host(&host) {
            return Decision::Deny(format!(
                "{tool} mcp {sub} points the agent at {host}, a tunnel / request-capture host: every tool call and its arguments would go there. {BYPASS_HINT}"
            ));
        }
        let plain = if u.starts_with("http://") && host != "localhost" && host != "127.0.0.1" {
            " over plaintext http (anyone on the path can rewrite its tool descriptions)"
        } else {
            ""
        };
        return Decision::Ask(format!(
            "{tool} mcp {sub} adds a remote MCP server at {host}{plain}. Its tools run on someone else's machine and see what you pass them; sigil cannot scan remote code. Confirm you trust {host}; afterwards audit with: sigil skills scan"
        ));
    }
    if let Some(r) = cmdline::parse_runner(&command) {
        return Decision::Deny(format!(
            "{tool} mcp {sub} registers a server that runs `{} {}`: the agent will fetch {} from the registry and run it with your privileges on every start. Use: {} && {original} — and pin an exact version. {BYPASS_HINT}",
            r.tool,
            r.spec,
            if r.pinned { "that release" } else { "whatever version is current" },
            r.sigil_alternative()
        ));
    }
    if let Some(risk) = cmdline::container_risk(&command) {
        if !risk.escapes.is_empty() {
            return Decision::Deny(format!(
                "{tool} mcp {sub} registers a container server with host-level access ({}). {BYPASS_HINT}",
                risk.escapes.join(" ")
            ));
        }
        return Decision::Ask(format!(
            "{tool} mcp {sub} registers a container image as an MCP server. Scan the image's source first (sigil clone <repo>) and pin the image by digest."
        ));
    }
    let script = command
        .iter()
        .skip(1)
        .chain(command.first())
        .find(|t| t.contains('/') || t.ends_with(".js") || t.ends_with(".py"))
        .cloned();
    Decision::Ask(match script {
        Some(p) => format!(
            "{tool} mcp {sub} registers `{}` as an MCP server the agent can call. If that code has not been scanned: sigil scan {p} && {original}",
            command.join(" ")
        ),
        None => format!(
            "{tool} mcp {sub} registers `{}` as an MCP server the agent can call. Confirm the program is trusted.",
            command.join(" ")
        ),
    })
}

/// Skill, plugin, extension and MCP-server acquisition by agent CLIs.
fn agent_acquisition(stage: &str) -> Option<Decision> {
    let from = |pat: &str| -> Option<Vec<String>> {
        find_at(stage, pat).map(|i| cmdline::tokenize(&stage[i..]))
    };
    let original = stage.trim();
    if let Some(t) = from(&mcp_add_pat()) {
        let tool = t[0].rsplit('/').next().unwrap_or(&t[0]).to_string();
        return Some(mcp_add(&tool, &t, original));
    }
    if let Some(t) = from(&marketplace_pat()) {
        let src = t.iter().skip(4).find(|x| !x.starts_with('-'))?.clone();
        return Some(Decision::Deny(format!(
            "Adding a plugin marketplace trusts every plugin it lists (plugins run hooks and MCP servers with your privileges). Use: {} && {original}. {BYPASS_HINT}",
            vet_source(&src)
        )));
    }
    if from(&format!(r"{WB}((\S*/)?claude\s+plugins?\s+(install|i))\s")).is_some() {
        return Some(Decision::Deny(format!(
            "Plugins bundle hooks, MCP servers and skills that run with your privileges. Vet the plugin's marketplace repository first: sigil clone <marketplace-repo> (claude plugin marketplace list shows it), then install with SIGIL_BYPASS=1 and audit with: sigil skills scan --tool claude-code. {BYPASS_HINT}"
        )));
    }
    if let Some(t) = from(&extensions_pat()) {
        let src = t.iter().skip(3).find(|x| !x.starts_with('-'))?.clone();
        return Some(Decision::Deny(format!(
            "Gemini extensions add MCP servers and context the agent follows. Use: {} && {original}. {BYPASS_HINT}",
            vet_source(&src)
        )));
    }
    if let Some(t) = from(&skills_cli_pat()) {
        let pos = t.iter().position(|x| x == "add" || x == "install")?;
        let src = t
            .iter()
            .skip(pos + 1)
            .find(|x| !x.starts_with('-'))?
            .clone();
        return Some(Decision::Deny(format!(
            "This installs agent skills straight from {src} with no scan. Use: {} && {original}. {BYPASS_HINT}",
            vet_source(&src)
        )));
    }
    if from(&format!(r"{WB}((\S*/)?clawhub(@\S+)?\s+install)\s")).is_some() {
        return Some(Decision::Deny(format!(
            "clawhub install fetches an OpenClaw skill and installs it unscanned. Download the skill archive and run: sigil scan <archive-or-url> first. {BYPASS_HINT}"
        )));
    }
    None
}

/// A package runner in command position: the command word once grouping
/// and wrappers are removed (`sudo -u root npx …`, `(npx …)`,
/// `timeout 60 uvx …`), or where [`RUNNER_PAT`] finds one (inside a
/// quoted string, after an argv `--`).
fn runner_at(stage: &str) -> Option<cmdline::Runner> {
    cmdline::parse_runner(&cmdline::command_words(stage).words).or_else(|| {
        find_at(stage, RUNNER_PAT)
            .and_then(|i| cmdline::parse_runner(&cmdline::tokenize(&stage[i..])))
    })
}

/// Remote package runners: fetch-and-execute in one step.
fn runner(stage: &str, ctx: &Context) -> Option<Decision> {
    let r = runner_at(stage)?;
    // `npx tsc` in a project that has typescript installed runs the local
    // binary; nothing is fetched.
    if matches!(r.tool.as_str(), "npx" | "bunx" | "bun x")
        && !r.spec.contains('@')
        && !r.spec.contains('/')
    {
        if let Some(cwd) = &ctx.cwd {
            let local = cwd
                .ancestors()
                .any(|d| d.join("node_modules/.bin").join(&r.name).exists());
            if local {
                return Some(Decision::Allow(format!(
                    "{} resolves to the project's own node_modules/.bin/{}",
                    r.tool, r.name
                )));
            }
        }
    }
    let registry = match r.ecosystem {
        cmdline::Ecosystem::Npm => "npm registry",
        cmdline::Ecosystem::Pypi => "Python package index",
    };
    Some(Decision::Deny(format!(
        "`{} {}` downloads {} from the {registry} and runs it in one step, with no scan{}. Use: {} && {}. {BYPASS_HINT}",
        r.tool,
        r.spec,
        r.spec,
        if r.pinned { "" } else { " (unpinned: whatever version is current)" },
        r.sigil_alternative(),
        stage.trim()
    )))
}

/// `deno run|x|install|serve <module>`: the module argument of a deno
/// command, when it is fetched from somewhere (`https://…`, `npm:…`,
/// `jsr:…`) rather than read from disk.
fn deno_module(stage: &str) -> Option<String> {
    let at = find_at(
        stage,
        &format!(r"{WB}((\S*/)?deno\s+(run|x|install|serve))(\s|$)"),
    )?;
    let toks = cmdline::tokenize(&stage[at..]);
    let m = toks.iter().skip(2).find(|t| !t.starts_with('-'))?;
    let remote = m.starts_with("https://")
        || m.starts_with("http://")
        || m.starts_with("npm:")
        || m.starts_with("jsr:");
    remote.then(|| m.clone())
}

/// Deno fetches and runs a remote module in one step, like npx.
fn deno_remote(stage: &str) -> Option<Decision> {
    let m = deno_module(stage)?;
    if let Some(spec) = m.strip_prefix("npm:") {
        return Some(Decision::Deny(format!(
            "deno fetches {spec} from the npm registry and runs it in one step, with no scan. Use: sigil npm {spec} && {}. {BYPASS_HINT}",
            stage.trim()
        )));
    }
    Some(Decision::Deny(format!(
        "deno fetches {m} and runs it in one step, with no scan (the server decides per request what it serves). Download the module, run sigil scan on it, then deno run the local file. {BYPASS_HINT}"
    )))
}

/// Downloads, unpacks and copies into agent tooling directories.
fn tooling_write(stage: &str, ctx: &Context) -> Option<Decision> {
    let words = cmdline::command_words(stage);
    let toks = &words.words;
    let head = toks.first()?.rsplit('/').next()?.to_string();
    let cwd_dest = || ctx.cwd.as_ref().map(|c| c.to_string_lossy().to_string());
    let original = stage.trim();
    let non_flags = |skip_values: &[&str]| -> Vec<String> {
        let mut out = Vec::new();
        let mut skip = false;
        for t in toks.iter().skip(1) {
            if skip {
                skip = false;
                continue;
            }
            if skip_values.contains(&t.as_str()) {
                skip = true;
                continue;
            }
            if !t.starts_with('-') {
                out.push(t.clone());
            }
        }
        out
    };
    match head.as_str() {
        "curl" | "wget" => {
            let dl = download(&words, stage, ctx)?;
            let dest = dl.files.into_iter().find(|f| agent_path(f))?;
            Some(tooling_download_deny(&dest, stage))
        }
        "unzip" | "tar" | "bsdtar" | "7z" | "7za" | "ditto" => {
            let extracting = match head.as_str() {
                "unzip" => true,
                "7z" | "7za" => toks.get(1).is_some_and(|t| t == "x" || t == "e"),
                "ditto" => toks.iter().any(|t| t == "-x"),
                _ => {
                    toks.iter().skip(1).any(|t| {
                        t == "--extract"
                            || t == "--get"
                            || (t.starts_with('-') && !t.starts_with("--") && t.contains('x'))
                    }) || toks
                        .get(1)
                        .is_some_and(|t| !t.starts_with('-') && t.contains('x'))
                }
            };
            if !extracting {
                return None;
            }
            let mut dest: Option<String> = None;
            let mut archive: Option<String> = None;
            let mut it = toks.iter().skip(1).peekable();
            while let Some(t) = it.next() {
                let t = t.as_str();
                let dest_flag = (head == "unzip" && t == "-d")
                    || (matches!(head.as_str(), "tar" | "bsdtar")
                        && (t == "-C" || t == "--directory"));
                if dest_flag {
                    dest = it.next().cloned();
                } else if let Some(v) = t.strip_prefix("--directory=") {
                    dest = Some(v.to_string());
                } else if head.starts_with("7z") && t.starts_with("-o") && t.len() > 2 {
                    dest = Some(t[2..].to_string());
                } else if matches!(head.as_str(), "tar" | "bsdtar")
                    && t.starts_with('-')
                    && !t.starts_with("--")
                    && t.ends_with('f')
                {
                    archive = it.next().cloned();
                } else if let Some(v) = t.strip_prefix("--file=") {
                    archive = Some(v.to_string());
                } else if !t.starts_with('-') && archive.is_none() && t != "x" && t != "e" {
                    if !(matches!(head.as_str(), "tar" | "bsdtar")
                        && t.contains('x')
                        && !t.contains('.'))
                    {
                        archive = Some(t.to_string());
                    }
                } else if head == "ditto" && !t.starts_with('-') {
                    dest = Some(t.to_string());
                }
            }
            let dest = dest.or_else(cwd_dest)?;
            if !is_agent_dest(&dest, ctx) {
                return None;
            }
            let archive = archive.unwrap_or_else(|| "<archive>".into());
            Some(Decision::Deny(format!(
                "Unpacks {archive} into agent tooling ({dest}) with no scan. Use: sigil scan {archive} && {original}. {BYPASS_HINT}"
            )))
        }
        "cp" | "mv" | "rsync" | "ln" | "install" | "scp" => {
            let valued: &[&str] = match head.as_str() {
                "rsync" => &["-e", "--rsh", "--exclude", "--include", "--filter", "-f"],
                "install" => &["-m", "--mode", "-o", "--owner", "-g", "--group"],
                "scp" => &["-P", "-i", "-o", "-F", "-J"],
                _ => &["-S", "--suffix"],
            };
            let mut target: Option<String> = None;
            let mut it = toks.iter().skip(1);
            while let Some(t) = it.next() {
                if t == "-t" || t == "--target-directory" {
                    target = it.next().cloned();
                } else if let Some(v) = t.strip_prefix("--target-directory=") {
                    target = Some(v.to_string());
                }
            }
            let mut args = non_flags(valued);
            if let Some(t) = &target {
                args.retain(|a| a != t);
            }
            let dest = match target {
                Some(t) => t,
                None => args.pop()?,
            };
            if args.is_empty() || !is_agent_dest(&dest, ctx) {
                return None;
            }
            // Rearranging what is already installed is not an acquisition.
            if args.iter().all(|a| is_agent_dest(a, ctx)) {
                return None;
            }
            let src = &args[0];
            if src.contains(':') && !src.starts_with('/') && head == "scp" {
                return Some(Decision::Deny(format!(
                    "Copies {src} from another host straight into agent tooling ({dest}). Copy it to a scratch directory, run sigil scan on it, then install it. {BYPASS_HINT}"
                )));
            }
            Some(Decision::Deny(format!(
                "Installs {} into agent tooling ({dest}) with no scan: skills, plugins and hooks there run with your privileges. Use: sigil scan {src} && {original}. {BYPASS_HINT}",
                args.join(" ")
            )))
        }
        _ => None,
    }
}

/// The original acquisition rules: clones and package-manager installs.
fn package_managers(stage: &str, ctx: &Context) -> Decision {
    // Cloning repositories.
    if let Some(at) = find_at(stage, &format!(r"{WB}(git){MOD}\s+clone(\s|$)")) {
        let toks = cmdline::tokenize(&stage[at..]);
        let (branch, args) = clone_operands(&toks);
        // A line that continues (`git clone --depth 1 \`) ends in a lone
        // backslash, not the repository.
        let args: Vec<String> = args
            .into_iter()
            .filter(|a| !a.is_empty() && a != "\\")
            .collect();
        let url = args.first().cloned().unwrap_or_else(|| "<url>".into());
        // The scan the gate accepts for this clone: the same branch.
        let vet = match &branch {
            Some(b) => format!("sigil clone {url} -b {b}"),
            None => format!("sigil clone {url}"),
        };
        let into_tooling = args.get(1).is_some_and(|d| is_agent_dest(d, ctx))
            || (args.len() == 1
                && ctx
                    .cwd
                    .as_ref()
                    .is_some_and(|c| agent_path(&c.to_string_lossy())));
        return Decision::Deny(if into_tooling {
            format!(
                "git clone into agent tooling installs unscanned skills or plugins. Use: {vet} && {} (the clone only runs if the scan passes). {BYPASS_HINT}",
                stage.trim()
            )
        } else {
            format!(
                "git clone pulls unscanned code. Use: {vet} (quarantine + scan first). {BYPASS_HINT}"
            )
        });
    }
    if has(stage, &format!(r"{WB}gh{MOD}\s+repo\s+clone(\s|$)")) {
        return Decision::Deny(format!(
            "gh repo clone pulls unscanned code. Use: sigil clone <url> (quarantine + scan first). {BYPASS_HINT}"
        ));
    }

    // npm: explicit package -> deny; bare lockfile restore -> ask.
    if has(stage, &format!(r"{WB}npm{MOD}\s+(install|i|add)(\s|$)")) {
        return if has(
            stage,
            &format!(r"{WB}npm{MOD}\s+(install|i|add){FLAGS}{PKG}"),
        ) {
            Decision::Deny(format!(
                "npm install with a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). {BYPASS_HINT}"
            ))
        } else {
            Decision::Ask(
                "Bare npm install restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted.".into(),
            )
        };
    }
    if has(stage, &format!(r"{WB}npm{MOD}\s+ci(\s|$)")) {
        return Decision::Ask(
            "npm ci restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted.".into(),
        );
    }

    // yarn / pnpm / bun.
    if has(
        stage,
        &format!(r"{WB}(yarn|pnpm|bun){MOD}(\s+global)?\s+add{FLAGS}{PKG}"),
    ) {
        return Decision::Deny(format!(
            "Adding a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). {BYPASS_HINT}"
        ));
    }
    if has(stage, &format!(r"{WB}(yarn|pnpm){MOD}\s+install(\s|$)")) {
        return Decision::Ask(
            "Lockfile restore can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted.".into(),
        );
    }

    // pip / uv: -r requirements -> ask, unless a package is named besides
    // it; explicit package -> deny.
    let pip_install = format!(
        r"{WB}(pip[0-9.]*{MOD}\s+install|python[0-9.]*\s+-m\s+pip\s+install|uv\s+pip\s+install)"
    );
    if has(stage, &format!(r"{pip_install}(\s|$)")) {
        return if has(stage, r"(^|\s)(-r|--requirement)(\s|$)")
            && !cmdline::pip_names_package(&cmdline::command_words(stage).words)
        {
            Decision::Ask(
                "pip install -r installs every pinned dependency, any of which can run setup.py code. Confirm the requirements file is trusted.".into(),
            )
        } else if has(stage, &format!(r"{pip_install}{FLAGS}{PKG}")) {
            Decision::Deny(format!(
                "pip install with a package installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). {BYPASS_HINT}"
            ))
        } else {
            Decision::Ask(
                "Bare pip install can execute setup.py from the current directory. Run sigil scan . first.".into(),
            )
        };
    }
    if has(stage, &format!(r"{WB}uv{MOD}\s+add{FLAGS}{PKG}")) {
        return Decision::Deny(format!(
            "uv add installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). {BYPASS_HINT}"
        ));
    }
    // Tool installers: the same registry download as `uvx` / `pipx run`,
    // kept on PATH afterwards.
    if let Some(at) = find_at(
        stage,
        &format!(r"{WB}((\S*/)?(pipx|uv{MOD}\s+tool){MOD}\s+install){FLAGS}{PKG}"),
    ) {
        let toks = cmdline::tokenize(&stage[at..]);
        let pkg = toks
            .iter()
            .skip_while(|t| *t != "install")
            .skip(1)
            .find(|t| !t.starts_with('-'))
            .map(|p| unquote(p).replace('@', "=="))
            .unwrap_or_else(|| "<pkg>".into());
        return Decision::Deny(format!(
            "This installs {pkg} from the Python package index with no scan; its build and entry points run with your privileges. Use: sigil pip {pkg} && {} — and pin an exact version. {BYPASS_HINT}",
            stage.trim()
        ));
    }

    // Other package managers with explicit packages.
    if has(
        stage,
        &format!(r"{WB}cargo{MOD}\s+(install|add){FLAGS}{PKG}"),
    ) {
        return Decision::Deny(format!(
            "cargo install/add builds and installs unscanned code. Quarantine + scan the crate source with sigil clone first. {BYPASS_HINT}"
        ));
    }
    if has(stage, &format!(r"{WB}gem{MOD}\s+install{FLAGS}{PKG}")) {
        return Decision::Deny(format!(
            "gem install runs unscanned code (gems can execute extensions at install). Quarantine + scan the source with sigil clone first. {BYPASS_HINT}"
        ));
    }
    if has(stage, &format!(r"{WB}go{MOD}\s+(install|get){FLAGS}{PKG}")) {
        return Decision::Deny(format!(
            "go install/get fetches and builds unscanned code. Quarantine + scan the module source with sigil clone first. {BYPASS_HINT}"
        ));
    }

    if has(stage, &format!(r"{WB}bundle\s+install(\s|$)")) {
        return Decision::Ask(
            "bundle install restores the Gemfile.lock, which can run native extension code from unreviewed gems. Confirm the lockfile is trusted.".into(),
        );
    }

    Decision::Allow(NO_MATCH.into())
}

/// What a `curl`/`wget` stage does with the body it downloads.
struct Download {
    /// Files it saves the body to, resolved like [`canon_path`]. When the
    /// name would come from the URL and the URL has none: the directory.
    files: Vec<String>,
    /// It writes the body to stdout, into the pipe.
    stdout: bool,
}

/// curl short options that take a value, besides `-o`.
const CURL_VALUED: &str = "dHuXAebcFTxwmrCEKYyzUQtPD";
/// wget short options that take a value, besides `-O` and `-P`.
const WGET_VALUED: &str = "oaeiBtTwQUDRAIXl";

/// The last path component of the first URL in `stage`.
fn url_name(stage: &str) -> Option<String> {
    cmdline::first_url(stage).and_then(|u| {
        let path = u.split(['?', '#']).next()?.to_string();
        let name = path
            .split("://")
            .nth(1)?
            .split_once('/')?
            .1
            .rsplit('/')
            .next()?;
        (!name.is_empty()).then(|| name.to_string())
    })
}

/// Where a `curl`/`wget` stage (as [`cmdline::command_words`] gives it)
/// puts what it downloads; `None` when it is not a download. Reads bundled
/// and attached options (`-fsSLo f`, `-oi.sh`, `-qO-`), the output
/// directory, and stdout redirections (`> f`, `1> f`, `&> f`).
fn download(w: &cmdline::Words, stage: &str, ctx: &Context) -> Option<Download> {
    let head = w.words.first()?.rsplit('/').next()?;
    let wget = head == "wget";
    if !wget && head != "curl" {
        return None;
    }
    let args = &w.words[1..];
    let mut outs: Vec<String> = Vec::new();
    let mut dir: Option<String> = None;
    let mut remote = false;
    let mut i = 0;
    while let Some(t) = args.get(i) {
        i += 1;
        if t == "--" {
            break;
        }
        if let Some(long) = t.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let valued = if wget {
                matches!(
                    name,
                    "output-document"
                        | "directory-prefix"
                        | "output-file"
                        | "append-output"
                        | "input-file"
                )
            } else {
                matches!(name, "output" | "output-dir")
            };
            if !valued {
                remote |= !wget && matches!(name, "remote-name" | "remote-name-all");
                continue;
            }
            let value = attached.or_else(|| {
                i += 1;
                args.get(i - 1).cloned()
            });
            match name {
                "output" | "output-document" => outs.extend(value),
                "output-dir" | "directory-prefix" => dir = value,
                _ => {}
            }
            continue;
        }
        if t.len() < 2 || !t.starts_with('-') {
            continue;
        }
        let flags: Vec<char> = t[1..].chars().collect();
        if wget && flags[0] == 'n' {
            continue; // -nv, -nc, -nd, -nH, -np
        }
        for (k, &c) in flags.iter().enumerate() {
            if !wget && c == 'O' {
                remote = true;
                continue;
            }
            let takes = if wget {
                c == 'O' || c == 'P' || WGET_VALUED.contains(c)
            } else {
                c == 'o' || CURL_VALUED.contains(c)
            };
            if !takes {
                continue;
            }
            let rest: String = flags[k + 1..].iter().collect();
            let value = if rest.is_empty() {
                i += 1;
                args.get(i - 1).cloned()
            } else {
                Some(rest)
            };
            match (c, wget) {
                ('o', false) | ('O', true) => outs.extend(value),
                ('P', true) => dir = value,
                _ => {}
            }
            break;
        }
    }
    // A bare file name lands in the output directory (for wget, only a
    // name taken from the URL: `-O` ignores `-P`).
    let join = |f: &str| match &dir {
        Some(d) if !f.contains('/') => format!("{}/{f}", d.trim_end_matches('/')),
        _ => f.to_string(),
    };
    let mut files = Vec::new();
    let mut body_to_stdout = false;
    for o in &outs {
        match o.as_str() {
            o if cmdline::is_stdout_path(o) => body_to_stdout = true,
            _ if o.starts_with("/dev/") => {}
            _ if wget => files.push(o.clone()),
            _ => files.push(join(o)),
        }
    }
    // wget names the file after the URL unless -O is given; curl with -O.
    // With no name in the URL, the directory it lands in.
    if remote || wget && outs.is_empty() {
        match url_name(stage) {
            Some(n) => files.push(join(&n)),
            None => files.extend(
                dir.clone()
                    .or_else(|| ctx.cwd.as_ref().map(|c| c.to_string_lossy().to_string())),
            ),
        }
    } else if !wget && outs.is_empty() {
        body_to_stdout = true;
    }
    // A redirection to stdout itself (`> /dev/stdout`) leaves it the pipe.
    let redirected: Vec<&String> = w
        .stdout
        .iter()
        .filter(|f| !cmdline::is_stdout_path(f))
        .collect();
    if body_to_stdout {
        files.extend(redirected.iter().map(|f| f.to_string()));
    }
    let files = files.iter().map(|f| canon_path(f, ctx)).collect();
    Some(Download {
        files,
        stdout: body_to_stdout && redirected.is_empty(),
    })
}

/// The file a stage executes: an interpreter's script (`bash x.sh`,
/// `python3 -X dev x.py`, `. x.sh`), the file an interpreter reads its
/// script from on stdin (`bash < x.sh`), or a path run directly (`./x`).
fn executed_file(w: &cmdline::Words, ctx: &Context) -> Option<String> {
    let head = w.words.first()?;
    match cmdline::interpreter_runs(&w.words) {
        Some(cmdline::Runs::File(f)) => Some(canon_path(&f, ctx)),
        Some(cmdline::Runs::Stdin) => match &w.stdin {
            cmdline::Stdin::File(f) => Some(canon_path(f, ctx)),
            _ => None,
        },
        Some(cmdline::Runs::Inline) => None,
        None => head.contains('/').then(|| canon_path(head, ctx)),
    }
}

/// The command string a stage hands to a shell of its own:
/// `bash -c '…'`, `su -c '…'`, `eval '…'`, `trap '…' EXIT` (and, through
/// [`cmdline::command_words`], `flock l -c '…'`, `script -c '…'`).
fn inner_command(words: &[String]) -> Option<String> {
    let head = words.first()?;
    let base = head.rsplit('/').next().unwrap_or(head);
    if base == "eval" {
        return (words.len() > 1).then(|| words[1..].join(" "));
    }
    // `trap 'bash i.sh' EXIT`: the shell runs the string when the signal
    // arrives (EXIT: when it ends).
    if base == "trap" {
        return words
            .get(1)
            .filter(|a| words.len() > 2 && !a.starts_with('-'))
            .cloned();
    }
    if base == "su" || base == "runuser" {
        let mut it = words.iter().skip(1);
        while let Some(t) = it.next() {
            if t == "-c" || t == "--command" {
                return it.next().cloned();
            }
            if let Some(v) = t.strip_prefix("--command=") {
                return Some(v.to_string());
            }
        }
        return None;
    }
    if cmdline::interpreter(head) != Some(cmdline::Interp::Shell)
        || cmdline::interpreter_runs(words) != Some(cmdline::Runs::Inline)
    {
        return None;
    }
    // The first word after the options is the command string.
    let mut i = 1;
    while let Some(t) = words.get(i) {
        let flag = (t.starts_with('-') || t.starts_with('+')) && t.len() > 1;
        if t == "--" {
            i += 1;
            break;
        }
        if !flag {
            break;
        }
        let valued = !t.starts_with("--") && (t.ends_with('o') || t.ends_with('O'))
            || matches!(t.as_str(), "--rcfile" | "--init-file");
        i += if valued { 2 } else { 1 };
    }
    words.get(i).cloned()
}

/// The deny for a download saved into agent tooling. Never gated: the
/// server decides per request what it serves.
fn tooling_download_deny(dest: &str, text: &str) -> Decision {
    let url = cmdline::first_url(text).unwrap_or_else(|| "<url>".into());
    Decision::Deny(format!(
        "Downloads into agent tooling ({dest}) with no scan. Use: sigil scan {url} — it downloads into quarantine and scans first. {BYPASS_HINT}"
    ))
}

fn classify_stage(stage: &str, ctx: &Context) -> Decision {
    if let Some(d) = agent_acquisition(stage) {
        return d;
    }
    if let Some(d) = runner(stage, ctx) {
        return d;
    }
    if let Some(d) = deno_remote(stage) {
        return d;
    }
    if let Some(d) = tooling_write(stage, ctx) {
        return d;
    }
    package_managers(stage, ctx)
}

/// Classify a Bash command. Pure function of the command and context;
/// env-based mode/bypass handling lives in `cmd_hook`.
pub fn classify_in(cmd: &str, ctx: &Context) -> Decision {
    // SIGIL_BYPASS=1 given as an env prefix inside the command string.
    if has(cmd, &format!(r"{WB}SIGIL_BYPASS=1(\s|$)")) {
        return Decision::Allow("Sigil guard bypassed (SIGIL_BYPASS=1)".into());
    }
    // A backslash-newline is a line continuation: the shell removes both,
    // so `… && sigil scan i.sh && \⏎bash i.sh` is one && chain.
    let cmd = cmd.replace("\\\r\n", "").replace("\\\n", "");

    // A download piped or substituted into an interpreter. Judged on the
    // whole command (process substitution spans segments) and never gated
    // by a prior scan: the server decides per request what it serves.
    if cmdline::pipes_download_to_interpreter(&cmd) {
        return pipe_deny(&cmd);
    }

    let mut walk = Walk {
        ctx: ctx.clone(),
        top: cmd.clone(),
        gates: Vec::new(),
        downloads: Vec::new(),
        decision: Decision::Allow(NO_MATCH.into()),
        untrusted_sigil: redefines_sigil(&cmd) || redefines_sigil(&cmdline::dequote(&cmd)),
        oldpwd: None,
        dirs: Vec::new(),
        in_subst: false,
        stdin_fed: false,
        piece_fed: false,
        subst_in: false,
        subst_out: false,
        fed_compound: None,
        list_downloads: Vec::new(),
        unsettled: Vec::new(),
    };
    walk.run(&cmd, false, 0);
    let decision = walk.decision;
    if let Decision::Allow(r) = &decision {
        if r == NO_MATCH && is_sigil(&cmd) {
            return Decision::Allow("Command uses sigil".into());
        }
    }
    decision
}

/// The deny for a download that an interpreter runs from a pipe or a
/// substitution. Never gated.
fn pipe_deny(cmd: &str) -> Decision {
    let alt = match cmdline::first_url(cmd) {
        Some(u) => format!(
            "Use: sigil scan {u} — or download it (curl -fsSLo script.sh {u}), run sigil scan script.sh, then run the file you scanned"
        ),
        None => "Download the script, run sigil scan on it, then execute the file you scanned".into(),
    };
    Decision::Deny(format!(
        "Piping a download into an interpreter executes unscanned code. {alt}. {BYPASS_HINT}"
    ))
}

/// How many `bash -c '…'` levels deep a command is followed.
const MAX_INNER: u8 = 3;

/// What a command line has done so far, segment by segment.
struct Walk {
    /// Where it runs (follows `cd`).
    ctx: Context,
    /// The whole command, for the URL a pipe deny names.
    top: String,
    /// What `sigil scan|clone|pip|npm` calls earlier in the `&&` chain vetted.
    gates: Vec<Vec<Target>>,
    /// Files curl/wget saved earlier in the command line, and copies of
    /// them.
    downloads: Vec<String>,
    decision: Decision,
    /// The command defines its own `sigil` or changes PATH: no sigil call
    /// in it vets anything.
    untrusted_sigil: bool,
    /// The directory before the last `cd`, for `cd -`.
    oldpwd: Option<Option<PathBuf>>,
    /// The `pushd` stack, for `popd`.
    dirs: Vec<Option<PathBuf>>,
    /// The string being walked runs inside a command substitution: no sigil
    /// call in it vets anything (`echo $(sigil scan x) && bash x` runs bash
    /// whatever the scan found: the status is echo's).
    in_subst: bool,
    /// The stdin of the command line being walked carries a download: it is
    /// the string of a `bash -c '…'` whose stage is fed from a download
    /// (`curl … | sh -c 'source /dev/stdin'`).
    stdin_fed: bool,
    /// The stdin of the piece being judged carries a download: `stdin_fed`
    /// for a list segment, or for a substitution what its command gives it.
    piece_fed: bool,
    /// For a substitution opened at the end of the segment just judged: its
    /// stdin carries a download (`… | bash -c "$(cat)"`: the stage's stdin
    /// is), or, for `>(…)`, what the stage writes there does
    /// (`curl … | tee >(bash)`).
    subst_in: bool,
    subst_out: bool,
    /// Inside a compound command that receives a download on stdin (`curl …
    /// | { echo; bash; }`, `curl … | while read l; do eval "$l"; done`): how
    /// many of the groups and compound commands opened since are open.
    fed_compound: Option<i32>,
    /// Files downloaded in the current and-or list, and those downloaded in
    /// a list that `&` sent to the background (`curl -o i.sh … & sigil scan
    /// i.sh && bash i.sh`): a scan may read one before the download ends,
    /// so no scan vets it until a `wait`.
    list_downloads: Vec<String>,
    unsettled: Vec<String>,
}

/// Does the text in front of a `$(`, `<(` or backtick run what the
/// substitution prints? It does when the substitution is the command word
/// (`$(cat i.sh)`), the code of `eval`, `bash -c "…"` or `python3 -c "…"`,
/// or the script of an interpreter (`bash <(cat i.sh)`, `source <(…)`).
/// `x=$(…)`, `echo $(…)` and `bash -c "echo $(…)"` do not.
fn runs_substitution(before: &str) -> bool {
    let Some((_, stage)) = stage_spans(before).pop() else {
        return true;
    };
    let toks = cmdline::tokenize(&stage);
    if toks.last().is_some_and(|t| t.ends_with('=')) {
        return false; // x=$(…)
    }
    let w = cmdline::command_words(&stage);
    let Some(head) = w.words.first() else {
        return true; // the command word
    };
    let code_missing = w.words.len() == 1 || w.words.last().is_some_and(String::is_empty);
    if head.rsplit('/').next() == Some("eval") {
        return w.words[1..].iter().all(String::is_empty);
    }
    match cmdline::interpreter_runs(&w.words) {
        Some(cmdline::Runs::Inline) => code_missing,
        Some(cmdline::Runs::Stdin) => true,
        _ => false,
    }
}

/// `cd`, `pushd` and `popd` as the working directory sees them.
enum DirChange {
    To(Option<PathBuf>),
    Back,
    Push(Option<PathBuf>),
    Pop,
}

/// The directory change a segment makes, read as the command words (so
/// grouping and redirections do not hide it). `cd -P dir`, `cd -- dir`,
/// `cd -` and a bare `popd` are followed; other forms are not.
fn dir_change(seg: &str, ctx: &Context) -> Option<DirChange> {
    let toks = cmdline::command_words(seg).words;
    let head = toks.first()?.as_str();
    if !matches!(head, "cd" | "pushd" | "popd") {
        return None;
    }
    let mut args = toks[1..].iter().map(String::as_str).peekable();
    while let Some(&a) = args.peek() {
        if a == "--" {
            args.next();
            break;
        }
        if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "LPe@".contains(c)) {
            args.next();
            continue;
        }
        break;
    }
    let rest: Vec<&str> = args.collect();
    let to = |d: Option<&&str>| match d {
        None => ctx.home.clone(),
        Some(d) => Some(expand(d, ctx)),
    };
    match (head, rest.len()) {
        ("popd", 0) => Some(DirChange::Pop),
        ("cd", 1) if rest[0] == "-" => Some(DirChange::Back),
        ("cd", 0 | 1) => Some(DirChange::To(to(rest.first()))),
        ("pushd", 1) => Some(DirChange::Push(to(rest.first()))),
        _ => None,
    }
}

/// `cp`/`mv`/`ln`/`install` of one of `files`: where the copies land (the
/// destination, and the file's name inside it when it is a directory).
fn copies(w: &cmdline::Words, files: &[String], ctx: &Context) -> Vec<(String, String)> {
    let Some(head) = w.words.first().map(|h| h.rsplit('/').next().unwrap_or(h)) else {
        return vec![];
    };
    if !matches!(head, "cp" | "mv" | "ln" | "install" | "rsync") {
        return vec![];
    }
    let valued: &[&str] = match head {
        "rsync" => &["-e", "--rsh", "--exclude", "--include", "--filter", "-f"],
        "install" => &["-m", "--mode", "-o", "--owner", "-g", "--group"],
        _ => &["-S", "--suffix"],
    };
    let mut target: Option<String> = None;
    let mut args: Vec<&String> = Vec::new();
    let mut it = w.words.iter().skip(1);
    while let Some(t) = it.next() {
        if t == "-t" || t == "--target-directory" {
            target = it.next().cloned();
        } else if let Some(v) = t.strip_prefix("--target-directory=") {
            target = Some(v.to_string());
        } else if valued.contains(&t.as_str()) {
            it.next();
        } else if !t.starts_with('-') {
            args.push(t);
        }
    }
    let dest = match target {
        Some(t) => t,
        None => match args.pop() {
            Some(d) => d.clone(),
            None => return vec![],
        },
    };
    let dest = canon_path(&dest, ctx);
    let mut out = Vec::new();
    for src in args {
        let s = canon_path(src, ctx);
        if files.contains(&s) {
            let name = s.rsplit('/').next().unwrap_or(&s).to_string();
            out.push((s.clone(), dest.clone()));
            out.push((s, format!("{}/{name}", dest.trim_end_matches('/'))));
        }
    }
    out
}

/// Files a stage writes: its stdout redirections, `dd of=`, the files `tee`
/// writes, where `cp`/`mv`/`ln`/`install`/`rsync` put what they copy, and
/// the files `sed -i`, `perl -i` and `ruby -i` edit in place.
fn overwrites(w: &cmdline::Words, dd_out: &[String], ctx: &Context) -> Vec<String> {
    let mut out: Vec<String> = w
        .stdout
        .iter()
        .chain(dd_out)
        .filter(|f| !f.starts_with("/dev/"))
        .map(|f| canon_path(f, ctx))
        .collect();
    let Some(head) = w.words.first().map(|h| h.rsplit('/').next().unwrap_or(h)) else {
        return out;
    };
    let args = &w.words[1..];
    let operands: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| canon_path(a, ctx))
        .collect();
    // An `-i` in a bundle of short options, before any option whose value
    // is attached (`perl -Mstrict` loads a module; its `i` is not -i).
    let in_place = |attached: &str| {
        args.iter().any(|a| {
            a == "--in-place"
                || a.starts_with("--in-place=")
                || a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..]
                        .chars()
                        .take_while(|c| !attached.contains(*c))
                        .any(|c| c == 'i')
        })
    };
    match head {
        "tee" => out.extend(operands),
        "sed" | "gsed" if in_place("ef") => out.extend(operands),
        "perl" if in_place("MmxFl0dIeEC") => out.extend(operands),
        "ruby" if in_place("rIxFeE0C") => out.extend(operands),
        "cp" | "mv" | "ln" | "install" | "rsync" => {
            out.extend(copies(w, &operands, ctx).into_iter().map(|(_, dest)| dest));
        }
        _ => {}
    }
    out
}

/// Where xargs gets the code it runs, when it hands the words it reads to
/// inline code that has none of its own: `xargs -0 bash -c`, `xargs
/// python3 -c`, or code built from them (`xargs -I{} sh -c '{}'`, `sh -c
/// '$0'`). Stdin, or the file of `xargs -a f`.
fn xargs_code(w: &cmdline::Words) -> Option<&cmdline::Stdin> {
    let src = w.xargs.as_ref()?;
    if cmdline::interpreter_runs(&w.words) != Some(cmdline::Runs::Inline) {
        return None;
    }
    let from_input = match inner_command(&w.words) {
        Some(code) => code.contains("{}") || matches!(code.trim(), "$0" | "$1" | "$@" | "$*"),
        None => w.words.last().is_some_and(|t| t.starts_with('-')),
    };
    from_input.then_some(src)
}

/// A word that is one parameter expansion and nothing else: `$l`, `${l}`,
/// `$1`, `$@`.
fn is_variable(s: &str) -> bool {
    static VAR: OnceLock<Regex> = OnceLock::new();
    VAR.get_or_init(|| {
        Regex::new(r"^\$(\{?[A-Za-z_][A-Za-z0-9_]*\}?|[0-9@*])$").expect("static pattern")
    })
    .is_match(s.trim())
}

/// Code that runs what the stage reads on stdin, though the stage is not an
/// interpreter reading it as a script: a variable run as code (`eval
/// "$l"`, `bash -c "$line"`, as in `… | while read l; do eval "$l";
/// done`), or inline code that reads stdin and evaluates it (`python3 -c
/// "exec(sys.stdin.read())"`, `node -e "eval(fs.readFileSync(0, …))"`,
/// `perl -e 'eval join "", <STDIN>'`, `ruby -e 'eval STDIN.read'`).
fn runs_read_code(words: &[String]) -> bool {
    static EXEC: OnceLock<Regex> = OnceLock::new();
    static READ: OnceLock<Regex> = OnceLock::new();
    if inner_command(words).is_some_and(|code| is_variable(&code)) {
        return true;
    }
    let Some(kind) = words.first().and_then(|h| cmdline::interpreter(h)) else {
        return false;
    };
    if !matches!(
        kind,
        cmdline::Interp::Python
            | cmdline::Interp::Node
            | cmdline::Interp::Perl
            | cmdline::Interp::Ruby
            | cmdline::Interp::Php
    ) || cmdline::interpreter_runs(words) != Some(cmdline::Runs::Inline)
    {
        return false;
    }
    let code = words[1..].join(" ");
    EXEC.get_or_init(|| {
        Regex::new(r"\b(exec|eval|compile|Function|instance_eval)\s*[\(\s]")
            .expect("static pattern")
    })
    .is_match(&code)
        && READ
            .get_or_init(|| {
                Regex::new(r"(?i)stdin|readFileSync\(\s*0|<>|\$<|ARGF|php://input|\binput\(")
                    .expect("static pattern")
            })
            .is_match(&code)
}

impl Walk {
    /// A stage gated by the `&&` chain is allowed.
    fn gate(&self, d: Decision, targets: &[Target]) -> Decision {
        if d.rank() > 0 && self.vetted(targets) {
            Decision::Allow("Gated by a preceding sigil check on the same target".into())
        } else {
            d
        }
    }

    /// The `&&` chain vetted every target, and none is a file still being
    /// downloaded in the background.
    fn vetted(&self, targets: &[Target]) -> bool {
        gated(&self.gates, targets)
            && !targets
                .iter()
                .any(|t| matches!(t, Target::Path(p) if self.unsettled.contains(p)))
    }

    /// A download replaces the file: a scan of it that ran earlier read
    /// other bytes, so it no longer vets it.
    fn record_download(&mut self, f: String) {
        let t = Target::Path(f.clone());
        for g in &mut self.gates {
            g.retain(|x| *x != t);
        }
        if !self.list_downloads.contains(&f) {
            self.list_downloads.push(f.clone());
        }
        if !self.downloads.contains(&f) {
            self.downloads.push(f);
        }
    }

    fn judge(&mut self, d: Decision) {
        let prev = std::mem::replace(&mut self.decision, Decision::Allow(NO_MATCH.into()));
        self.decision = worse(prev, d);
    }

    /// Judge `cmd` segment by segment. `inherit`: the first segment
    /// continues the caller's `&&` chain (the string of a `bash -c`).
    fn run(&mut self, cmd: &str, inherit: bool, depth: u8) {
        let chars: Vec<char> = cmd.chars().collect();
        let q = quote_map(&chars);
        let inner = inner_strings(&chars, &q);
        let pcs = pieces(&chars, &q);
        // The directory each open `( … )` group and substitution started
        // in (they are subshells, so a `cd` in one ends with it), and
        // whether it is a substitution.
        let mut groups: Vec<(Option<PathBuf>, bool)> = Vec::new();
        // The directory the current and-or list started in: a list that `&`
        // ends ran in a background subshell (`cd /tmp & …`, `cd /tmp && x &
        // …`), so its `cd` ends with it.
        let mut list_cwd = self.ctx.cwd.clone();
        for (n, p) in pcs.iter().enumerate() {
            if p.op == Op::Bg {
                self.ctx.cwd = list_cwd.clone();
                // The list before the `&` runs in the background: what it
                // downloads may still be arriving when later commands run.
                let bg = std::mem::take(&mut self.list_downloads);
                self.unsettled.extend(bg);
            }
            if matches!(p.op, Op::Other | Op::Bg) {
                list_cwd = self.ctx.cwd.clone();
                self.list_downloads.clear();
            }
            // `;`, `||`, `&` and newlines end the `&&` chain. A substitution
            // runs as part of the command around it, so it neither ends the
            // chain nor starts one.
            if matches!(p.op, Op::Other | Op::Bg) || n == 0 && !inherit {
                self.gates.clear();
            }
            match p.op {
                Op::Subst | Op::OutSubst | Op::Tick => groups.push((self.ctx.cwd.clone(), true)),
                Op::Untick => {
                    if let Some((c, _)) = groups.pop() {
                        self.ctx.cwd = c;
                    }
                }
                _ => {}
            }
            let executed = matches!(p.op, Op::Subst | Op::Tick)
                && n > 0
                && runs_substitution(&pcs[n - 1].text);
            // What the piece reads on stdin: a substitution reads what the
            // command around it gives it; anything else, the command
            // line's own stdin.
            self.piece_fed = match p.op {
                Op::Subst | Op::Tick => self.subst_in,
                Op::OutSubst => self.subst_out,
                _ => self.stdin_fed || self.fed_compound.is_some(),
            };
            self.subst_in = false;
            self.subst_out = false;
            // Unquoted `(` at the start open groups; an unquoted `)` that
            // closes nothing opened in this piece closes one opened before.
            let text: Vec<char> = p.text.chars().collect();
            let mut k = 0;
            while k < text.len() && (text[k] == '(' || text[k].is_whitespace()) {
                if text[k] == '(' && q.get(p.start + k) == Some(&Q::Out) {
                    groups.push((self.ctx.cwd.clone(), false));
                }
                k += 1;
            }
            let in_subst = self.in_subst || groups.iter().any(|(_, s)| *s);
            match dir_change(&uncommented(&p.text, p.start, &q), &self.ctx) {
                Some(change) => {
                    let here = self.ctx.cwd.clone();
                    match change {
                        DirChange::To(d) => self.ctx.cwd = d,
                        DirChange::Back => {
                            if let Some(d) = self.oldpwd.clone() {
                                self.ctx.cwd = d;
                            }
                        }
                        DirChange::Push(d) => {
                            self.dirs.push(here.clone());
                            self.ctx.cwd = d;
                        }
                        DirChange::Pop => {
                            if let Some(d) = self.dirs.pop() {
                                self.ctx.cwd = d;
                            }
                        }
                    }
                    self.oldpwd = Some(here);
                }
                None if !p.text.trim().is_empty() => {
                    let outer = std::mem::replace(&mut self.in_subst, in_subst);
                    self.segment(p, &q, &inner, depth, executed);
                    self.in_subst = outer;
                }
                None => {}
            }
            let mut open = 0;
            for (j, c) in text.iter().enumerate().skip(k) {
                if q.get(p.start + j) != Some(&Q::Out) {
                    continue;
                }
                match c {
                    '(' => open += 1,
                    ')' if open > 0 => open -= 1,
                    ')' => {
                        if let Some((cwd, _)) = groups.pop() {
                            self.ctx.cwd = cwd;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Judge one list segment: its pipeline stages, then the command
    /// strings they hand to a shell of their own. `executed`: the segment
    /// opens a substitution whose output runs as code (`eval "$(…)"`).
    fn segment(&mut self, p: &Piece, q: &[Q], inner_full: &WholeStages, depth: u8, executed: bool) {
        // A substitution's stdin, or the command line's (the string of a
        // `bash -c` fed from a download), reaches the first stage.
        let mut pipe = Pipe {
            fed: self.piece_fed,
            ..Pipe::default()
        };
        // Each string a stage hands to a shell, and whether the stage's
        // stdin carries a download.
        let mut inner: Vec<(String, bool)> = Vec::new();
        let spans = stage_spans(&p.text);
        let last = spans.len().saturating_sub(1);
        // The stdin of the last stage, and what it writes: a substitution
        // that closes the segment opens inside it.
        let (mut last_in, mut last_out) = (false, false);
        for (k, (off, raw)) in spans.iter().enumerate() {
            let stage = raw.trim();
            if stage.is_empty() {
                continue;
            }
            let lead = raw.chars().take_while(|c| c.is_whitespace()).count();
            let at = p.start + off + lead;
            // A substitution ends at its `)`: `>(bash) >/dev/null` runs
            // `bash`. What follows belongs to the command around it and is
            // judged as a stage of its own (`$(true) npm install evil`,
            // `$(sigil --version) npm install evil`).
            let parts = match p.op {
                Op::Subst | Op::OutSubst if k == 0 => match split_close(stage, at, q) {
                    (head, Some(tail)) => vec![(head, at), tail],
                    (head, None) => vec![(head, at)],
                },
                _ => vec![(stage, at)],
            };
            let subst_head = matches!(p.op, Op::Subst | Op::OutSubst) && k == 0;
            for (n, (stage, at)) in parts.into_iter().enumerate() {
                if stage.is_empty() {
                    continue;
                }
                // Groups and compound commands this stage opens and closes
                // (not the substitution it starts, which ends at its `)`).
                let (opens, closes) = if subst_head && n == 0 {
                    (0, 0)
                } else {
                    compound_marks(stage, at, q)
                };
                let fed_before = pipe.fed;
                self.stage_part(
                    stage,
                    at,
                    p,
                    q,
                    k,
                    last,
                    &mut pipe,
                    executed && n == 0,
                    depth,
                    inner_full,
                    &mut inner,
                    &mut last_in,
                    &mut last_out,
                );
                // A compound command whose stdin is a download: every command
                // in it reads that stdin, until it closes.
                self.fed_compound = match self.fed_compound {
                    Some(d) if d + opens - closes > 0 => Some(d + opens - closes),
                    Some(_) => None,
                    None if fed_before && opens > closes => Some(opens - closes),
                    None => None,
                };
            }
        }
        // `bash -c '…'`: the string is a command line of its own, run in a
        // child shell (a `cd` in it does not last) with the stage's stdin.
        for (s, fed) in inner {
            let cwd = self.ctx.cwd.clone();
            let outer = std::mem::replace(&mut self.stdin_fed, fed);
            let compound = self.fed_compound.take();
            self.run(&s, true, depth + 1);
            self.fed_compound = compound;
            self.stdin_fed = outer;
            self.ctx.cwd = cwd;
        }
        self.subst_in = last_in;
        self.subst_out = last_out;
    }

    /// One stage of a segment (or the part of one before or after the `)`
    /// of a substitution): a sigil call's gate, the stage's judgement, the
    /// segment's last-stage state and the strings it hands to a shell.
    #[allow(clippy::too_many_arguments)]
    fn stage_part(
        &mut self,
        stage: &str,
        at: usize,
        p: &Piece,
        q: &[Q],
        k: usize,
        last: usize,
        pipe: &mut Pipe,
        executed: bool,
        depth: u8,
        inner_full: &WholeStages,
        inner: &mut Vec<(String, bool)>,
        last_in: &mut bool,
        last_out: &mut bool,
    ) {
        // The command is going through sigil: that stage is allowed, and a
        // vetting call gates what follows it with `&&` — when it is the real
        // sigil, outside quotes and substitutions, and the pipeline's exit
        // status is its own (the last stage: `sigil scan x | tee log` exits
        // with tee's status).
        if is_sigil(stage) {
            if !self.untrusted_sigil
                && !self.in_subst
                && trusted_sigil(stage)
                && q.get(at) == Some(&Q::Out)
                && k == last
            {
                if let Some(t) = vetting_targets(stage, &self.ctx) {
                    self.gates.push(t);
                }
            }
            return;
        }
        // What the stage runs is read without its `# comment`
        // (`curl … | python3 -E # install`); the classifiers still see the
        // whole text.
        let w = cmdline::command_words(&uncommented(stage, at, q));
        let fed_in = pipe.fed && w.stdin == cmdline::Stdin::Inherit;
        let reads_code = inner_full.reads_code.contains(&at);
        self.stage(stage, &p.text, &w, k, pipe, executed, reads_code);
        if k == last {
            (*last_in, *last_out) = (fed_in, pipe.fed);
        }
        if depth < MAX_INNER {
            // The string read whole when a separator in it cut this stage
            // short.
            inner.extend(
                inner_full
                    .inner
                    .get(&at)
                    .cloned()
                    .or_else(|| inner_command(&w.words))
                    .map(|s| (s, fed_in)),
            );
        }
    }

    /// Judge one stage. `reads_code`: read whole (a separator inside its
    /// quotes cut `stage` short), its inline code runs its stdin.
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &mut self,
        stage: &str,
        seg: &str,
        w: &cmdline::Words,
        k: usize,
        pipe: &mut Pipe,
        executed: bool,
        reads_code: bool,
    ) {
        let ctx = self.ctx.clone();
        // Judged as written and with word-internal quoting removed, as the
        // shell reads it (`"npm" exec x`, `de''no run …`, `pip''x install`).
        let mut d = Decision::Allow(NO_MATCH.into());
        let dq = cmdline::dequote(stage);
        for v in [stage, dq.as_str()] {
            let dv = classify_stage(v, &ctx);
            d = worse(d, self.gate(dv, &stage_targets(v, &ctx)));
            if dq == stage {
                break;
            }
        }
        // The files this stage reads: its arguments and a `< file`.
        let mut reads: Vec<String> = w
            .words
            .iter()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .map(|a| canon_path(a, &ctx))
            .collect();
        if let cmdline::Stdin::File(f) = &w.stdin {
            reads.push(canon_path(f, &ctx));
        }
        // `dd if=f of=g`: the file it reads and the file it writes, as
        // `< f` and `> g` would be.
        let dd = w
            .words
            .first()
            .is_some_and(|h| h.rsplit('/').next() == Some("dd"));
        let dd_arg = |key: &str| -> Vec<String> {
            w.words
                .iter()
                .skip(1)
                .filter(|_| dd)
                .filter_map(|a| a.strip_prefix(key).map(str::to_string))
                .collect()
        };
        let dd_out = dd_arg("of=");
        reads.extend(dd_arg("if=").iter().map(|f| canon_path(f, &ctx)));
        let reads_download = reads.iter().find(|f| self.downloads.contains(f)).cloned();
        // `xargs -0 bash -c`, `xargs -I{} sh -c '{}'`: the words xargs reads
        // are the code; `xargs -a f …` reads them from f.
        let xargs = xargs_code(w);
        // A program that runs what comes down its stdin: an interpreter
        // (also a shell that `sudo -s` or `su` starts), or inline code that
        // xargs fills in from stdin.
        let runs_stdin = w.stdin == cmdline::Stdin::Inherit
            && (cmdline::interpreter_runs(&w.words) == Some(cmdline::Runs::Stdin)
                || xargs == Some(&cmdline::Stdin::Inherit)
                || reads_code
                || runs_read_code(&w.words)
                // `… | while read l; do $l; done`: a variable as the whole
                // command, inside a compound command that reads the
                // download (not `… | $PAGER`, whose program is unknown).
                || self.fed_compound.is_some() && w.words.len() == 1 && is_variable(&w.words[0]));
        let reads_pipe = k > 0 && runs_stdin;
        if runs_stdin && pipe.fed {
            // `curl … | base64 -d | sh`, `curl … | (bash)`, `curl … | node -r x`,
            // `curl … | sudo -s`, `curl … | sh -c 'source /dev/stdin'`,
            // `curl … | tee >(bash)`.
            d = worse(d, pipe_deny(&self.top));
        }
        // `curl … | bash -c "$(cat)"`, `curl … | eval "$(cat)"`: a
        // substitution that prints its stdin, the download, as code.
        if executed && k == 0 && pipe.fed && cmdline::passes_stdin(w) {
            d = worse(d, pipe_deny(&self.top));
        }
        // Download to a file, then run that file: the same remote execution
        // as `curl … | sh`, one step removed. Unlike the pipe, this form can
        // be gated — the scan reads the bytes that run.
        let xargs_file = match xargs {
            Some(cmdline::Stdin::File(f)) => Some(canon_path(f, &ctx)),
            _ => None,
        };
        let ran = executed_file(w, &ctx)
            .into_iter()
            .chain(xargs_file)
            .find(|f| self.downloads.contains(f))
            .map(|f| (f, stage))
            .or_else(|| {
                // `cat i.sh | sh`, `head i.sh | sh`: the file, read into an
                // interpreter.
                let f = pipe.sources.iter().find(|f| self.downloads.contains(f))?;
                reads_pipe.then(|| (f.clone(), seg))
            });
        if let Some((f, shown)) = ran {
            let deny = Decision::Deny(format!(
                "Runs {f}, downloaded earlier in this command, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan {f} && {} (after the download). {BYPASS_HINT}",
                shown.trim()
            ));
            d = worse(d, self.gate(deny, &[Target::Path(f)]));
        }
        // `eval "$(cat i.sh)"`, `bash <(cat i.sh)`: a substitution whose
        // output runs as code, printing a downloaded file.
        if let Some(f) = reads_download.as_ref().filter(|_| executed) {
            let deny = Decision::Deny(format!(
                "Runs {f}, downloaded earlier in this command, through a command substitution, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan {f} before running it. {BYPASS_HINT}"
            ));
            d = worse(d, self.gate(deny, &[Target::Path(f.clone())]));
        }
        // What this stage writes a download to.
        let mut written: Vec<String> = Vec::new();
        let dl = download(w, stage, &ctx);
        if let Some(dl) = &dl {
            written.extend(dl.files.iter().cloned());
        }
        let carried = pipe.fed || k > 0 && pipe.sources.iter().any(|f| self.downloads.contains(f));
        if carried || reads_download.is_some() {
            // `curl … | tee f`, `curl … | sed … > f`, `cat i.sh > j.sh`: the
            // download, passed on.
            let tee = w
                .words
                .first()
                .is_some_and(|h| h.rsplit('/').next() == Some("tee"));
            let args = if tee && carried {
                &w.words[1..]
            } else {
                &[][..]
            };
            let piped: Vec<String> = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .chain(&w.stdout)
                .chain(&dd_out)
                .filter(|f| !f.starts_with("/dev/"))
                .map(|f| canon_path(f, &ctx))
                .collect();
            if pipe.fed {
                if let Some(dest) = piped.iter().find(|f| agent_path(f)) {
                    d = worse(d, tooling_download_deny(dest, seg));
                }
            }
            written.extend(piped);
        }
        // A file downloaded earlier and written again — edited in place
        // (`sed -i`, `perl -pi`), appended to, overwritten or replaced by a
        // copy — holds other bytes than a scan of it read: the scan no
        // longer vets it (`sigil scan i.sh && sed -i 's/^#//' i.sh && bash
        // i.sh` runs lines the scan saw as comments).
        written.extend(
            overwrites(w, &dd_out, &ctx)
                .into_iter()
                .filter(|f| self.downloads.contains(f)),
        );
        // `cp i.sh j.sh`, `mv i.sh j.sh`: the copy is the download too; a
        // copy of a file the chain has scanned holds the scanned bytes
        // (`sigil scan i.sh && cp i.sh j.sh && bash j.sh`).
        let copied = copies(w, &self.downloads, &ctx);
        let vetted: Vec<Target> = copied
            .iter()
            .filter(|(src, _)| self.vetted(&[Target::Path(src.clone())]))
            .map(|(_, dest)| Target::Path(dest.clone()))
            .collect();
        written.extend(copied.into_iter().map(|(_, dest)| dest));
        if dl.is_some_and(|dl| dl.stdout) {
            pipe.fed = true;
        }
        pipe.sources.extend(reads);
        for f in written {
            self.record_download(f);
        }
        if !vetted.is_empty() {
            self.gates.push(vetted);
        }
        // A sourced file can define a `sigil` function or change PATH: no
        // sigil call after it vets anything.
        if w.words.first().map(|h| cmdline::interpreter(h)) == Some(Some(cmdline::Interp::Source)) {
            self.untrusted_sigil = true;
        }
        // `wait`: the background downloads have ended.
        if w.words.first().is_some_and(|h| h == "wait") {
            self.unsettled.clear();
        }
        self.judge(d);
    }
}

/// What earlier stages of a pipeline put into it.
#[derive(Default)]
struct Pipe {
    /// A download written to stdout.
    fed: bool,
    /// Files read into it (`cat f |`, `< f`, `head f |`).
    sources: Vec<String>,
}

/// Judge a Write/Edit to a file: only agent tooling is in scope.
pub fn classify_write(path: &str, content: &str, ctx: &Context) -> Decision {
    let resolved = expand(path, ctx);
    let shown = resolved.to_string_lossy().to_string();
    if !agent_path(&shown) && !agent_path(path) {
        return Decision::Allow("Not agent tooling".into());
    }
    if cmdline::pipes_download_to_interpreter(content) {
        return Decision::Deny(format!(
            "Writes a command that pipes a download into an interpreter into agent tooling ({shown}); it would run unscanned code automatically. {BYPASS_HINT}"
        ));
    }
    if cmdline::forwards_stdin(content) || content.contains("/dev/tcp/") {
        return Decision::Deny(format!(
            "Writes a command into agent tooling ({shown}) that ships data off the machine. Hook payloads carry tool inputs and file contents. {BYPASS_HINT}"
        ));
    }
    let lower = shown.to_ascii_lowercase();
    let auto_runs = lower.ends_with("settings.json") && content.contains("\"hooks\"")
        || lower.ends_with("settings.local.json") && content.contains("\"hooks\"")
        || lower.ends_with("hooks.json")
        || lower.ends_with(".mcp.json")
        || lower.ends_with("mcp.json")
        || lower.ends_with("claude_desktop_config.json")
        || lower.ends_with("mcp_config.json")
        || lower.ends_with(".claude.json")
        || (lower.ends_with("config.toml") && content.contains("mcp_servers"));
    if auto_runs {
        return Decision::Ask(format!(
            "The agent is changing its own hooks or MCP servers ({shown}); they run with your privileges on every session. Confirm the change is intended, then audit with: sigil skills scan"
        ));
    }
    Decision::Allow("Agent tooling edit with no auto-run content".into())
}

fn emit(decision: &str, reason: &str) -> i32 {
    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    println!("{out}");
    0
}

pub fn cmd_hook(event: &str) -> i32 {
    if !event.eq_ignore_ascii_case("pretooluse") {
        eprintln!("sigil hook: unsupported event '{event}' (supported: pretooluse)");
        // Exit 0 with no stdout: an unsupported event must never block a tool
        // call — Claude Code treats empty hook output as a no-op.
        return 0;
    }

    let mode = std::env::var("SIGIL_GUARD_MODE").unwrap_or_else(|_| "enforce".into());
    if mode == "off" {
        return emit("allow", "Sigil guard disabled (SIGIL_GUARD_MODE=off)");
    }
    if std::env::var("SIGIL_BYPASS").as_deref() == Ok("1") {
        return emit("allow", "Sigil guard bypassed (SIGIL_BYPASS=1)");
    }

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return emit("allow", "Sigil guard: no command extracted");
    }

    // Fail-open on parse: an unparseable payload is a hook-plumbing problem,
    // not evidence of an acquisition attempt. We gate patterns, not people.
    let payload = serde_json::from_str::<Value>(&input).unwrap_or(Value::Null);
    let ctx = Context {
        cwd: payload
            .pointer("/cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from),
        home: dirs::home_dir(),
    };
    let tool = payload
        .pointer("/tool_name")
        .and_then(Value::as_str)
        .unwrap_or("Bash");

    let decision = match tool {
        "Write" | "Edit" | "MultiEdit" => {
            let path = payload
                .pointer("/tool_input/file_path")
                .and_then(Value::as_str)
                .unwrap_or("");
            if path.is_empty() {
                return emit("allow", "Sigil guard: no file path extracted");
            }
            let mut content = String::new();
            for key in ["/tool_input/content", "/tool_input/new_string"] {
                if let Some(s) = payload.pointer(key).and_then(Value::as_str) {
                    content.push_str(s);
                    content.push('\n');
                }
            }
            if let Some(Value::Array(edits)) = payload.pointer("/tool_input/edits") {
                for e in edits {
                    if let Some(s) = e.get("new_string").and_then(Value::as_str) {
                        content.push_str(s);
                        content.push('\n');
                    }
                }
            }
            classify_write(path, &content, &ctx)
        }
        _ => {
            let cmd = payload
                .pointer("/tool_input/command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if cmd.is_empty() {
                return emit("allow", "Sigil guard: no command extracted");
            }
            classify_in(cmd, &ctx)
        }
    };

    match decision {
        Decision::Allow(reason) => emit("allow", &reason),
        Decision::Ask(reason) => emit("ask", &reason),
        // In advise mode every deny is downgraded to ask.
        Decision::Deny(reason) if mode == "advise" => emit("ask", &reason),
        Decision::Deny(reason) => emit("deny", &reason),
    }
}

#[cfg(test)]
#[path = "hook_tests.rs"]
mod tests;
