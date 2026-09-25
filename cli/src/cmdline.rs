//! Shell command-line analysis shared by the PreToolUse hook (`hook.rs`)
//! and the installed-tooling posture scan (`inventory.rs`).
//!
//! Both look at the same thing from two sides: a command an agent is about
//! to run, and a command a config file will run on every agent start (an
//! MCP server's `command`/`args`, a Claude Code hook). The shapes that
//! matter are the same — a download piped into an interpreter, a package
//! runner that fetches whatever the registry serves today, a command that
//! ships data off the machine — so they are recognised in one place.
//!
//! This is pattern analysis of text, not a shell parser. It errs toward
//! seeing a shape inside quotes (`bash -c 'curl x | sh'` is still a pipe to
//! a shell) because the cost of that is a question, and the cost of the
//! opposite is a skipped check.

use regex::Regex;
use std::sync::OnceLock;

/// Split a command line into words, honouring single and double quotes and
/// backslash escapes the way a POSIX shell would for simple commands.
/// Operators are not split out: callers split segments first.
pub fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    cur.push(d);
                }
            }
            '"' => {
                in_word = true;
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' => {
                            if let Some(&n) = chars.peek() {
                                if matches!(n, '"' | '\\' | '$' | '`') {
                                    cur.push(n);
                                    chars.next();
                                    continue;
                                }
                            }
                            cur.push('\\');
                        }
                        _ => cur.push(d),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static pattern compiles"))
}

/// Remove quoting that does not change what a word is: quotes around a
/// run with no whitespace or quote in it (`"bash"`, `de''no`, `'npm'`) and a
/// backslash in front of a word character (`b\ash`). A quoted string with
/// whitespace keeps its quotes, so `bash -c 'npm install x'` keeps its shape.
/// The result is for pattern matching only.
pub fn dequote(s: &str) -> String {
    static SQ: OnceLock<Regex> = OnceLock::new();
    static DQ: OnceLock<Regex> = OnceLock::new();
    static BS: OnceLock<Regex> = OnceLock::new();
    if !s.contains(['\'', '"', '\\']) {
        return s.to_string();
    }
    let a = re(&SQ, r#"'([^'"[[:space:]]]*)'"#).replace_all(s, "$1");
    let b = re(&DQ, r#""([^'"[[:space:]]]*)""#).replace_all(&a, "$1");
    re(&BS, r"\\([A-Za-z0-9_./-])")
        .replace_all(&b, "$1")
        .into_owned()
}

/// A redirection word: `> f`, `2>&1`, `&>f`, `< f`, `<<EOF`, `<<< s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// It replaces stdin (`<`, `<>`, `<<`, `<<<`, `<&` on descriptor 0).
    pub stdin: bool,
    /// Stdin becomes text on the command line (a here-document or
    /// here-string), not a file.
    pub inline: bool,
    /// It sends stdout to a file (`>`, `>>`, `>|`, `1>`, `&>`, `>& file`).
    pub stdout: bool,
    /// The file, when it is part of the word (`>out.txt`).
    pub target: Option<String>,
    /// The file is the next word (`> out.txt`).
    pub takes_next: bool,
    /// The descriptor it redirects, as written (`2` in `2>&1`, `&` in
    /// `&>f`, empty for the default).
    pub fd: String,
    /// The descriptor it copies instead of opening a file (`1` in `2>&1`,
    /// `0` in `<&0` or `3<&0`, `-` to close).
    pub dup: Option<String>,
}

/// Paths that name a process's own stdin: reading one reads the pipe.
pub fn is_stdin_path(p: &str) -> bool {
    matches!(
        p,
        "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0" | "/proc/$$/fd/0"
    )
}

/// Paths that name a process's own stdout: writing to one writes to the
/// pipe (`curl … -o /dev/fd/1 | …`, `curl … > /dev/stdout | …`).
pub fn is_stdout_path(p: &str) -> bool {
    matches!(
        p,
        "-" | "/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1" | "/proc/$$/fd/1"
    )
}

/// Parse a word as a redirection: the operator starts the word, after an
/// optional descriptor number (`2>`) or `&` (`&>`). A word with another `<`
/// or `>` after the operator is a documentation placeholder
/// (`<repo>/skills/x`), not a redirection.
pub fn redirection(t: &str) -> Option<Redirect> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let c = re(&RE, r"(?s)^([0-9]*|&)(<<<|<<-|<<|<>|<&|>&|>>|>\||<|>)(.*)$").captures(t)?;
    let fd = c.get(1).map_or("", |m| m.as_str());
    let op = c.get(2).map_or("", |m| m.as_str());
    let rest = c.get(3).map_or("", |m| m.as_str());
    if rest.contains(['<', '>']) {
        return None;
    }
    let input = op.starts_with('<');
    let on_stdin = input && (fd.is_empty() || fd == "0");
    let mut r = Redirect {
        stdin: on_stdin,
        inline: on_stdin && matches!(op, "<<" | "<<-" | "<<<"),
        stdout: !input && matches!(fd, "" | "1" | "&"),
        target: None,
        takes_next: false,
        fd: fd.to_string(),
        dup: None,
    };
    if matches!(op, ">&" | "<&") {
        if rest.is_empty() && op == ">&" {
            // `>& file`: stdout and stderr to the file.
            r.takes_next = true;
        } else if rest.chars().all(|ch| ch.is_ascii_digit() || ch == '-') {
            // `2>&1`, `>&2`, `<&3`: another descriptor, not a file.
            r.stdout = false;
            r.dup = Some(rest.to_string());
        } else {
            r.target = Some(rest.to_string());
        }
        return Some(r);
    }
    if rest.is_empty() {
        r.takes_next = true;
    } else {
        r.target = Some(rest.to_string());
    }
    Some(r)
}

/// Where a simple command's stdin comes from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Stdin {
    /// The pipe or terminal it was started with.
    #[default]
    Inherit,
    /// `< file`.
    File(String),
    /// A here-document or here-string, or another descriptor (`<&3`).
    Inline,
}

/// A simple command as the shell runs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Words {
    /// The command word and its arguments, with grouping (`(`, `{`, `if`,
    /// `do`, ...), leading `VAR=value` assignments, redirections and
    /// wrapper commands (`sudo -u root`, `env -i`, `command`, `exec`,
    /// `nohup`, `time`, `xargs`, ...) removed. Empty when a wrapper runs
    /// nothing (`sudo -l`, `command -v x`).
    pub words: Vec<String>,
    /// Where stdin comes from.
    pub stdin: Stdin,
    /// Files stdout is written to (`> f`, `>> f`, `1> f`, `&> f`).
    pub stdout: Vec<String>,
    /// The command runs behind `xargs`, which reads the words it appends
    /// from here: stdin, or the file of `-a f` / `--arg-file f`. With an
    /// inline-code interpreter and no code of its own (`xargs -0 bash -c`,
    /// `xargs -I{} sh -c '{}'`), those words are the code it runs.
    pub xargs: Option<Stdin>,
}

fn is_assignment(t: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    re(&RE, r"^[A-Za-z_][A-Za-z0-9_]*\+?=").is_match(t)
}

/// A command that runs its remaining arguments as another command: its
/// short options that take a value, long options that take the next word
/// as a value, short options after which no command runs, the operands it
/// takes before the command, whether `VAR=value` words may come first, the
/// short options whose value is a command line for a shell (`flock -c
/// '…'`, `script -c '…'`), and the short options that start a shell of
/// their own when no command follows (`sudo -s`, `sudo -i`, `doas -s`),
/// which then reads its commands from stdin.
struct Wrapper {
    short_valued: &'static str,
    long_valued: &'static [&'static str],
    no_command: &'static str,
    operands: usize,
    assignments: bool,
    string_opt: &'static str,
    shell_opt: &'static str,
}

fn wrapper(head: &str) -> Option<Wrapper> {
    let w = |short_valued, long_valued, no_command, operands, assignments| Wrapper {
        short_valued,
        long_valued,
        no_command,
        operands,
        assignments,
        string_opt: "",
        shell_opt: "",
    };
    const NONE: &[&str] = &[];
    Some(match head {
        "sudo" => Wrapper {
            shell_opt: "si",
            ..w(
                "ugCDhprtTUR",
                &[
                    "--user",
                    "--group",
                    "--close-from",
                    "--chdir",
                    "--host",
                    "--prompt",
                    "--role",
                    "--type",
                    "--command-timeout",
                    "--other-user",
                    "--chroot",
                ],
                "lveVK",
                0,
                true,
            )
        },
        "doas" => Wrapper {
            shell_opt: "s",
            ..w("u", NONE, "CL", 0, false)
        },
        "env" => w(
            "uCS",
            &["--unset", "--chdir", "--split-string"],
            "",
            0,
            true,
        ),
        "command" => w("", NONE, "vV", 0, false),
        "builtin" | "nohup" | "busybox" | "setsid" | "setpriv" => w("", NONE, "", 0, false),
        "exec" => w("a", NONE, "", 0, false),
        "time" => w("fo", &["--format", "--output"], "", 0, false),
        "nice" => w("n", &["--adjustment"], "", 0, false),
        "timeout" => w("sk", &["--signal", "--kill-after"], "", 1, false),
        "stdbuf" => w("ioe", &["--input", "--output", "--error"], "", 0, false),
        "ionice" => w(
            "cnpPu",
            &["--class", "--classdata", "--pid", "--pgid", "--uid"],
            "",
            0,
            false,
        ),
        "xargs" => w(
            "adEILnPs",
            &[
                "--arg-file",
                "--delimiter",
                "--eof",
                "--max-lines",
                "--max-args",
                "--max-procs",
                "--max-chars",
                "--process-slot-var",
            ],
            "",
            0,
            false,
        ),
        // `flock /tmp/l bash i.sh`, `flock /tmp/l -c 'bash i.sh'`.
        "flock" => Wrapper {
            string_opt: "c",
            ..w("wE", &["--timeout", "--conflict-exit-code"], "hV", 1, false)
        },
        // `chroot / bash i.sh`, `taskset -c 0 bash i.sh`, `chrt -f 9 bash
        // i.sh`: an operand (the root, the CPU mask, the priority) first.
        "chroot" => w("", &["--userspec", "--groups"], "", 1, false),
        "taskset" => w("", NONE, "p", 1, false),
        "chrt" => w("T", NONE, "pm", 1, false),
        "unshare" => w("SGRw", NONE, "", 0, false),
        "strace" | "ltrace" => w("eopsuEaIbOPSXnlwAL", NONE, "hV", 0, false),
        // `watch -n 1 bash i.sh` runs its words as a command line.
        "watch" => w("n", &["--interval"], "hv", 0, false),
        // `script -qc 'bash i.sh' /dev/null`, `sg grp -c 'bash i.sh'`.
        "script" => Wrapper {
            string_opt: "c",
            ..w("EIOTBmo", NONE, "hV", 0, false)
        },
        "sg" => Wrapper {
            string_opt: "c",
            ..w("", NONE, "", 1, false)
        },
        // `runuser -u root -- bash i.sh`, `runuser -l root -c 'bash i.sh'`;
        // with no -u, the user is an operand, and with no command a shell
        // runs, as for su.
        "runuser" => Wrapper {
            string_opt: "c",
            ..w(
                "ugGsw",
                &[
                    "--user",
                    "--group",
                    "--supp-group",
                    "--shell",
                    "--whitelist-environment",
                ],
                "hV",
                1,
                false,
            )
        },
        _ => return None,
    })
}

/// Record what a redirection (with its target filled in) does to a simple
/// command's stdin and stdout. `pipe_kept` is set when it copies stdin to
/// another descriptor (`3<&0`), where the program can still read it.
fn apply_redirect(out: &mut Words, pipe_kept: &mut bool, r: Redirect) {
    if r.dup.as_deref() == Some("0") && !r.stdin {
        *pipe_kept = true;
    }
    if r.inline {
        out.stdin = Stdin::Inline;
    } else if r.stdin {
        match (r.dup.as_deref(), r.target) {
            // `<&0`: stdin stays the pipe.
            (Some("0"), _) => {}
            (Some(_), _) => out.stdin = Stdin::Inline,
            // `< /dev/stdin`: the pipe again.
            (None, Some(f)) if is_stdin_path(&f) => {}
            (None, target) => out.stdin = target.map_or(Stdin::Inline, Stdin::File),
        }
    } else if r.stdout {
        out.stdout.extend(r.target);
    }
}

/// Reserved words and grouping that can come before a simple command.
const KEYWORDS: &[&str] = &[
    "(", "{", "!", "if", "then", "else", "elif", "do", "while", "until",
];

/// The command a pipeline stage runs, as the shell would see it (see
/// [`Words`]).
pub fn command_words(stage: &str) -> Words {
    let mut toks = tokenize(stage);
    // Grouping: `(bash i.sh)`, `{ bash i.sh; }`, `if bash i.sh; then`.
    while let Some(first) = toks.first() {
        if first.is_empty() || KEYWORDS.contains(&first.as_str()) {
            toks.remove(0);
        } else if first.starts_with('(') {
            toks[0] = first.trim_start_matches('(').to_string();
        } else {
            break;
        }
    }
    while let Some(last) = toks.last() {
        if last == ")" || last == "}" {
            toks.pop();
        } else if last.ends_with(')') && !last.contains('(') {
            let n = toks.len() - 1;
            toks[n] = last.trim_end_matches(')').to_string();
        } else {
            break;
        }
    }
    // Redirections, wherever they are. A redirection that reads the pipe
    // itself (`< /dev/stdin`, `<&0`) leaves stdin as it was, and one that
    // copies it to another descriptor (`3<&0`) leaves it reachable: then no
    // stdin redirection counts as replacing it.
    let mut out = Words::default();
    let mut words = Vec::new();
    let mut pipe_kept = false;
    let mut it = toks.into_iter();
    while let Some(t) = it.next() {
        let Some(mut r) = redirection(&t) else {
            words.push(t);
            continue;
        };
        if r.takes_next {
            r.target = it.next();
        }
        apply_redirect(&mut out, &mut pipe_kept, r);
    }
    // Assignments and wrapper commands.
    let mut i = 0;
    // A `sudo -s`/`sudo -i`/`doas -s` seen: with no command after it, a
    // shell runs, reading its commands from stdin.
    let mut shell = false;
    loop {
        while words.get(i).is_some_and(|t| is_assignment(t)) {
            i += 1;
        }
        let Some(head) = words.get(i).map(|h| basename(h).to_ascii_lowercase()) else {
            break;
        };
        let Some(w) = wrapper(&head) else {
            break;
        };
        if head == "xargs" {
            out.xargs = Some(Stdin::Inherit);
        }
        let mut j = i + 1;
        let mut operands = w.operands;
        if head == "runuser" {
            let named = words[j..]
                .iter()
                .any(|t| t == "-u" || t == "--user" || t.starts_with("--user="));
            if named {
                operands = 0;
            } else {
                shell = true;
            }
        }
        while let Some(t) = words.get(j).cloned() {
            if t == "--" {
                j += 1;
                break;
            }
            if head == "xargs" {
                // `xargs -a f`, `xargs -af`, `xargs --arg-file=f`.
                let file = match t.as_str() {
                    "-a" | "--arg-file" => words.get(j + 1).cloned(),
                    _ => t
                        .strip_prefix("--arg-file=")
                        .or_else(|| t.strip_prefix("-a"))
                        .map(str::to_string),
                };
                if let Some(f) = file.filter(|f| !f.is_empty()) {
                    out.xargs = Some(Stdin::File(f));
                }
            }
            if head == "sudo" && matches!(t.as_str(), "--shell" | "--login") {
                shell = true;
            }
            if head == "env" && (t == "--split-string" || t.starts_with("--split-string=")) {
                // `env --split-string='bash -e' i.sh`, as `-S`.
                let (value, step) = match t.split_once('=') {
                    Some((_, v)) => (v.to_string(), 1),
                    None => (words.get(j + 1).cloned().unwrap_or_default(), 2),
                };
                let tail = words.split_off((j + step).min(words.len()));
                words.truncate(j);
                words.extend(tokenize(&value));
                words.extend(tail);
                continue;
            }
            if t.starts_with("--") {
                if !w.string_opt.is_empty() && (t == "--command" || t.starts_with("--command=")) {
                    // `flock l --command 'bash i.sh'`: a shell runs the string.
                    let value = match t.split_once('=') {
                        Some((_, v)) => v.to_string(),
                        None => words.get(j + 1).cloned().unwrap_or_default(),
                    };
                    return shell_string(out, pipe_kept, value);
                }
                let valued = !t.contains('=') && w.long_valued.contains(&t.as_str());
                j += if valued { 2 } else { 1 };
                continue;
            }
            if t.len() > 1 && t.starts_with('-') {
                let flags: Vec<char> = t[1..].chars().collect();
                let mut step = 1;
                for (k, c) in flags.iter().enumerate() {
                    if w.no_command.contains(*c) {
                        return out;
                    }
                    if w.shell_opt.contains(*c) {
                        shell = true;
                    }
                    if w.string_opt.contains(*c) {
                        let attached: String = flags[k + 1..].iter().collect();
                        let value = match attached.as_str() {
                            "" => words.get(j + 1).cloned().unwrap_or_default(),
                            _ => attached,
                        };
                        return shell_string(out, pipe_kept, value);
                    }
                    if !w.short_valued.contains(*c) {
                        continue;
                    }
                    let attached: String = flags[k + 1..].iter().collect();
                    let value = if attached.is_empty() {
                        step = 2;
                        words.get(j + 1).cloned().unwrap_or_default()
                    } else {
                        attached
                    };
                    if head == "env" && *c == 'S' {
                        // `env -S 'bash -e' i.sh`: the value is split into
                        // words, which come first.
                        let tail = words.split_off((j + step).min(words.len()));
                        words.truncate(j);
                        words.extend(tokenize(&value));
                        words.extend(tail);
                        step = 0;
                    }
                    break;
                }
                j += step;
                continue;
            }
            if t == "-" || w.assignments && is_assignment(&t) {
                j += 1;
                continue;
            }
            if operands > 0 {
                operands -= 1;
                j += 1;
                continue;
            }
            break;
        }
        i = j;
    }
    out.words = words.split_off(i.min(words.len()));
    // `sudo -s`, `sudo -i`, `doas -s` with nothing to run, and `su` with no
    // `-c`: a shell that reads its commands from stdin.
    let su_shell = out.words.first().is_some_and(|h| basename(h) == "su")
        && !out.words[1..]
            .iter()
            .any(|t| t == "-c" || t == "--command" || t.starts_with("--command="));
    if out.words.is_empty() && shell || su_shell {
        out.words = vec!["sh".to_string()];
    }
    if pipe_kept {
        out.stdin = Stdin::Inherit;
    }
    out
}

/// Does this command (as [`command_words`] gives it) copy its stdin to its
/// stdout, transformed or not: a filter given no file of its own (`cat`,
/// `cat -`, `head -n 5`, `base64 -d`, `tr -d '\r'`, `sed 's/a/b/'`), or a
/// bare `< /dev/stdin`. `$(cat)` in a stage fed from a download prints the
/// download.
pub fn passes_stdin(w: &Words) -> bool {
    if w.stdin != Stdin::Inherit {
        return false;
    }
    let Some(head) = w.words.first() else {
        return true; // `$(</dev/stdin)`, or nothing at all
    };
    // Operands other than stdin itself and option values that are numbers
    // (`head -n 5`).
    let files = w.words[1..]
        .iter()
        .filter(|a| {
            !a.starts_with('-')
                && !is_stdin_path(a)
                && !a
                    .trim_start_matches('+')
                    .chars()
                    .all(|c| c.is_ascii_digit())
        })
        .count();
    match basename(head) {
        "tr" | "tee" => true,
        "cat" | "head" | "tail" | "tac" | "rev" | "nl" | "base64" | "base32" | "gunzip"
        | "gzip" | "zcat" | "bzcat" | "bzip2" | "xz" | "xzcat" | "unxz" | "zstd" | "zstdcat"
        | "xxd" | "sort" | "uniq" | "fold" | "expand" | "iconv" => files == 0,
        // The first operand is the script or pattern.
        "sed" | "awk" | "gawk" | "mawk" | "grep" | "egrep" | "fgrep" | "cut" => files <= 1,
        "dd" => !w.words.iter().any(|a| a.starts_with("if=")),
        "openssl" => !w.words.iter().any(|a| a == "-in"),
        _ => false,
    }
}

/// A wrapper that hands `value` to a shell as a command line (`flock l -c
/// '…'`): the command is read as `sh -c '…'`.
fn shell_string(mut out: Words, pipe_kept: bool, value: String) -> Words {
    out.words = vec!["sh".to_string(), "-c".to_string(), value];
    if pipe_kept {
        out.stdin = Stdin::Inherit;
    }
    out
}

/// Interpreter families, by how they read their command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interp {
    /// sh, bash, zsh, dash, ksh, fish, the other Bourne and C shells
    /// ([`SHELLS`]), `$SHELL`, `$BASH`.
    Shell,
    Python,
    /// node and bun.
    Node,
    Deno,
    Perl,
    Ruby,
    Php,
    /// pwsh and powershell.
    Pwsh,
    /// `source` and `.`: run a file in the current shell.
    Source,
}

/// Shells, by command name (a version suffix such as `ksh93` is dropped
/// first). Each runs a script from stdin when given no script file.
pub const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh", "pdksh", "oksh", "yash", "posh",
    "rbash", "csh", "tcsh",
];

/// The interpreter family a command word names (`python3.11`, `/bin/bash`,
/// `$SHELL`, `.`), if any.
pub fn interpreter(word: &str) -> Option<Interp> {
    let w = word.to_ascii_lowercase();
    if matches!(w.as_str(), "$shell" | "${shell}" | "$bash" | "${bash}") {
        return Some(Interp::Shell);
    }
    let base = basename(&w);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    if base == "." || base == "source" {
        return Some(Interp::Source);
    }
    let name = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if SHELLS.contains(&name) {
        return Some(Interp::Shell);
    }
    Some(match name {
        "python" => Interp::Python,
        "node" | "bun" => Interp::Node,
        "deno" => Interp::Deno,
        "perl" => Interp::Perl,
        "ruby" => Interp::Ruby,
        "php" => Interp::Php,
        "pwsh" | "powershell" => Interp::Pwsh,
        _ => return None,
    })
}

/// What an interpreter invocation runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runs {
    /// A script file (`bash i.sh`, `python3 -X dev i.py`, `. ./i.sh`).
    File(String),
    /// Its stdin (`bash`, `sh -s`, `python3 -`).
    Stdin,
    /// Code on the command line (`bash -c`, `python3 -m`, `node -e`).
    Inline,
}

/// PowerShell options that take a value (lowercase).
const PWSH_VALUED: &[&str] = &[
    "-ex",
    "-ep",
    "-executionpolicy",
    "-w",
    "-windowstyle",
    "-wd",
    "-workingdirectory",
    "-o",
    "-of",
    "-outputformat",
    "-if",
    "-inputformat",
    "-config",
    "-configurationname",
    "-v",
    "-version",
    "-settingsfile",
    "-psconsolefile",
    "-custompipename",
    "-configurationfile",
];

/// What `words` (a command as [`command_words`] gives it) runs when its
/// command word is an interpreter; `None` when it is not one. Options are
/// read per interpreter family: `bash -e i.sh` runs i.sh (`-e` is errexit),
/// `python3 -X dev i.py` and `bash -O extglob i.sh` run the file (`-X` and
/// `-O` take a value), `bash -c '…'` and `python3 -m x` run inline code.
/// A script file that is the process's own stdin (`bash /dev/stdin`,
/// `. /dev/stdin`, `pwsh -File -`) runs the pipe.
pub fn interpreter_runs(words: &[String]) -> Option<Runs> {
    match runs_as_written(words)? {
        Runs::File(f) if f == "-" || is_stdin_path(&f) => Some(Runs::Stdin),
        r => Some(r),
    }
}

fn runs_as_written(words: &[String]) -> Option<Runs> {
    let kind = interpreter(words.first()?)?;
    let mut args = &words[1..];
    if kind == Interp::Source {
        return Some(args.first().map_or(Runs::Stdin, |f| Runs::File(f.clone())));
    }
    // deno and bun take a subcommand; `deno eval` is inline code.
    if matches!(kind, Interp::Deno | Interp::Node) {
        match args.first().map(String::as_str) {
            Some("run") => args = &args[1..],
            Some("eval") if kind == Interp::Deno => return Some(Runs::Inline),
            _ => {}
        }
    }
    // Option characters that mean inline code; that take a value (attached,
    // or else the next word); that take an attached value only; and long
    // options that take the next word as a value.
    let (inline, valued, attached, long_valued): (&str, &str, &str, &[&str]) = match kind {
        Interp::Shell => ("c", "oO", "", &["--rcfile", "--init-file"]),
        Interp::Python => ("cm", "WX", "", &["--check-hash-based-pycs"]),
        Interp::Node => (
            "ep",
            "rC",
            "",
            &[
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "--conditions",
                "--env-file",
            ],
        ),
        Interp::Deno => (
            "",
            "cL",
            "",
            &[
                "--config",
                "--import-map",
                "--lock",
                "--cert",
                "--location",
                "--seed",
                "--log-level",
            ],
        ),
        // perl reads `-I lib` as -I with its value (and the program from
        // stdin); -M, -m, -x, -l and the rest take theirs attached.
        Interp::Perl => ("eE", "I", "MmxFil0d", &[]),
        Interp::Ruby => ("e", "rICE", "xFi0", &[]),
        Interp::Php => ("rRBE", "cdzt", "", &[]),
        Interp::Pwsh | Interp::Source => ("", "", "", &[]),
    };
    let mut i = 0;
    while let Some(t) = args.get(i) {
        let t = t.as_str();
        if t == "-" {
            return Some(Runs::Stdin);
        }
        if t == "--" {
            return Some(
                args.get(i + 1)
                    .map_or(Runs::Stdin, |f| Runs::File(f.clone())),
            );
        }
        let plus = kind == Interp::Shell && t.starts_with('+');
        if !t.starts_with('-') && !plus {
            return Some(Runs::File(t.to_string()));
        }
        if kind == Interp::Pwsh {
            let l = t.to_ascii_lowercase();
            match l.as_str() {
                // `-Command -` reads the commands from stdin (read the same
                // way for the encoded-command options).
                "-c" | "-command" | "-e" | "-ec" | "-encodedcommand"
                    if args.get(i + 1).map(String::as_str) == Some("-") =>
                {
                    return Some(Runs::Stdin)
                }
                "-c" | "-command" | "-e" | "-ec" | "-enc" | "-encodedcommand" | "-cwa"
                | "-commandwithargs" => return Some(Runs::Inline),
                "-f" | "-file" => return args.get(i + 1).map(|f| Runs::File(f.clone())),
                _ => {
                    i += if PWSH_VALUED.contains(&l.as_str()) {
                        2
                    } else {
                        1
                    }
                }
            }
            continue;
        }
        if t.starts_with("--") {
            if kind == Interp::Node && matches!(t, "--eval" | "--print") {
                return Some(Runs::Inline);
            }
            i += if !t.contains('=') && long_valued.contains(&t) {
                2
            } else {
                1
            };
            continue;
        }
        let bundle: Vec<char> = t[1..].chars().collect();
        let mut step = 1;
        for (k, c) in bundle.iter().enumerate() {
            if inline.contains(*c) {
                return Some(Runs::Inline);
            }
            if kind == Interp::Shell && *c == 's' {
                // -s: commands come from stdin; the words after it are the
                // script's arguments.
                return Some(Runs::Stdin);
            }
            if kind == Interp::Php && *c == 'f' {
                return match bundle[k + 1..].iter().collect::<String>() {
                    f if !f.is_empty() => Some(Runs::File(f)),
                    _ => args.get(i + 1).map(|f| Runs::File(f.clone())),
                };
            }
            if valued.contains(*c) {
                if k + 1 == bundle.len() {
                    step = 2;
                }
                break;
            }
            if attached.contains(*c) {
                break;
            }
        }
        i += step;
    }
    Some(Runs::Stdin)
}

/// Where a pipeline stage's text ends: the first `|`, `;`, `)`, quote,
/// backtick or newline, or an `&` that is not part of a redirection
/// (`2>&1`, `&>f`, `<&3`).
fn stage_end(tail: &str) -> usize {
    let b = tail.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'|' | b';' | b')' | b'\'' | b'"' | b'`' | b'\n' => return i,
            b'&' => {
                let prev = i.checked_sub(1).map(|p| b[p]);
                if !matches!(prev, Some(b'>' | b'<')) && b.get(i + 1) != Some(&b'>') {
                    return i;
                }
            }
            _ => {}
        }
    }
    tail.len()
}

/// Does an interpreter at the end of a pipe run what it reads on stdin?
///
/// `curl … | python3` does; `curl … | python3 -m json.tool`,
/// `curl … | python3 -c '…'`, `curl … | node script.js`,
/// `curl … | bash -c 'jq …'` and `curl … | bash < other.sh` read the
/// download as *data* or not at all. `rest` is the text after the
/// interpreter word up to the end of its pipeline stage (so it has no
/// quotes). Output redirections (`>/dev/null`, `2>&1`) and a `# comment`
/// change nothing; a redirection of stdin (`< x.sh`, `<<'EOF'`) means the
/// download is not what runs, unless it reads the pipe itself
/// (`< /dev/stdin`, `<&0`) or the pipe is copied to another descriptor
/// (`3<&0`). Redirections and comments are read from the words as written
/// (`\#` and `\<` are ordinary characters); options after backslash
/// removal (`\-s` is `-s`), per interpreter as [`interpreter_runs`] reads
/// them (`node -r x` loads a module and still runs stdin; a script named
/// `/dev/stdin` is the pipe).
fn executes_stdin(interp: &str, rest: &str) -> bool {
    let interp = interp.to_ascii_lowercase();
    if matches!(interp.as_str(), "iex" | "invoke-expression") {
        return true;
    }
    let mut raw: Vec<&str> = rest.split_whitespace().collect();
    if let Some(c) = raw.iter().position(|w| w.starts_with('#')) {
        raw.truncate(c); // a comment
    }
    let mut stage = Words::default();
    let mut pipe_kept = false;
    let mut words = vec![interp];
    let mut it = raw.into_iter();
    while let Some(w) = it.next() {
        match redirection(w) {
            Some(mut r) => {
                if r.takes_next {
                    r.target = it.next().map(str::to_string);
                }
                apply_redirect(&mut stage, &mut pipe_kept, r);
            }
            None => words.push(tokenize(w).into_iter().next().unwrap_or_default()),
        }
    }
    if stage.stdin != Stdin::Inherit && !pipe_kept {
        return false; // stdin is a file or text, not the download
    }
    interpreter_runs(&words) == Some(Runs::Stdin)
}

/// A download piped or substituted into an interpreter:
/// `curl … | sh`, `wget -qO- … | python3`, `bash <(curl …)`,
// sigil:ignore-next-line NET-RCE-001 -- doc comment listing the download-to-interpreter shapes this function detects
/// `sh -c "$(curl …)"`, `eval "$(wget …)"`, `iwr … | iex`, `iex (irm …)`.
/// An interpreter that treats the download as data (`| python3 -m
/// json.tool`, `| node script.js`) does not count. The command is also
/// read with word-internal quoting removed ([`dequote`]), so `| "bash"`
/// and `| b''ash` are bash.
pub fn pipes_download_to_interpreter(s: &str) -> bool {
    let dq = dequote(s);
    pipes_to_interpreter(s) || dq != s && pipes_to_interpreter(&dq)
}

fn pipes_to_interpreter(s: &str) -> bool {
    static PIPE: OnceLock<Regex> = OnceLock::new();
    static SUBST: OnceLock<Regex> = OnceLock::new();
    static PS: OnceLock<Regex> = OnceLock::new();
    const DL: &str = r"(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)";
    // The shells of `SHELLS`, with a version suffix (`ksh93`), and the
    // other interpreters.
    const INTERP: &str = r"((sh|bash|zsh|dash|ksh|fish|ash|mksh|pdksh|oksh|yash|posh|rbash|csh|tcsh)[0-9.]*|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell|\$shell|\$\{shell\}|\$bash|\$\{bash\})";
    // A stage's arguments: anything up to a pipe or list operator, where
    // `2>&1`, `&>f` and `<&3` are redirections rather than `&`.
    const ARGS: &str = r"(\s([^|;&]|>&|&>|<&)*)?";
    // Commands that run the next word as the command (`sudo -u root`,
    // `env -i`, `command`, `doas`, `busybox`, `timeout 60`, ...).
    // `VAR=value` words before the command (`| INSTALL_DIR=~/bin bash`).
    const WRAP: &str = r"([A-Za-z_][A-Za-z0-9_]*=\S*\s+|(\S*/)?(sudo|doas|env|command|builtin|exec|nohup|time|nice|timeout|stdbuf|setsid|ionice|busybox)(\s+(-\S+(\s+[^-\s|;&<>]\S*)?|[A-Za-z0-9_]+=\S*|[0-9.]+[smhd]?))*\s+)";
    // The end of a group or compound command the download is in, with the
    // commands after the download in it: `{ curl …; }`, `(curl …; true)`,
    // `{ curl … && echo; }`, `if …; then curl …; fi`, `for …; do curl …;
    // done`. Its output is what the pipe after it carries.
    let group = format!(
        r"((\s*(;|&&|\|\|?|\n)[^;&|\n]*?)*?\s*;?\s*([}})]|(^|[\s;&|])(fi|done|esac)){ARGS})*"
    );
    let pipe = re(
        &PIPE,
        &format!(
            // `| tee file |` stages in between still hand the interpreter
            // the download; `|&` pipes stderr as well. A group the download
            // is in (`{ curl …; } | sh`, `(curl …; true) | sh`) pipes its
            // output.
            r#"(?i)(^|[\s;&|("'`$])(\S*/)?{DL}{ARGS}{group}(\|&?\s*({WRAP})*(\S*/)?tee{ARGS})*\|&?\s*({WRAP})*(\S*/)?(?P<interp>{INTERP})([\s"')`;&|<>]|$)"#
        ),
    );
    let subst = re(
        &SUBST,
        &format!(
            // `bash < <(curl …)` and `bash <<< "$(curl …)"` feed stdin.
            r#"(?i)(^|[\s;&|("'`])((\S*/)?{INTERP}\s+(-\S+\s+)*(<<<\s*|<\s*)?|source\s+|\.\s+|eval\s+)["']?(<\(|\$\(|`)\s*(\S*/)?{DL}\s"#
        ),
    );
    let ps = re(
        &PS,
        r#"(?i)(iex|invoke-expression)\s*\(?\s*(\(|\$\()?\s*(iwr|irm|invoke-webrequest|invoke-restmethod|\(?new-object\s+(system\.)?net\.webclient)"#,
    );
    let piped = pipe.captures_iter(s).any(|c| {
        let Some(m) = c.name("interp") else {
            return false;
        };
        let tail = &s[m.end()..];
        executes_stdin(m.as_str(), &tail[..stage_end(tail)])
    });
    piped || subst.is_match(s) || ps.is_match(s)
}

/// The first http(s) URL in `s`, for quoting an exact `sigil scan <url>`.
pub fn first_url(s: &str) -> Option<String> {
    static URL: OnceLock<Regex> = OnceLock::new();
    re(&URL, r#"https?://[^\s'"|;&)<>`]+"#)
        .find(s)
        .map(|m| m.as_str().to_string())
}

/// A command that sends data to another host: an HTTP request with a body,
/// a raw socket, or `/dev/tcp`.
pub fn sends_off_machine(s: &str) -> bool {
    static SEND: OnceLock<Regex> = OnceLock::new();
    re(
        &SEND,
        r#"(?i)(\bcurl\b[^|;&]*\s(-d|--data[\w-]*|-F|--form[\w-]*|-T|--upload-file|--json|-X\s*(POST|PUT|PATCH)|--request[\s=]+(POST|PUT|PATCH))([\s=@]|$))|(\bwget\b[^|;&]*--(post-data|post-file|body-data|body-file|method[\s=]+(POST|PUT)))|((^|[\s;&|(])(nc|ncat|netcat|socat)\s+\S)|(/dev/(tcp|udp)/)|(invoke-(webrequest|restmethod)[^|;&]*-method\s+(post|put))"#,
    )
    .is_match(s)
}

/// A network send whose body is the command's own stdin: for a hook, that is
/// the whole event payload — tool inputs, file contents, prompts.
pub fn forwards_stdin(s: &str) -> bool {
    static STDIN: OnceLock<Regex> = OnceLock::new();
    re(
        &STDIN,
        r#"(?i)(\bcurl\b[^|;&]*(@-|@/dev/stdin|-T\s*-(\s|$)))|(\|\s*(nc|ncat|netcat|socat)\b)|(\bcurl\b[^|;&]*\$\(\s*cat\s*\))"#,
    )
    .is_match(s)
}

/// References to credential stores a hook or server has no business reading.
pub fn touches_credentials(s: &str) -> bool {
    static CRED: OnceLock<Regex> = OnceLock::new();
    re(
        &CRED,
        // sigil:ignore-next-line CRED-003 -- detection pattern for credential paths, not an access
        r#"(?i)(\.ssh/|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials|security\s+find-(generic|internet)-password|/login data\b|keychain)"#,
    )
    .is_match(s)
}

/// Package ecosystems a runner fetches from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

/// A package runner invocation: `npx -y pkg`, `uvx pkg`, `pnpm dlx pkg`, ...
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runner {
    /// The runner as typed (`npx`, `pnpm dlx`, `uvx`, ...).
    pub tool: String,
    pub ecosystem: Ecosystem,
    /// The package spec as given (`@scope/pkg@1.2.3`, `ruff==0.4.0`).
    pub spec: String,
    /// The bare package name, for `sigil npm <name>` / `sigil pip <name>`.
    pub name: String,
    /// An exact version is pinned.
    pub pinned: bool,
    /// `-y`/`--yes` (or a runner that never asks).
    pub auto_yes: bool,
}

impl Runner {
    /// The package spec as `sigil npm` / `sigil pip` takes it (`ruff@0.4.0`
    /// in uvx syntax is `ruff==0.4.0` to pip).
    pub fn vet_target(&self) -> String {
        match self.ecosystem {
            Ecosystem::Npm => self.spec.clone(),
            Ecosystem::Pypi => self.spec.replace('@', "=="),
        }
    }

    /// The sigil command that vets this package before it runs.
    pub fn sigil_alternative(&self) -> String {
        match self.ecosystem {
            Ecosystem::Npm => format!("sigil npm {}", self.vet_target()),
            Ecosystem::Pypi => format!("sigil pip {}", self.vet_target()),
        }
    }
}

fn basename(t: &str) -> &str {
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

/// Split an npm spec into (name, version-or-tag).
fn npm_split(spec: &str) -> (String, Option<String>) {
    let (scope_at, rest) = if let Some(r) = spec.strip_prefix('@') {
        ("@", r)
    } else {
        ("", spec)
    };
    match rest.split_once('@') {
        Some((n, v)) => (format!("{scope_at}{n}"), Some(v.to_string())),
        None => (spec.to_string(), None),
    }
}

fn exact_version(v: &str) -> bool {
    let v = v.trim_start_matches('v').trim_start_matches('=');
    let mut parts = v.split('.');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            !digits.is_empty()
        })
    };
    ok(parts.next()) && ok(parts.next()) && ok(parts.next())
}

fn local_spec(spec: &str) -> bool {
    spec.starts_with('.')
        || spec.starts_with('/')
        || spec.starts_with('~')
        || spec.starts_with("file:")
        || spec.ends_with(".tgz") && !spec.contains("://")
}

/// Recognise a package runner at the start of `tokens` (after any env
/// assignments or `sudo`). Local paths (`npx ./tool`, `uvx --from .`) are
/// not runners of remote code and return `None`.
pub fn parse_runner(tokens: &[String]) -> Option<Runner> {
    let mut i = 0;
    while i < tokens.len()
        && (tokens[i].contains('=') && !tokens[i].starts_with('-')
            || tokens[i] == "sudo"
            || tokens[i] == "env"
            || tokens[i] == "exec"
            || tokens[i] == "command")
    {
        i += 1;
    }
    let head = basename(tokens.get(i)?).to_ascii_lowercase();
    let head = head.trim_end_matches(".cmd").trim_end_matches(".exe");
    let next = tokens.get(i + 1).map(String::as_str);
    let (tool, eco, start) = match (head, next) {
        ("npx", _) => ("npx".to_string(), Ecosystem::Npm, i + 1),
        ("bunx", _) => ("bunx".to_string(), Ecosystem::Npm, i + 1),
        ("bun", Some("x")) => ("bun x".to_string(), Ecosystem::Npm, i + 2),
        ("pnpm", Some("dlx")) => ("pnpm dlx".to_string(), Ecosystem::Npm, i + 2),
        ("yarn", Some("dlx")) => ("yarn dlx".to_string(), Ecosystem::Npm, i + 2),
        ("npm", Some("exec" | "x")) => ("npm exec".to_string(), Ecosystem::Npm, i + 2),
        ("uvx", _) => ("uvx".to_string(), Ecosystem::Pypi, i + 1),
        ("uv", Some("tool")) if tokens.get(i + 2).map(String::as_str) == Some("run") => {
            ("uv tool run".to_string(), Ecosystem::Pypi, i + 3)
        }
        ("pipx", Some("run")) => ("pipx run".to_string(), Ecosystem::Pypi, i + 2),
        _ => return None,
    };

    // Flags whose next token is a value, per runner family.
    let npm_valued = [
        "-p",
        "--package",
        "-c",
        "--call",
        "--registry",
        "-w",
        "--workspace",
        "--cache",
        "--userconfig",
    ];
    let py_valued = [
        "--from",
        "--with",
        "--python",
        "-p",
        "--index-url",
        "--extra-index-url",
        "--index",
        "--default-index",
        "--spec",
        "--pip-args",
        "--with-requirements",
        "--constraints",
    ];
    let mut auto_yes = matches!(tool.as_str(), "pnpm dlx" | "yarn dlx" | "bunx" | "bun x");
    if eco == Ecosystem::Pypi {
        auto_yes = true; // uvx and pipx never ask
    }
    let mut explicit: Option<String> = None;
    let mut positional: Option<String> = None;
    let mut j = start;
    while j < tokens.len() {
        let t = tokens[j].as_str();
        if t == "--" {
            if positional.is_none() {
                positional = tokens.get(j + 1).cloned();
            }
            break;
        }
        if t == "-y" || t == "--yes" {
            auto_yes = true;
            j += 1;
            continue;
        }
        if let Some((flag, val)) = t.split_once('=').filter(|_| t.starts_with('-')) {
            if matches!(flag, "--package" | "--from" | "--spec") {
                explicit = Some(val.to_string());
            }
            j += 1;
            continue;
        }
        if t.starts_with('-') {
            let valued = match eco {
                Ecosystem::Npm => npm_valued.contains(&t),
                Ecosystem::Pypi => py_valued.contains(&t),
            };
            if valued {
                if matches!(t, "-p" | "--package") && eco == Ecosystem::Npm
                    || matches!(t, "--from" | "--spec")
                {
                    explicit = tokens.get(j + 1).cloned();
                }
                j += 2;
            } else {
                j += 1;
            }
            continue;
        }
        positional = Some(t.to_string());
        break;
    }
    let spec = explicit.or(positional)?;
    if local_spec(&spec) {
        return None;
    }
    let (name, pinned) = match eco {
        Ecosystem::Npm => {
            if spec.contains("://") || spec.contains(':') && !spec.starts_with('@') {
                // git+https://, github:user/repo, a tarball URL
                (spec.clone(), false)
            } else {
                let (n, v) = npm_split(&spec);
                let pinned = v.as_deref().is_some_and(exact_version);
                (n, pinned)
            }
        }
        Ecosystem::Pypi => {
            if spec.contains("://") {
                (spec.clone(), false)
            } else if let Some((n, v)) = spec.split_once("==") {
                (n.to_string(), exact_version(v))
            } else if let Some((n, v)) = spec.split_once('@') {
                (n.to_string(), exact_version(v))
            } else {
                let n = spec
                    .split(|c: char| "[<>=!~; ".contains(c))
                    .next()
                    .unwrap_or(&spec);
                (n.to_string(), false)
            }
        }
    };
    Some(Runner {
        tool,
        ecosystem: eco,
        spec,
        name,
        pinned,
        auto_yes,
    })
}

/// What a `docker|podman|nerdctl run` hands the container of the host.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ContainerRisk {
    /// Flags that give the container the host: `--privileged`, dangerous
    /// capabilities, host PID/user/IPC namespaces, unconfined profiles,
    /// and mounts of `/`, a home directory, `/etc`, the Docker socket or a
    /// credential directory.
    pub escapes: Vec<String>,
    /// `--network host`: reaches every local-only service.
    pub host_network: bool,
}

/// `None` unless `parts` is a container run.
pub fn container_risk(parts: &[String]) -> Option<ContainerRisk> {
    let head = parts
        .first()
        .map(|h| basename(h).to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(head.as_str(), "docker" | "podman" | "nerdctl")
        || !parts.iter().any(|p| p == "run")
    {
        return None;
    }
    const SENSITIVE: &[&str] = &[
        ".ssh",
        ".aws",
        ".kube",
        ".gnupg",
        ".docker",
        ".config/gcloud",
        ".azure",
        ".netrc",
    ];
    let host_root = |src: &str| {
        let s = src.trim_end_matches('/');
        s.is_empty()
            || matches!(
                s,
                "~" | "$HOME" | "${HOME}" | "/root" | "/etc" | "/home" | "/Users"
            )
            || s.ends_with("docker.sock")
            || (s.starts_with("/home/") || s.starts_with("/Users/")) && s.matches('/').count() == 2
            || SENSITIVE
                .iter()
                .any(|d| s.ends_with(d) || s.contains(&format!("{d}/")))
    };
    let mut risk = ContainerRisk::default();
    for (i, p) in parts.iter().enumerate() {
        let (flag, val) = match p.split_once('=') {
            Some((f, v)) if f.starts_with('-') => (f, Some(v.to_string())),
            _ => (p.as_str(), parts.get(i + 1).cloned()),
        };
        match flag {
            "--privileged" => risk.escapes.push("--privileged".into()),
            "--cap-add" => {
                if let Some(v) = &val {
                    let u = v.to_ascii_uppercase();
                    if [
                        "ALL",
                        "SYS_ADMIN",
                        "SYS_PTRACE",
                        "SYS_MODULE",
                        "DAC_READ_SEARCH",
                    ]
                    .iter()
                    .any(|c| u.contains(c))
                    {
                        risk.escapes.push(format!("--cap-add {v}"));
                    }
                }
            }
            "--pid" | "--userns" | "--ipc" | "--uts" if val.as_deref() == Some("host") => {
                risk.escapes.push(format!("{flag}=host"))
            }
            "--security-opt" if val.as_deref().is_some_and(|v| v.contains("unconfined")) => risk
                .escapes
                .push(format!("--security-opt {}", val.unwrap_or_default())),
            "-v" | "--volume" => {
                if let Some(v) = &val {
                    if host_root(v.split(':').next().unwrap_or("")) {
                        risk.escapes.push(format!("-v {v}"));
                    }
                }
            }
            "--mount" => {
                if let Some(v) = &val {
                    let src = v
                        .split(',')
                        .find_map(|kv| {
                            kv.strip_prefix("source=")
                                .or_else(|| kv.strip_prefix("src="))
                        })
                        .unwrap_or("-");
                    if host_root(src) {
                        risk.escapes.push(format!("--mount {v}"));
                    }
                }
            }
            "--network" | "--net" if val.as_deref() == Some("host") => risk.host_network = true,
            _ => {}
        }
    }
    Some(risk)
}

/// Tunnel, request-capture and paste services: legitimate for debugging,
/// and the standard infrastructure for exfiltration and throwaway C2.
pub fn capture_host(host: &str) -> bool {
    const HOSTS: &[&str] = &[
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "ngrok.dev",
        "trycloudflare.com",
        "webhook.site",
        "pipedream.net",
        "requestbin.com",
        "requestbin.net",
        "beeceptor.com",
        "hookbin.com",
        "burpcollaborator.net",
        "oastify.com",
        "interact.sh",
        "oast.fun",
        "oast.me",
        "oast.pro",
        "oast.site",
        "oast.online",
        "oast.live",
        "serveo.net",
        "loca.lt",
        "localtunnel.me",
        "localhost.run",
        "pastebin.com",
        "transfer.sh",
        "bore.pub",
    ];
    let h = host.to_ascii_lowercase();
    HOSTS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

#[cfg(test)]
#[path = "cmdline_tests.rs"]
mod tests;
