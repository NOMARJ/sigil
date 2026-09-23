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

/// Does an interpreter at the end of a pipe run what it reads on stdin?
///
/// `curl … | python3` does; `curl … | python3 -m json.tool`,
/// `curl … | python3 -c '…'`, `curl … | node script.js` and
/// `curl … | bash -c 'jq …'` read stdin as *data*. `rest` is the text after
/// the interpreter word up to the end of its pipeline stage.
fn executes_stdin(interp: &str, rest: &str) -> bool {
    let interp = interp.to_ascii_lowercase();
    if matches!(interp.as_str(), "iex" | "invoke-expression") {
        return true;
    }
    let shell = matches!(
        interp.as_str(),
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish"
    );
    let pwsh = matches!(interp.as_str(), "pwsh" | "powershell");
    let toks = tokenize(rest);
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i].as_str();
        let lower = t.to_ascii_lowercase();
        if t == "--" || t == "-" {
            // Options end; what follows is passed to the stdin program.
            return true;
        }
        if pwsh {
            if matches!(
                lower.as_str(),
                "-c" | "-command" | "-f" | "-file" | "-encodedcommand" | "-e" | "-ec"
            ) {
                return toks.get(i + 1).map(String::as_str) == Some("-");
            }
        } else if shell {
            if t.starts_with('-') && !t.starts_with("--") && t.contains('c') {
                return false; // -c 'string': stdin is data for that string
            }
            if t == "-o" || t == "+o" {
                i += 2;
                continue;
            }
        } else if t.starts_with('-') && !t.starts_with("--") {
            // python -c/-m, node -e/-p, perl -e/-n/-p, ruby -e, php -r
            if t[1..]
                .chars()
                .any(|c| matches!(c, 'c' | 'm' | 'e' | 'p' | 'n' | 'r' | 'E'))
            {
                return false;
            }
            if matches!(t, "-W" | "-X") {
                i += 2;
                continue;
            }
        } else if matches!(lower.as_str(), "--eval" | "--print" | "--module") {
            return false;
        }
        if !t.starts_with('-') && !t.starts_with('+') {
            return false; // a script file: stdin is its input
        }
        i += 1;
    }
    true
}

/// A download piped or substituted into an interpreter:
/// `curl … | sh`, `wget -qO- … | python3`, `bash <(curl …)`,
/// `sh -c "$(curl …)"`, `eval "$(wget …)"`, `iwr … | iex`, `iex (irm …)`.
/// An interpreter that treats the download as data (`| python3 -m
/// json.tool`, `| node script.js`) does not count.
pub fn pipes_download_to_interpreter(s: &str) -> bool {
    static PIPE: OnceLock<Regex> = OnceLock::new();
    static SUBST: OnceLock<Regex> = OnceLock::new();
    static PS: OnceLock<Regex> = OnceLock::new();
    const DL: &str = r"(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)";
    const INTERP: &str = r"(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell)";
    let pipe = re(
        &PIPE,
        &format!(
            r#"(?i)(^|[\s;&|("'`$])(\S*/)?{DL}(\s[^|;&]*)?\|\s*(sudo(\s+-\S+)*\s+)?(env(\s+\w+=\S*)*\s+)?(\S*/)?(?P<interp>sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell)([\s"')]|$)"#
        ),
    );
    let subst = re(
        &SUBST,
        &format!(
            r#"(?i)(^|[\s;&|("'`])((\S*/)?{INTERP}\s+(-\S+\s+)*|source\s+|\.\s+|eval\s+)["']?(<\(|\$\(|`)\s*(\S*/)?{DL}\s"#
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
        let end = tail
            .find(['|', ';', '&', ')', '\'', '"', '`', '\n'])
            .unwrap_or(tail.len());
        executes_stdin(m.as_str(), &tail[..end])
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
