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
//! with a harmless sigil call does not launder it.
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
use std::io::Read;
use std::path::PathBuf;
use std::sync::OnceLock;

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

fn has(cmd: &str, pattern: &str) -> bool {
    // Patterns are static and known-valid; a compile failure is a bug, and
    // failing open here matches the shell guard's fail-open posture.
    Regex::new(pattern)
        .map(|re| re.is_match(cmd))
        .unwrap_or(false)
}

/// Where a pattern first matches, for re-tokenising from the command word.
fn find_at(cmd: &str, pattern: &str) -> Option<usize> {
    let re = Regex::new(pattern).ok()?;
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
}

/// Split a command line into list segments on `;`, `&&`, `||`, `&`,
/// newlines and command/process substitution, recording the operator in
/// front of each. Quotes are not honoured: a separator inside quotes only
/// makes the pieces smaller, and every piece is still judged.
fn segments(cmd: &str) -> Vec<(Op, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut op = Op::Start;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    let push = |out: &mut Vec<(Op, String)>, cur: &mut String, op: Op| {
        out.push((op, std::mem::take(cur)));
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev = if i > 0 { Some(chars[i - 1]) } else { None };
        match (c, next) {
            ('&', Some('&')) => {
                push(&mut out, &mut cur, op);
                op = Op::And;
                i += 2;
            }
            ('|', Some('|')) => {
                push(&mut out, &mut cur, op);
                op = Op::Other;
                i += 2;
            }
            // `2>&1`, `&>file`, `>&2` are redirections, not background.
            ('&', n) if prev != Some('>') && n != Some('>') => {
                push(&mut out, &mut cur, op);
                op = Op::Other;
                i += 1;
            }
            (';', _) | ('\n', _) | ('`', _) => {
                push(&mut out, &mut cur, op);
                op = Op::Other;
                i += 1;
            }
            ('$', Some('(')) | ('<', Some('(')) | ('>', Some('(')) => {
                push(&mut out, &mut cur, op);
                op = Op::Other;
                i += 2;
            }
            _ => {
                cur.push(c);
                i += 1;
            }
        }
    }
    push(&mut out, &mut cur, op);
    out
}

/// Pipeline stages of one segment.
fn stages(seg: &str) -> Vec<&str> {
    seg.split('|').collect()
}

fn is_sigil(stage: &str) -> bool {
    has(
        stage,
        r"^\s*(\w+=\S*\s+)*(sudo(\s+-\S+)*\s+)?(\S*/)?sigil(\.exe)?(\s|$)",
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
/// `.` components and trailing slashes dropped.
fn canon_path(t: &str, ctx: &Context) -> String {
    expand(unquote(t), ctx)
        .components()
        .filter(|c| *c != std::path::Component::CurDir)
        .collect::<PathBuf>()
        .to_string_lossy()
        .to_string()
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
    const VALUED: &[&str] = &[
        "-f",
        "--format",
        "-p",
        "--phases",
        "-s",
        "--severity",
        "--fail-on",
        "-b",
        "--branch",
        "--baseline",
        "-o",
        "--output",
        "--policy",
        "--rules",
        "--config",
    ];
    let mut names = Vec::new();
    // `sigil pip ruff -V 0.4.0` vets ruff==0.4.0, not whatever `ruff`
    // resolves to later.
    let mut version: Option<String> = None;
    // `sigil clone <url> -b dev` vets the dev branch, not the default one.
    let mut branch: Option<String> = None;
    let mut it = toks[i + 2..].iter();
    while let Some(t) = it.next() {
        if t == "-V" || t == "--version" {
            version = it.next().cloned();
        } else if let Some(v) = t.strip_prefix("--version=") {
            version = Some(v.to_string());
        } else if t == "-b" || t == "--branch" {
            branch = it.next().cloned();
        } else if VALUED.contains(&t.as_str()) {
            it.next();
        } else if !t.starts_with('-') {
            names.push(unquote(t).to_string());
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
    if let Some(r) = find_at(stage, RUNNER_PAT)
        .and_then(|i| cmdline::parse_runner(&cmdline::tokenize(&stage[i..])))
    {
        return vec![runner_target(&r)];
    }
    if let Some(m) = deno_module(stage) {
        // A URL module is fetched at run time: nothing can vet it by name.
        return vec![match m.strip_prefix("npm:") {
            Some(spec) => Target::Npm(spec.to_string()),
            None => Target::Unvettable,
        }];
    }
    let mut toks = cmdline::tokenize(stage);
    while toks
        .first()
        .is_some_and(|t| t == "sudo" || (t.contains('=') && !t.starts_with('-')))
    {
        toks.remove(0);
    }
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
            let i = toks.iter().position(|t| t == "clone").unwrap_or(toks.len());
            let mut branch = None;
            let mut url = None;
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
                } else if !t.starts_with('-') && url.is_none() {
                    url = Some(t.clone());
                }
            }
            url.map(|u| {
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

fn expand(path: &str, ctx: &Context) -> PathBuf {
    let p = path.trim_matches(['"', '\'']);
    let home = ctx.home.clone();
    for pre in ["~/", "$HOME/", "${HOME}/"] {
        if let (Some(r), Some(h)) = (p.strip_prefix(pre), &home) {
            return h.join(r);
        }
    }
    if p == "~" {
        if let Some(h) = home {
            return h;
        }
    }
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        return pb;
    }
    match &ctx.cwd {
        Some(c) => c.join(pb),
        None => pb,
    }
}

/// `cd dir` / `pushd dir`: where later segments run.
fn cd_target(seg: &str, ctx: &Context) -> Option<Option<PathBuf>> {
    let toks = cmdline::tokenize(seg);
    if !matches!(toks.first().map(String::as_str), Some("cd" | "pushd")) || toks.len() > 2 {
        return None;
    }
    Some(match toks.get(1) {
        None => ctx.home.clone(),
        Some(d) => Some(expand(d, ctx)),
    })
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
        Regex::new(&format!(
            r"(^|/)(({})(/|$)|({})$)",
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

/// Remote package runners: fetch-and-execute in one step.
fn runner(stage: &str, ctx: &Context) -> Option<Decision> {
    let at = find_at(stage, RUNNER_PAT)?;
    let toks = cmdline::tokenize(&stage[at..]);
    let r = cmdline::parse_runner(&toks)?;
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
    let mut toks = cmdline::tokenize(stage);
    while toks
        .first()
        .is_some_and(|t| t == "sudo" || (t.contains('=') && !t.starts_with('-')))
    {
        toks.remove(0);
    }
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
            let mut dest: Option<String> = None;
            let mut remote_name = head == "wget";
            let mut it = toks.iter().skip(1).peekable();
            while let Some(t) = it.next() {
                let t = t.as_str();
                match t {
                    "-o" | "--output" | "-O" if head == "wget" && t == "-O" => {
                        dest = it.next().cloned();
                    }
                    "-o" | "--output" => dest = it.next().cloned(),
                    "--output-document" => dest = it.next().cloned(),
                    "--output-dir" | "-P" | "--directory-prefix" => {
                        dest = it.next().cloned();
                        remote_name = true;
                    }
                    "-O" | "--remote-name" => remote_name = true,
                    _ if t.starts_with("--output-document=")
                        || t.starts_with("--directory-prefix=") =>
                    {
                        dest = t.split_once('=').map(|(_, v)| v.to_string());
                    }
                    _ if head == "curl" && t.starts_with('-') && !t.starts_with("--") => {
                        if t.ends_with('o') {
                            dest = it.next().cloned();
                        } else if t.contains('O') {
                            remote_name = true;
                        }
                    }
                    _ => {}
                }
            }
            // The flag parse above, or the saved file as `download_file`
            // resolves it (which also follows `> file` redirects).
            let dest = dest
                .or_else(|| remote_name.then(cwd_dest).flatten())
                .filter(|d| d != "-" && is_agent_dest(d, ctx))
                .or_else(|| download_file(stage, ctx).filter(|f| agent_path(f)))?;
            let url = cmdline::first_url(stage).unwrap_or_else(|| "<url>".into());
            Some(Decision::Deny(format!(
                "Downloads into agent tooling ({dest}) with no scan. Use: sigil scan {url} — it downloads into quarantine and scans first. {BYPASS_HINT}"
            )))
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
        let args: Vec<&String> = toks
            .iter()
            .skip_while(|t| *t != "clone")
            .skip(1)
            .filter(|t| !t.starts_with('-'))
            .collect();
        let url = args
            .first()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<url>".into());
        let into_tooling = args.get(1).is_some_and(|d| is_agent_dest(d, ctx))
            || (args.len() == 1
                && ctx
                    .cwd
                    .as_ref()
                    .is_some_and(|c| agent_path(&c.to_string_lossy())));
        return Decision::Deny(if into_tooling {
            format!(
                "git clone into agent tooling installs unscanned skills or plugins. Use: sigil clone {url} && {} (the clone only runs if the scan passes). {BYPASS_HINT}",
                stage.trim()
            )
        } else {
            format!(
                "git clone pulls unscanned code. Use: sigil clone {url} (quarantine + scan first). {BYPASS_HINT}"
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

    // pip / uv: -r requirements -> ask; explicit package -> deny.
    let pip_install = format!(
        r"{WB}(pip[0-9.]*{MOD}\s+install|python[0-9.]*\s+-m\s+pip\s+install|uv\s+pip\s+install)"
    );
    if has(stage, &format!(r"{pip_install}(\s|$)")) {
        return if has(stage, r"(^|\s)(-r|--requirement)(\s|$)") {
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

/// Tokens of a stage with leading `sudo` and `VAR=value` words dropped.
fn command_tokens(stage: &str) -> Vec<String> {
    let mut toks = cmdline::tokenize(stage);
    while toks
        .first()
        .is_some_and(|t| t == "sudo" || t == "env" || (t.contains('=') && !t.starts_with('-')))
    {
        toks.remove(0);
    }
    toks
}

/// The file a `curl`/`wget` stage saves its download to, resolved like
/// [`canon_path`]. `None` when it writes to stdout or is not a download.
fn download_file(stage: &str, ctx: &Context) -> Option<String> {
    let toks = command_tokens(stage);
    let head = toks.first()?.rsplit('/').next()?.to_string();
    let wget = head == "wget";
    if !wget && head != "curl" {
        return None;
    }
    let url_name = cmdline::first_url(stage).and_then(|u| {
        let path = u.split(['?', '#']).next()?.to_string();
        let name = path
            .split("://")
            .nth(1)?
            .split_once('/')?
            .1
            .rsplit('/')
            .next()?;
        (!name.is_empty()).then(|| name.to_string())
    });
    let mut out: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut remote = wget;
    let mut it = toks.iter().skip(1);
    while let Some(t) = it.next() {
        let t = t.as_str();
        match t {
            ">" | ">>" => out = it.next().cloned(),
            _ if t.starts_with('>') && !t.starts_with(">&") => {
                out = Some(t.trim_start_matches('>').to_string())
            }
            "--output" | "--output-document" => out = it.next().cloned(),
            "-o" if wget => {
                it.next(); // wget -o is its log file
            }
            "-o" => out = it.next().cloned(),
            "-O" if wget => out = it.next().cloned(),
            "-O" | "--remote-name" => remote = true,
            "-P" | "--directory-prefix" | "--output-dir" => dir = it.next().cloned(),
            _ if t.starts_with("--output-document=") || t.starts_with("--output=") => {
                out = t.split_once('=').map(|(_, v)| v.to_string())
            }
            _ if t.starts_with("--directory-prefix=") || t.starts_with("--output-dir=") => {
                dir = t.split_once('=').map(|(_, v)| v.to_string())
            }
            // Bundled short flags: curl `-fsSLo file`, `-fsSLO`; wget `-qO file`, `-qO-`.
            _ if t.starts_with('-') && !t.starts_with("--") => {
                let flags = &t[1..];
                if wget {
                    if let Some(i) = flags.find('O') {
                        let rest = &flags[i + 1..];
                        out = if rest.is_empty() {
                            it.next().cloned()
                        } else {
                            Some(rest.to_string())
                        };
                    }
                } else if flags.ends_with('o') {
                    out = it.next().cloned();
                } else if flags.contains('O') {
                    remote = true;
                }
            }
            _ => {}
        }
    }
    let file = out.or_else(|| remote.then_some(url_name).flatten())?;
    if file == "-" || file.starts_with("/dev/") {
        return None;
    }
    let file = match dir {
        Some(d) if !file.contains('/') => format!("{}/{file}", d.trim_end_matches('/')),
        _ => file,
    };
    Some(canon_path(&file, ctx))
}

/// The file a stage executes: the script argument of an interpreter
/// (`bash x.sh`, `python3 x.py`, `. x.sh`) or a path run directly (`./x`).
fn executed_file(stage: &str, ctx: &Context) -> Option<String> {
    let toks = command_tokens(stage);
    let head = toks.first()?;
    let base = head.rsplit('/').next().unwrap_or(head);
    let interp = matches!(
        base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "python"
            | "node"
            | "deno"
            | "bun"
            | "perl"
            | "ruby"
            | "php"
            | "pwsh"
            | "powershell"
            | "source"
            | "."
    );
    if !interp {
        return head.contains('/').then(|| canon_path(head, ctx));
    }
    for t in toks.iter().skip(1) {
        if matches!(
            t.as_str(),
            "-c" | "-e" | "-m" | "-Command" | "-EncodedCommand"
        ) {
            return None; // inline code or a module, not a file
        }
        if t == "run" || t.starts_with('-') {
            continue;
        }
        return Some(canon_path(t, ctx));
    }
    None
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

    // A download piped or substituted into an interpreter. Judged on the
    // whole command (process substitution spans segments) and never gated
    // by a prior scan: the server decides per request what it serves.
    if cmdline::pipes_download_to_interpreter(cmd) {
        let alt = match cmdline::first_url(cmd) {
            Some(u) => format!(
                "Use: sigil scan {u} — or download it (curl -fsSLo script.sh {u}), run sigil scan script.sh, then run the file you scanned"
            ),
            None => "Download the script, run sigil scan on it, then execute the file you scanned".into(),
        };
        return Decision::Deny(format!(
            "Piping a download into an interpreter executes unscanned code. {alt}. {BYPASS_HINT}"
        ));
    }

    let mut ctx = ctx.clone();
    let mut gates: Vec<Vec<Target>> = Vec::new();
    // Files curl/wget saved earlier in this command line.
    let mut downloads: Vec<String> = Vec::new();
    let mut decision = Decision::Allow(NO_MATCH.into());
    for (op, seg) in segments(cmd) {
        if op != Op::And {
            gates.clear();
        }
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some(dir) = cd_target(seg, &ctx) {
            ctx.cwd = dir;
            continue;
        }
        for stage in stages(seg) {
            let stage = stage.trim();
            if stage.is_empty() {
                continue;
            }
            // The command is going through sigil: that stage is allowed,
            // and a vetting call gates what follows it with `&&`.
            if is_sigil(stage) {
                if let Some(t) = vetting_targets(stage, &ctx) {
                    gates.push(t);
                }
                continue;
            }
            let mut d = classify_stage(stage, &ctx);
            let mut targets = stage_targets(stage, &ctx);
            // Download to a file, then run that file: the same remote
            // execution as `curl … | sh`, one step removed. Unlike the pipe,
            // this form can be gated — the scan reads the bytes that run.
            if let Some(f) = executed_file(stage, &ctx).filter(|f| downloads.contains(f)) {
                d = worse(
                    d,
                    Decision::Deny(format!(
                        "Runs {f}, downloaded earlier in this command, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan {f} && {} (after the download). {BYPASS_HINT}",
                        stage.trim()
                    )),
                );
                targets = vec![Target::Path(f)];
            }
            if let Some(f) = download_file(stage, &ctx) {
                downloads.push(f);
            }
            let d = if d.rank() > 0 && gated(&gates, &targets) {
                Decision::Allow("Gated by a preceding sigil check on the same target".into())
            } else {
                d
            };
            decision = worse(decision, d);
        }
    }
    if let Decision::Allow(r) = &decision {
        if r == NO_MATCH && is_sigil(cmd) {
            return Decision::Allow("Command uses sigil".into());
        }
    }
    decision
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
