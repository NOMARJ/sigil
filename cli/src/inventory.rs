//! `sigil skills` — what agent tooling is installed here, and is any of it
//! dangerous?
//!
//! `sigil scan` answers "is this code safe to bring in". This module answers
//! the posture question for everything already brought in: the skills,
//! plugins, extensions, agent/command definitions, hooks and MCP servers
//! that Claude Code, Codex, Gemini CLI, Cursor, Windsurf, VS Code, Cline /
//! Roo, Continue, Goose, OpenCode, Zed, Amazon Q, Kiro, Junie and OpenClaw
//! will load on their next start — for the user (home directory) and for the
//! current project.
//!
//! Two kinds of item come out of discovery:
//!
//! - **Content** (skills, plugins, extensions, instruction directories): the
//!   directory is scanned with the normal scanner, and its verdict is the
//!   scanner's.
//! - **Configuration** (MCP server entries, hooks, agent settings): the
//!   command line, URL, environment and flags are inspected by the
//!   `AGENTCFG-*` checks below, and a local script the entry runs is scanned
//!   too. A config item's verdict is its worst finding's severity.
//!
//! The `AGENTCFG-*` severities follow the project's policy: an idiom that
//! is routine in legitimate configs (an unpinned `npx -y`, a token in your
//! own `claude_desktop_config.json`, a remote https endpoint) is at most Low
//! — recorded, never gating. Medium is suspicious in context; High and
//! Critical are attack shapes (a download piped to a shell, a hook that
//! ships the event payload off the machine, a container with the host's
//! root filesystem).
//!
//! Every path is taken relative to an explicit home and project directory,
//! so tests (and fleet tooling) can point `--root` at a fixture tree and
//! never touch the real machine. System-wide managed settings are read only
//! when `--root` is not given.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

use crate::cmdline;
use crate::scanner::{self, Evidence, Finding, Phase, Severity, Verdict};

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Skill,
    Plugin,
    Extension,
    Instructions,
    McpServer,
    Hook,
    Settings,
    Marketplace,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Skill => "skill",
            Kind::Plugin => "plugin",
            Kind::Extension => "extension",
            Kind::Instructions => "instructions",
            Kind::McpServer => "mcp-server",
            Kind::Hook => "hook",
            Kind::Settings => "settings",
            Kind::Marketplace => "marketplace",
        }
    }

    fn is_content(self) -> bool {
        matches!(
            self,
            Kind::Skill | Kind::Plugin | Kind::Extension | Kind::Instructions
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub tool: String,
    pub scope: String,
    pub kind: Kind,
    pub name: String,
    /// Where it lives, `~`-relative for home paths.
    pub location: String,
    #[serde(skip)]
    pub path: PathBuf,
    /// Command line (secrets redacted), URL, or source.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    pub score: u32,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    /// Scripts this entry runs that were found on disk and scanned.
    #[serde(skip)]
    scripts: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub home: PathBuf,
    pub project: Option<PathBuf>,
    /// Read system-wide managed settings (`/etc/claude-code/...`).
    pub system: bool,
    /// Restrict to these tool ids.
    pub tools: Option<Vec<String>>,
    /// Honour `CLAUDE_CONFIG_DIR` / `CODEX_HOME` from the environment.
    pub env_overrides: bool,
    /// Read user-level (home) and system locations. Off for a
    /// project-only check such as a pre-commit hook, where the result must
    /// not depend on whose machine runs it.
    pub user: bool,
}

// ---------------------------------------------------------------------------
// AGENTCFG checks
// ---------------------------------------------------------------------------

/// Rule ids, severities and titles for configuration findings. Titles are
/// also registered in `scanner::profile::builtin_title`.
pub const RULES: &[(&str, Severity, &str)] = &[
    (
        "AGENTCFG-001",
        Severity::Low,
        "Package runner fetches an unpinned package at every start",
    ),
    (
        "AGENTCFG-002",
        Severity::Critical,
        "Download piped or substituted into an interpreter",
    ),
    (
        "AGENTCFG-003",
        Severity::High,
        "Container runs with host-level privileges or host secrets mounted",
    ),
    (
        "AGENTCFG-004",
        Severity::Low,
        "Container shares the host network namespace",
    ),
    (
        "AGENTCFG-005",
        Severity::High,
        "Credential literal in a project-scoped agent config (travels with the repository)",
    ),
    (
        "AGENTCFG-006",
        Severity::Medium,
        "Secret-named literal in a project-scoped agent config",
    ),
    (
        "AGENTCFG-007",
        Severity::Low,
        "Plaintext credential in a user-level agent config",
    ),
    (
        "AGENTCFG-008",
        Severity::Medium,
        "Remote MCP endpoint over plaintext http or a raw IP address",
    ),
    (
        "AGENTCFG-009",
        Severity::High,
        "Remote MCP endpoint on a tunnel or request-capture host",
    ),
    (
        "AGENTCFG-010",
        Severity::High,
        "Inline interpreter payload that decodes or evaluates code",
    ),
    (
        "AGENTCFG-011",
        Severity::Medium,
        "Runs a program from a world-writable temporary directory",
    ),
    (
        "AGENTCFG-012",
        Severity::Medium,
        "Agent-wide auto-approval: tools or project servers run without asking",
    ),
    (
        "AGENTCFG-013",
        Severity::Low,
        "Per-server auto-approval of tool calls",
    ),
    (
        "AGENTCFG-014",
        Severity::Medium,
        "Command sends data to another host",
    ),
    (
        "AGENTCFG-015",
        Severity::High,
        "Hook forwards its event payload off the machine",
    ),
    (
        "AGENTCFG-016",
        Severity::Medium,
        "Command reads credential stores",
    ),
];

fn rule(id: &str) -> (Severity, &'static str) {
    RULES
        .iter()
        .find(|(r, _, _)| *r == id)
        .map(|(_, s, t)| (*s, *t))
        .unwrap_or((Severity::Low, "agent configuration"))
}

pub fn title(id: &str) -> Option<&'static str> {
    RULES.iter().find(|(r, _, _)| *r == id).map(|(_, _, t)| *t)
}

fn finding(id: &str, file: &str, line: Option<usize>, detail: String) -> Finding {
    let (severity, title) = rule(id);
    Finding {
        phase: Phase::SkillSecurity,
        rule: id.to_string(),
        severity,
        file: file.to_string(),
        line,
        snippet: format!("{title}: {detail}"),
        weight: Phase::SkillSecurity.default_weight(),
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: None,
        evidence: Evidence::Standalone,
    }
}

/// A normalised MCP server entry, whatever tool wrote it.
#[derive(Debug, Clone, Default)]
struct Server {
    command: Vec<String>,
    url: Option<String>,
    env: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    cwd: Option<String>,
    auto_approve: bool,
    disabled: bool,
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(Value::Object(m)) = v {
        for (k, v) in m {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            out.insert(k.clone(), s);
        }
    }
    out
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

/// Normalise one server object. Handles the shapes of every tool listed in
/// the module docs: `command`+`args` (most), `cmd`+`envs` (Goose), a
/// `command` array + `environment` (OpenCode), a nested `command` object
/// (Zed), `url` / `httpUrl` / `serverUrl` / `uri`, and Continue's legacy
/// `transport` object.
fn normalise(v: &Value) -> Server {
    let mut s = Server::default();
    let obj = match v.as_object() {
        Some(o) => o,
        None => return s,
    };
    let src = match obj.get("transport") {
        Some(t @ Value::Object(_)) => t,
        _ => v,
    };
    match src.get("command").or_else(|| src.get("cmd")) {
        Some(Value::String(c)) => s.command.push(c.clone()),
        Some(a @ Value::Array(_)) => s.command.extend(str_list(Some(a))),
        Some(Value::Object(o)) => {
            if let Some(Value::String(p)) = o.get("path") {
                s.command.push(p.clone());
            }
            s.command.extend(str_list(o.get("args")));
            s.env.extend(str_map(o.get("env")));
        }
        _ => {}
    }
    s.command.extend(str_list(src.get("args")));
    for key in ["env", "envs", "environment"] {
        s.env.extend(str_map(src.get(key)));
    }
    for key in ["headers", "http_headers", "requestInit"] {
        let h = src.get(key);
        let h = h.and_then(|h| h.get("headers")).or(h);
        s.headers.extend(str_map(h));
    }
    s.url = ["url", "httpUrl", "serverUrl", "uri", "endpoint"]
        .iter()
        .find_map(|k| src.get(*k).and_then(Value::as_str).map(str::to_string));
    s.cwd = src.get("cwd").and_then(Value::as_str).map(str::to_string);
    let non_empty = |k: &str| match obj.get(k) {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Bool(b)) => *b,
        _ => false,
    };
    s.auto_approve = non_empty("autoApprove") || non_empty("alwaysAllow") || non_empty("trust");
    s.disabled = obj.get("disabled").and_then(Value::as_bool) == Some(true)
        || obj.get("enabled").and_then(Value::as_bool) == Some(false);
    s
}

/// Values that are references or placeholders rather than secrets.
fn is_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.len() < 8
        || v.contains("${")
        || v.starts_with('$')
        || v.contains("{{")
        || v.starts_with('<')
        || l.starts_with("env:")
        || l.starts_with("op://")
        || [
            "your",
            "xxx",
            "***",
            "...",
            "changeme",
            "example",
            "placeholder",
            "replace",
            "todo",
            "insert",
            "redacted",
            "dummy",
        ]
        .iter()
        .any(|p| l.contains(p))
}

/// Known credential formats: an exact provider-issued token shape.
fn known_secret(v: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|shpat_[a-fA-F0-9]{32}|pplx-[A-Za-z0-9]{40,}|lin_api_[A-Za-z0-9]{40}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
        )
        .expect("static pattern compiles")
    })
    .is_match(v)
}

fn secret_named(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "api_key",
        "api-key",
        "access_key",
        "private_key",
        "authorization",
        "auth",
        "credential",
        "pat",
    ]
    .iter()
    .any(|w| l.contains(w))
}

fn redact(v: &str) -> String {
    let keep: String = v.chars().take(4).collect();
    format!("{keep}…({} chars)", v.chars().count())
}

/// Replace secret-looking values in a command line for display.
fn redact_line(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            let shown = if known_secret(p) {
                redact(p)
            } else if let Some((k, v)) = p.split_once('=') {
                if secret_named(k) && !is_placeholder(v) {
                    format!("{k}={}", redact(v))
                } else {
                    p.clone()
                }
            } else {
                p.clone()
            };
            if shown.contains(' ') {
                format!("'{shown}'")
            } else {
                shown
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Exposure {
    /// Shared with everyone who clones the repository.
    Project,
    /// Readable by every process running as the user.
    User,
}

fn check_secret(
    out: &mut Vec<Finding>,
    file: &str,
    line: Option<usize>,
    exposure: Exposure,
    key: &str,
    value: &str,
) {
    let v = value
        .trim_start_matches("Bearer ")
        .trim_start_matches("bearer ");
    if is_placeholder(v) {
        return;
    }
    let known = known_secret(v);
    let named = secret_named(key);
    let id = match (exposure, known, named) {
        (_, false, false) => return,
        (Exposure::Project, true, _) => "AGENTCFG-005",
        (Exposure::Project, false, true) => "AGENTCFG-006",
        (Exposure::User, _, _) => "AGENTCFG-007",
    };
    out.push(finding(id, file, line, format!("{key}={}", redact(v))));
}

/// Checks on any command line an agent tool will run on its own.
/// `raw` is the command as the agent will hand it to a shell (a hook's
/// `command` string) or the argv joined (an MCP server); `parts` is argv.
fn check_command(
    out: &mut Vec<Finding>,
    file: &str,
    line: Option<usize>,
    raw: &str,
    parts: &[String],
    is_hook: bool,
) {
    if parts.is_empty() {
        return;
    }
    let joined = raw;
    let shown = redact_line(parts);
    if cmdline::pipes_download_to_interpreter(joined) {
        let alt = cmdline::first_url(joined)
            .map(|u| format!(" — vet it first: sigil scan {u}"))
            .unwrap_or_default();
        out.push(finding("AGENTCFG-002", file, line, format!("{shown}{alt}")));
    }
    if let Some(r) = cmdline::parse_runner(parts) {
        if !r.pinned {
            out.push(finding(
                "AGENTCFG-001",
                file,
                line,
                format!(
                    "{} {} — whatever the registry serves at each start runs with your privileges; vet with `{}` and pin an exact version",
                    r.tool,
                    r.spec,
                    r.sigil_alternative()
                ),
            ));
        }
    }
    check_container(out, file, line, parts);
    // Inline interpreter payloads that decode or evaluate.
    static DECODE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let decode = DECODE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(base64\s+(-d|--decode|-D)|b64decode|atob\s*\(|fromcharcode|frombase64string|\bexec\s*\(|\beval\s*\(|marshal\.loads|zlib\.decompress|codecs\.decode)",
        )
        .expect("static pattern compiles")
    });
    let inline = parts.windows(2).any(|w| {
        matches!(
            w[0].as_str(),
            "-c" | "-e" | "--eval" | "-Command" | "-EncodedCommand" | "-enc"
        )
    }) || parts
        .iter()
        .any(|p| p.contains(" -c ") || p.contains(" -e "));
    if inline && decode.is_match(joined) {
        out.push(finding("AGENTCFG-010", file, line, shown.clone()));
    }
    if parts
        .iter()
        .any(|p| p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.starts_with("/dev/shm/"))
    {
        out.push(finding("AGENTCFG-011", file, line, shown.clone()));
    }
    if is_hook && cmdline::forwards_stdin(joined) {
        out.push(finding("AGENTCFG-015", file, line, shown.clone()));
    } else if cmdline::sends_off_machine(joined) {
        out.push(finding("AGENTCFG-014", file, line, shown.clone()));
    }
    if cmdline::touches_credentials(joined) {
        out.push(finding("AGENTCFG-016", file, line, shown));
    }
}

fn check_container(out: &mut Vec<Finding>, file: &str, line: Option<usize>, parts: &[String]) {
    let Some(risk) = cmdline::container_risk(parts) else {
        return;
    };
    if !risk.escapes.is_empty() {
        out.push(finding("AGENTCFG-003", file, line, risk.escapes.join(" ")));
    }
    if risk.host_network {
        out.push(finding("AGENTCFG-004", file, line, "--network host".into()));
    }
}

fn check_url(
    out: &mut Vec<Finding>,
    file: &str,
    line: Option<usize>,
    exposure: Exposure,
    url: &str,
) {
    let Ok(u) = reqwest::Url::parse(url) else {
        return;
    };
    let host = u
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .to_string();
    let local = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if cmdline::capture_host(&host) {
        out.push(finding("AGENTCFG-009", file, line, host.clone()));
    } else if !local
        && (u.scheme() == "http"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| !crate::ingest::is_non_public(ip)))
    {
        out.push(finding(
            "AGENTCFG-008",
            file,
            line,
            format!("{}://{host}", u.scheme()),
        ));
    }
    // Credentials embedded in the URL itself.
    if !u.password().unwrap_or("").is_empty() {
        check_secret(
            out,
            file,
            line,
            exposure,
            "url-password",
            u.password().unwrap_or(""),
        );
    }
    for (k, v) in u.query_pairs() {
        check_secret(out, file, line, exposure, &k, &v);
    }
}

// ---------------------------------------------------------------------------
// Config parsing helpers
// ---------------------------------------------------------------------------

/// Strip `//` and `/* */` comments and trailing commas (VS Code, Zed and
/// OpenCode configs are JSONC).
fn strip_jsonc(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                out.push(c);
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b',' => {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if !matches!(b.get(j), Some(b'}') | Some(b']')) {
                    out.push(c);
                }
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
    Json,
    Yaml,
    Toml,
}

fn load(path: &Path, fmt: Fmt) -> Option<(String, Value)> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let v = match fmt {
        Fmt::Json => serde_json::from_str(&text)
            .or_else(|_| serde_json::from_str(&strip_jsonc(&text)))
            .ok()?,
        Fmt::Yaml => {
            let y: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
            serde_json::to_value(y).ok()?
        }
        Fmt::Toml => mini_toml::parse(&text).ok()?,
    };
    Some((text, v))
}

fn line_of(text: &str, needle: &str) -> Option<usize> {
    text.lines().position(|l| l.contains(needle)).map(|i| i + 1)
}

fn get<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |acc, k| acc.get(*k))
}

/// Named servers under `path`: an object of name → entry, or an array of
/// entries carrying a `name` (Continue).
fn servers_at(v: &Value, path: &[&str]) -> Vec<(String, Value)> {
    match get(v, path) {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let name = e
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("server-{i}"));
                (name, e.clone())
            })
            .collect(),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

struct Discovery<'a> {
    opts: &'a Options,
    items: Vec<Item>,
    /// Skill / plugin / settings paths already listed (canonical).
    seen: HashSet<PathBuf>,
    /// (config file, key path) pairs already read for servers.
    parsed: HashSet<(PathBuf, String)>,
    searched: Vec<(PathBuf, bool)>,
}

/// Skill roots relative to the home directory.
const USER_SKILL_ROOTS: &[(&str, &str)] = &[
    ("claude-code", ".claude/skills"),
    ("codex", ".codex/skills"),
    ("agents", ".agents/skills"),
    ("gemini-cli", ".gemini/skills"),
    ("cursor", ".cursor/skills"),
    ("copilot", ".copilot/skills"),
    ("windsurf", ".codeium/windsurf/skills"),
    ("opencode", ".config/opencode/skill"),
    ("opencode", ".config/opencode/skills"),
    ("goose", ".config/goose/skills"),
    ("openclaw", ".openclaw/skills"),
    ("openclaw", ".openclaw/workspace/skills"),
    ("openclaw", ".clawdbot/skills"),
    ("openclaw", ".moltbot/skills"),
];

/// Skill roots relative to the project directory.
const PROJECT_SKILL_ROOTS: &[(&str, &str)] = &[
    ("claude-code", ".claude/skills"),
    ("codex", ".codex/skills"),
    ("agents", ".agents/skills"),
    ("gemini-cli", ".gemini/skills"),
    ("cursor", ".cursor/skills"),
    ("copilot", ".github/skills"),
    ("opencode", ".opencode/skill"),
    ("opencode", ".opencode/skills"),
];

/// Agent / command / rule definition directories: markdown the agent loads
/// as instructions.
const USER_INSTRUCTION_DIRS: &[(&str, &str)] = &[
    ("claude-code", ".claude/agents"),
    ("claude-code", ".claude/commands"),
    ("codex", ".codex/prompts"),
    ("gemini-cli", ".gemini/commands"),
    ("opencode", ".config/opencode/agent"),
    ("opencode", ".config/opencode/command"),
];

const PROJECT_INSTRUCTION_DIRS: &[(&str, &str)] = &[
    ("claude-code", ".claude/agents"),
    ("claude-code", ".claude/commands"),
    ("gemini-cli", ".gemini/commands"),
    ("cursor", ".cursor/rules"),
    ("windsurf", ".windsurf/rules"),
    ("windsurf", ".windsurf/workflows"),
    ("copilot", ".github/prompts"),
    ("copilot", ".github/instructions"),
    ("opencode", ".opencode/agent"),
    ("opencode", ".opencode/command"),
    ("roo-code", ".roo/rules"),
    ("cline", ".clinerules"),
];

/// MCP config files: (tool, path, format, key path to the server map).
type McpSource = (&'static str, &'static str, Fmt, &'static [&'static str]);

const USER_MCP: &[McpSource] = &[
    (
        "claude-desktop",
        "Library/Application Support/Claude/claude_desktop_config.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "claude-desktop",
        ".config/Claude/claude_desktop_config.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "claude-desktop",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "gemini-cli",
        ".gemini/settings.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    ("cursor", ".cursor/mcp.json", Fmt::Json, &["mcpServers"]),
    (
        "windsurf",
        ".codeium/windsurf/mcp_config.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "opencode",
        ".config/opencode/opencode.json",
        Fmt::Json,
        &["mcp"],
    ),
    (
        "opencode",
        ".config/opencode/opencode.jsonc",
        Fmt::Json,
        &["mcp"],
    ),
    (
        "opencode",
        ".config/opencode/config.json",
        Fmt::Json,
        &["mcp"],
    ),
    (
        "continue",
        ".continue/config.json",
        Fmt::Json,
        &["experimental", "modelContextProtocolServers"],
    ),
    (
        "continue",
        ".continue/config.yaml",
        Fmt::Yaml,
        &["mcpServers"],
    ),
    (
        "goose",
        ".config/goose/config.yaml",
        Fmt::Yaml,
        &["extensions"],
    ),
    (
        "zed",
        ".config/zed/settings.json",
        Fmt::Json,
        &["context_servers"],
    ),
    (
        "amazon-q",
        ".aws/amazonq/mcp.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "kiro",
        ".kiro/settings/mcp.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    ("junie", ".junie/mcp/mcp.json", Fmt::Json, &["mcpServers"]),
    (
        "cline",
        ".cline/data/settings/cline_mcp_settings.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "openclaw",
        ".openclaw/openclaw.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    (
        "openclaw",
        ".openclaw/openclaw.json",
        Fmt::Json,
        &["mcp", "servers"],
    ),
];

const PROJECT_MCP: &[McpSource] = &[
    ("claude-code", ".mcp.json", Fmt::Json, &["mcpServers"]),
    ("cursor", ".cursor/mcp.json", Fmt::Json, &["mcpServers"]),
    ("vscode", ".vscode/mcp.json", Fmt::Json, &["servers"]),
    (
        "gemini-cli",
        ".gemini/settings.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    ("codex", ".codex/config.toml", Fmt::Toml, &["mcp_servers"]),
    ("roo-code", ".roo/mcp.json", Fmt::Json, &["mcpServers"]),
    ("opencode", "opencode.json", Fmt::Json, &["mcp"]),
    ("opencode", "opencode.jsonc", Fmt::Json, &["mcp"]),
    ("amazon-q", ".amazonq/mcp.json", Fmt::Json, &["mcpServers"]),
    (
        "kiro",
        ".kiro/settings/mcp.json",
        Fmt::Json,
        &["mcpServers"],
    ),
    ("zed", ".zed/settings.json", Fmt::Json, &["context_servers"]),
];

/// VS Code-family user directories (Linux, macOS, Windows layouts).
const VSCODE_USER_DIRS: &[&str] = &[
    ".config/Code/User",
    ".config/Code - Insiders/User",
    ".config/VSCodium/User",
    "Library/Application Support/Code/User",
    "Library/Application Support/Code - Insiders/User",
    "Library/Application Support/VSCodium/User",
    "AppData/Roaming/Code/User",
    "AppData/Roaming/Code - Insiders/User",
];

/// Cline-family extensions keep MCP settings in VS Code global storage.
const VSCODE_EXTENSION_MCP: &[(&str, &str)] = &[
    (
        "cline",
        "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    ),
    (
        "roo-code",
        "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
    ),
    (
        "kilo-code",
        "globalStorage/kilocode.kilo-code/settings/mcp_settings.json",
    ),
];

impl<'a> Discovery<'a> {
    fn new(opts: &'a Options) -> Self {
        Discovery {
            opts,
            items: Vec::new(),
            seen: HashSet::new(),
            parsed: HashSet::new(),
            searched: Vec::new(),
        }
    }

    fn display(&self, p: &Path) -> String {
        if let Some(proj) = self.opts.project.as_ref().filter(|p| **p != self.opts.home) {
            if let Ok(rel) = p.strip_prefix(proj) {
                let r = rel.display().to_string();
                return if r.is_empty() { ".".into() } else { r };
            }
        }
        if let Ok(rel) = p.strip_prefix(&self.opts.home) {
            return format!("~/{}", rel.display());
        }
        p.display().to_string()
    }

    /// First sighting of a path wins, so a project that *is* the home
    /// directory does not list everything twice.
    fn first_time(&mut self, p: &Path) -> bool {
        let key = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        self.seen.insert(key)
    }

    fn note(&mut self, p: &Path) -> bool {
        let in_project = self
            .opts
            .project
            .as_ref()
            .is_some_and(|proj| p.starts_with(proj));
        if !self.opts.user && !in_project {
            return false;
        }
        let exists = p.exists();
        self.searched.push((p.to_path_buf(), exists));
        exists
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        tool: &str,
        scope: &str,
        kind: Kind,
        name: String,
        path: &Path,
        detail: String,
        findings: Vec<Finding>,
    ) {
        let location = self.display(path);
        self.items.push(Item {
            tool: tool.to_string(),
            scope: scope.to_string(),
            kind,
            name,
            location,
            path: path.to_path_buf(),
            detail,
            verdict: None,
            score: 0,
            files_scanned: 0,
            findings,
            scripts: Vec::new(),
        });
    }

    fn claude_dir(&self) -> PathBuf {
        if self.opts.env_overrides {
            if let Ok(d) = std::env::var("CLAUDE_CONFIG_DIR") {
                return PathBuf::from(d);
            }
        }
        self.opts.home.join(".claude")
    }

    fn codex_dir(&self) -> PathBuf {
        if self.opts.env_overrides {
            if let Ok(d) = std::env::var("CODEX_HOME") {
                return PathBuf::from(d);
            }
        }
        self.opts.home.join(".codex")
    }

    fn user_path(&self, rel: &str) -> PathBuf {
        if let Some(r) = rel.strip_prefix(".claude/") {
            return self.claude_dir().join(r);
        }
        if let Some(r) = rel.strip_prefix(".codex/") {
            return self.codex_dir().join(r);
        }
        self.opts.home.join(rel)
    }

    // -- skills ------------------------------------------------------------

    fn skills(&mut self) {
        let roots: Vec<(String, &str, PathBuf)> = USER_SKILL_ROOTS
            .iter()
            .map(|(t, r)| (t.to_string(), "user", self.user_path(r)))
            .chain(self.opts.project.iter().flat_map(|p| {
                PROJECT_SKILL_ROOTS
                    .iter()
                    .map(move |(t, r)| (t.to_string(), "project", p.join(r)))
            }))
            .collect();
        for (tool, scope, root) in roots {
            if !self.note(&root) {
                continue;
            }
            for dir in find_skill_dirs(&root) {
                if !self.first_time(&dir) {
                    continue;
                }
                let name = skill_name(&dir);
                let detail = match std::fs::read_link(&dir) {
                    Ok(t) => format!("symlink → {}", t.display()),
                    Err(_) => String::new(),
                };
                self.push(&tool, scope, Kind::Skill, name, &dir, detail, vec![]);
            }
        }
    }

    // -- Claude Code plugins and marketplaces -------------------------------

    fn plugins(&mut self) {
        let base = self.claude_dir().join("plugins");
        if !self.note(&base) {
            return;
        }
        let mut dirs: Vec<(String, PathBuf, String)> = Vec::new();
        if let Some((_, v)) = load(&base.join("installed_plugins.json"), Fmt::Json) {
            if let Some(Value::Object(m)) = v.get("plugins") {
                for (id, entry) in m {
                    let entries: Vec<&Value> = match entry {
                        Value::Array(a) => a.iter().collect(),
                        other => vec![other],
                    };
                    for e in entries {
                        if let Some(p) = e.get("installPath").and_then(Value::as_str) {
                            let scope = e.get("scope").and_then(Value::as_str).unwrap_or("user");
                            dirs.push((id.clone(), PathBuf::from(p), scope.to_string()));
                        }
                    }
                }
            }
        }
        if dirs.is_empty() {
            for d in find_marked_dirs(&base, &[".claude-plugin", "plugin.json"], 6) {
                let name = load(&d.join(".claude-plugin/plugin.json"), Fmt::Json)
                    .and_then(|(_, v)| v.get("name").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_else(|| dir_name(&d));
                dirs.push((name, d, "user".into()));
            }
        }
        for (name, dir, scope) in dirs {
            if !dir.is_dir() || !self.first_time(&dir) {
                continue;
            }
            self.push(
                "claude-code",
                &scope,
                Kind::Plugin,
                name.clone(),
                &dir,
                String::new(),
                vec![],
            );
            // What the plugin wires into the agent: its hooks and servers.
            let hooks = dir.join("hooks/hooks.json");
            if let Some((text, v)) = load(&hooks, Fmt::Json) {
                let hv = v.get("hooks").cloned().unwrap_or(v);
                self.hooks_from(
                    &hooks,
                    &text,
                    &hv,
                    "claude-code",
                    &scope,
                    &format!("{name}:"),
                    Some(&dir),
                );
            }
            let mcp = dir.join(".mcp.json");
            if let Some((text, v)) = load(&mcp, Fmt::Json) {
                let key: &[&str] = if v.get("mcpServers").is_some() {
                    &["mcpServers"]
                } else {
                    &[]
                };
                self.servers_from(
                    &mcp,
                    &text,
                    &v,
                    key,
                    "claude-code",
                    &scope,
                    &format!("{name}:"),
                    Exposure::User,
                );
            }
            let manifest = dir.join(".claude-plugin/plugin.json");
            if let Some((text, v)) = load(&manifest, Fmt::Json) {
                if v.get("mcpServers").is_some_and(Value::is_object) {
                    self.servers_from(
                        &manifest,
                        &text,
                        &v,
                        &["mcpServers"],
                        "claude-code",
                        &scope,
                        &format!("{name}:"),
                        Exposure::User,
                    );
                }
                if v.get("hooks").is_some_and(Value::is_object) {
                    let hv = v["hooks"].clone();
                    self.hooks_from(
                        &manifest,
                        &text,
                        &hv,
                        "claude-code",
                        &scope,
                        &format!("{name}:"),
                        Some(&dir),
                    );
                }
            }
        }
        let known = base.join("known_marketplaces.json");
        if let Some((_, Value::Object(m))) = load(&known, Fmt::Json) {
            for (name, e) in m {
                let src = e.get("source").cloned().unwrap_or(Value::Null);
                let detail = ["repo", "url", "path"]
                    .iter()
                    .find_map(|k| src.get(*k).and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string();
                self.push(
                    "claude-code",
                    "user",
                    Kind::Marketplace,
                    name,
                    &known,
                    detail,
                    vec![],
                );
            }
        }
    }

    // -- Gemini CLI extensions ---------------------------------------------

    fn extensions(&mut self) {
        let mut bases = vec![(self.opts.home.join(".gemini/extensions"), "user")];
        if let Some(p) = &self.opts.project {
            bases.push((p.join(".gemini/extensions"), "project"));
        }
        for (base, scope) in bases {
            if !self.note(&base) {
                continue;
            }
            for d in find_marked_dirs(&base, &["gemini-extension.json"], 2) {
                if !self.first_time(&d) {
                    continue;
                }
                let manifest = d.join("gemini-extension.json");
                let loaded = load(&manifest, Fmt::Json);
                let name = loaded
                    .as_ref()
                    .and_then(|(_, v)| v.get("name").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_else(|| dir_name(&d));
                self.push(
                    "gemini-cli",
                    scope,
                    Kind::Extension,
                    name.clone(),
                    &d,
                    String::new(),
                    vec![],
                );
                if let Some((text, v)) = loaded {
                    let exposure = if scope == "project" {
                        Exposure::Project
                    } else {
                        Exposure::User
                    };
                    self.servers_from(
                        &manifest,
                        &text,
                        &v,
                        &["mcpServers"],
                        "gemini-cli",
                        scope,
                        &format!("{name}:"),
                        exposure,
                    );
                }
            }
        }
    }

    // -- agent / command / rule definitions ---------------------------------

    fn instructions(&mut self) {
        let dirs: Vec<(String, &str, PathBuf)> = USER_INSTRUCTION_DIRS
            .iter()
            .map(|(t, r)| (t.to_string(), "user", self.user_path(r)))
            .chain(self.opts.project.iter().flat_map(|p| {
                PROJECT_INSTRUCTION_DIRS
                    .iter()
                    .map(move |(t, r)| (t.to_string(), "project", p.join(r)))
            }))
            .collect();
        for (tool, scope, d) in dirs {
            if !self.note(&d) || !self.first_time(&d) {
                continue;
            }
            let has_files = if d.is_dir() {
                std::fs::read_dir(&d)
                    .map(|mut r| r.next().is_some())
                    .unwrap_or(false)
            } else {
                d.is_file()
            };
            if has_files {
                let name = self.display(&d);
                self.push(
                    &tool,
                    scope,
                    Kind::Instructions,
                    name,
                    &d,
                    String::new(),
                    vec![],
                );
            }
        }
    }

    // -- MCP servers ---------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn servers_from(
        &mut self,
        file: &Path,
        text: &str,
        v: &Value,
        key: &[&str],
        tool: &str,
        scope: &str,
        prefix: &str,
        exposure: Exposure,
    ) {
        let shown_file = self.display(file);
        let base_dir = file.parent().map(Path::to_path_buf);
        for (name, entry) in servers_at(v, key) {
            let s = normalise(&entry);
            let line = line_of(text, &format!("\"{name}\""))
                .or_else(|| line_of(text, &format!("[mcp_servers.{name}]")))
                .or_else(|| line_of(text, &format!("{name}:")));
            let mut out = Vec::new();
            check_command(
                &mut out,
                &shown_file,
                line,
                &s.command.join(" "),
                &s.command,
                false,
            );
            for (k, v) in &s.env {
                check_secret(&mut out, &shown_file, line, exposure, k, v);
            }
            for (k, v) in &s.headers {
                check_secret(&mut out, &shown_file, line, exposure, k, v);
            }
            for a in &s.command {
                if let Some((k, v)) = a.split_once('=') {
                    check_secret(
                        &mut out,
                        &shown_file,
                        line,
                        exposure,
                        k.trim_start_matches('-'),
                        v,
                    );
                } else if known_secret(a) {
                    check_secret(&mut out, &shown_file, line, exposure, "argument", a);
                }
            }
            if let Some(u) = &s.url {
                check_url(&mut out, &shown_file, line, exposure, u);
            }
            if s.auto_approve {
                out.push(finding(
                    "AGENTCFG-013",
                    &shown_file,
                    line,
                    format!("server {name}"),
                ));
            }
            let mut detail = if let Some(u) = &s.url {
                u.split('?').next().unwrap_or(u).to_string()
            } else {
                redact_line(&s.command)
            };
            if s.disabled {
                detail.push_str(" (disabled)");
            }
            let cwd = s
                .cwd
                .as_ref()
                .map(PathBuf::from)
                .or_else(|| self.opts.project.clone().filter(|_| scope == "project"))
                .or(base_dir.clone());
            let scripts = script_targets(&s.command, cwd.as_deref(), &self.opts.home, None);
            self.push(
                tool,
                scope,
                Kind::McpServer,
                format!("{prefix}{name}"),
                file,
                detail,
                out,
            );
            if let Some(last) = self.items.last_mut() {
                last.scripts = scripts;
            }
        }
    }

    /// Read one config file's servers under `key`, once per (file, key).
    #[allow(clippy::too_many_arguments)]
    fn server_file(
        &mut self,
        tool: &str,
        scope: &str,
        path: &Path,
        fmt: Fmt,
        key: &[&str],
        exposure: Exposure,
    ) {
        if !self.note(path) {
            return;
        }
        let canon = std::fs::canonicalize(path).unwrap_or(path.to_path_buf());
        if !self.parsed.insert((canon, key.join("."))) {
            return;
        }
        if let Some((text, v)) = load(path, fmt) {
            self.servers_from(path, &text, &v, key, tool, scope, "", exposure);
            if tool == "codex" {
                self.codex_posture(path, &text, &v, scope);
            }
        }
    }

    fn mcp_configs(&mut self) {
        // Claude Code keeps user- and local-scope servers in ~/.claude.json
        // (or $CLAUDE_CONFIG_DIR/.claude.json).
        let claude_json = if self.opts.env_overrides && std::env::var("CLAUDE_CONFIG_DIR").is_ok() {
            self.claude_dir().join(".claude.json")
        } else {
            self.opts.home.join(".claude.json")
        };
        if self.note(&claude_json) {
            let canon = std::fs::canonicalize(&claude_json).unwrap_or(claude_json.clone());
            if self.parsed.insert((canon, "claude.json".into())) {
                if let Some((text, v)) = load(&claude_json, Fmt::Json) {
                    self.servers_from(
                        &claude_json,
                        &text,
                        &v,
                        &["mcpServers"],
                        "claude-code",
                        "user",
                        "",
                        Exposure::User,
                    );
                    if let Some(Value::Object(projects)) = v.get("projects") {
                        for (proj, pv) in projects {
                            if pv
                                .get("mcpServers")
                                .and_then(Value::as_object)
                                .is_some_and(|o| !o.is_empty())
                            {
                                let short = Path::new(proj)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                self.servers_from(
                                    &claude_json,
                                    &text,
                                    pv,
                                    &["mcpServers"],
                                    "claude-code",
                                    "local",
                                    &format!("{short}:"),
                                    Exposure::User,
                                );
                            }
                        }
                    }
                }
            }
        }
        let codex = self.codex_dir().join("config.toml");
        self.server_file(
            "codex",
            "user",
            &codex,
            Fmt::Toml,
            &["mcp_servers"],
            Exposure::User,
        );
        for (tool, rel, fmt, key) in USER_MCP {
            let path = self.opts.home.join(rel);
            self.server_file(tool, "user", &path, *fmt, key, Exposure::User);
        }
        for base in VSCODE_USER_DIRS {
            let b = self.opts.home.join(base);
            self.server_file(
                "vscode",
                "user",
                &b.join("mcp.json"),
                Fmt::Json,
                &["servers"],
                Exposure::User,
            );
            self.server_file(
                "vscode",
                "user",
                &b.join("settings.json"),
                Fmt::Json,
                &["mcp", "servers"],
                Exposure::User,
            );
            for (tool, rel) in VSCODE_EXTENSION_MCP {
                self.server_file(
                    tool,
                    "user",
                    &b.join(rel),
                    Fmt::Json,
                    &["mcpServers"],
                    Exposure::User,
                );
            }
        }
        if let Some(p) = self.opts.project.clone() {
            for (tool, rel, fmt, key) in PROJECT_MCP {
                self.server_file(tool, "project", &p.join(rel), *fmt, key, Exposure::Project);
            }
        }
        if self.opts.system {
            for f in [
                "/etc/claude-code/managed-mcp.json",
                "/Library/Application Support/ClaudeCode/managed-mcp.json",
            ] {
                self.server_file(
                    "claude-code",
                    "managed",
                    Path::new(f),
                    Fmt::Json,
                    &["mcpServers"],
                    Exposure::User,
                );
            }
        }
        // Continue: one file per server set.
        let mut cont = vec![(
            self.opts.home.join(".continue/mcpServers"),
            "user",
            Exposure::User,
        )];
        if let Some(p) = &self.opts.project {
            cont.push((p.join(".continue/mcpServers"), "project", Exposure::Project));
        }
        for (dir, scope, exposure) in cont {
            if !self.note(&dir) {
                continue;
            }
            let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).collect())
                .unwrap_or_default();
            files.sort();
            for f in files {
                let fmt = match f.extension().and_then(|e| e.to_str()) {
                    Some("yaml" | "yml") => Fmt::Yaml,
                    Some("json") => Fmt::Json,
                    _ => continue,
                };
                self.server_file("continue", scope, &f, fmt, &["mcpServers"], exposure);
            }
        }
    }

    fn codex_posture(&mut self, file: &Path, text: &str, v: &Value, scope: &str) {
        let shown = self.display(file);
        let notify = str_list(v.get("notify"));
        if !notify.is_empty() {
            let mut out = Vec::new();
            let line = line_of(text, "notify");
            check_command(&mut out, &shown, line, &notify.join(" "), &notify, true);
            let scripts =
                script_targets(&notify, self.opts.project.as_deref(), &self.opts.home, None);
            self.push(
                "codex",
                scope,
                Kind::Hook,
                "notify".into(),
                file,
                redact_line(&notify),
                out,
            );
            if let Some(last) = self.items.last_mut() {
                last.scripts = scripts;
            }
        }
        if v.get("sandbox_mode").and_then(Value::as_str) == Some("danger-full-access") {
            let f = finding(
                "AGENTCFG-012",
                &shown,
                line_of(text, "sandbox_mode"),
                "sandbox_mode = \"danger-full-access\"".into(),
            );
            self.push(
                "codex",
                scope,
                Kind::Settings,
                "sandbox_mode".into(),
                file,
                "danger-full-access".into(),
                vec![f],
            );
        }
    }

    // -- hooks and agent settings -------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn hooks_from(
        &mut self,
        file: &Path,
        text: &str,
        hooks: &Value,
        tool: &str,
        scope: &str,
        prefix: &str,
        plugin_root: Option<&Path>,
    ) {
        let Some(events) = hooks.as_object() else {
            return;
        };
        let shown = self.display(file);
        for (event, groups) in events {
            let groups: Vec<&Value> = match groups {
                Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            for g in groups {
                // Claude Code: {matcher, hooks: [{type, command}]}; Cursor:
                // {command} directly.
                let inner: Vec<&Value> = match g.get("hooks") {
                    Some(Value::Array(a)) => a.iter().collect(),
                    _ => vec![g],
                };
                let matcher = g.get("matcher").and_then(Value::as_str).unwrap_or("");
                for h in inner {
                    let Some(cmd) = h.get("command").and_then(Value::as_str) else {
                        continue;
                    };
                    let mut out = Vec::new();
                    let line = line_of(text, cmd.lines().next().unwrap_or(cmd));
                    check_command(&mut out, &shown, line, cmd, &cmdline::tokenize(cmd), true);
                    let name = if matcher.is_empty() {
                        format!("{prefix}{event}")
                    } else {
                        format!("{prefix}{event}[{matcher}]")
                    };
                    let scripts = script_targets(
                        &cmdline::tokenize(cmd),
                        self.opts.project.as_deref(),
                        &self.opts.home,
                        plugin_root,
                    );
                    let detail: String = cmd.chars().take(160).collect();
                    self.push(tool, scope, Kind::Hook, name, file, detail, out);
                    if let Some(last) = self.items.last_mut() {
                        last.scripts = scripts;
                    }
                }
            }
        }
    }

    fn settings(&mut self) {
        let mut files: Vec<(String, &str, PathBuf, Exposure)> = vec![
            (
                "claude-code".into(),
                "user",
                self.claude_dir().join("settings.json"),
                Exposure::User,
            ),
            (
                "claude-code".into(),
                "user",
                self.claude_dir().join("settings.local.json"),
                Exposure::User,
            ),
            (
                "cursor".into(),
                "user",
                self.opts.home.join(".cursor/hooks.json"),
                Exposure::User,
            ),
        ];
        if let Some(p) = &self.opts.project {
            files.push((
                "claude-code".into(),
                "project",
                p.join(".claude/settings.json"),
                Exposure::Project,
            ));
            files.push((
                "claude-code".into(),
                "project",
                p.join(".claude/settings.local.json"),
                Exposure::User,
            ));
            files.push((
                "cursor".into(),
                "project",
                p.join(".cursor/hooks.json"),
                Exposure::Project,
            ));
        }
        if self.opts.system {
            for f in [
                "/etc/claude-code/managed-settings.json",
                "/Library/Application Support/ClaudeCode/managed-settings.json",
            ] {
                files.push((
                    "claude-code".into(),
                    "managed",
                    PathBuf::from(f),
                    Exposure::User,
                ));
            }
        }
        for (tool, scope, f, exposure) in files {
            if !self.note(&f) || !self.first_time(&f) {
                continue;
            }
            let Some((text, v)) = load(&f, Fmt::Json) else {
                continue;
            };
            if let Some(h) = v.get("hooks") {
                self.hooks_from(&f, &text, h, &tool, scope, "", None);
            }
            let shown = self.display(&f);
            let mut out = Vec::new();
            if v.get("enableAllProjectMcpServers").and_then(Value::as_bool) == Some(true) {
                out.push(finding(
                    "AGENTCFG-012",
                    &shown,
                    line_of(&text, "enableAllProjectMcpServers"),
                    "enableAllProjectMcpServers: true — any repository's .mcp.json starts its servers without asking".into(),
                ));
            }
            if get(&v, &["permissions", "defaultMode"]).and_then(Value::as_str)
                == Some("bypassPermissions")
            {
                out.push(finding(
                    "AGENTCFG-012",
                    &shown,
                    line_of(&text, "defaultMode"),
                    "permissions.defaultMode: bypassPermissions — every tool call runs without asking".into(),
                ));
            }
            for (k, val) in str_map(v.get("env")) {
                check_secret(
                    &mut out,
                    &shown,
                    line_of(&text, &format!("\"{k}\"")),
                    exposure,
                    &k,
                    &val,
                );
            }
            for key in ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"] {
                if let Some(cmd) = v.get(key).and_then(Value::as_str) {
                    check_command(
                        &mut out,
                        &shown,
                        line_of(&text, key),
                        cmd,
                        &cmdline::tokenize(cmd),
                        false,
                    );
                }
            }
            if let Some(cmd) = get(&v, &["statusLine", "command"]).and_then(Value::as_str) {
                check_command(
                    &mut out,
                    &shown,
                    line_of(&text, "statusLine"),
                    cmd,
                    &cmdline::tokenize(cmd),
                    true,
                );
            }
            if !out.is_empty() {
                dedupe(&mut out);
                let name = f
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                self.push(&tool, scope, Kind::Settings, name, &f, String::new(), out);
            }
        }
    }
}

fn dedupe(out: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    out.retain(|f| seen.insert((f.rule.clone(), f.snippet.clone())));
}

fn dir_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

fn skill_name(dir: &Path) -> String {
    let text = std::fs::read_to_string(dir.join("SKILL.md")).unwrap_or_default();
    let mut lines = text.lines();
    if lines.next().map(str::trim) == Some("---") {
        for l in lines.take(40) {
            let t = l.trim();
            if t == "---" {
                break;
            }
            if let Some(v) = t.strip_prefix("name:") {
                let v = v.trim().trim_matches(['"', '\'']).trim();
                if !v.is_empty() {
                    return v.chars().take(80).collect();
                }
            }
        }
    }
    dir_name(dir)
}

/// Skill directories under a skills root. Immediate entries may be
/// symlinks (the usual way to install a skill you are developing) and are
/// followed; below that, nothing is followed and the walk stops at depth 4
/// or at the first `SKILL.md` on a branch.
fn find_skill_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.join("SKILL.md").is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    for e in entries {
        if !e.is_dir() {
            continue;
        }
        if e.join("SKILL.md").is_file() {
            out.push(e);
            continue;
        }
        let mut stack = vec![(e, 1usize)];
        while let Some((d, depth)) = stack.pop() {
            if depth >= 4 {
                continue;
            }
            let mut kids: Vec<PathBuf> = std::fs::read_dir(&d)
                .map(|r| {
                    r.filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                        .map(|e| e.path())
                        .collect()
                })
                .unwrap_or_default();
            kids.sort();
            for k in kids.into_iter().rev() {
                let n = dir_name(&k);
                if matches!(
                    n.as_str(),
                    "node_modules" | ".git" | "__pycache__" | ".venv"
                ) {
                    continue;
                }
                if k.join("SKILL.md").is_file() {
                    out.push(k);
                } else {
                    stack.push((k, depth + 1));
                }
            }
        }
    }
    out.sort();
    out
}

/// Directories under `base` (to `max_depth`, not following symlinks) that
/// contain the marker path; the walk does not descend into a match.
fn find_marked_dirs(base: &Path, marker: &[&str], max_depth: usize) -> Vec<PathBuf> {
    let marker: PathBuf = marker.iter().collect();
    let mut out = Vec::new();
    let mut stack = vec![(base.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        if d.join(&marker).is_file() && d != base {
            out.push(d);
            continue;
        }
        if depth >= max_depth {
            continue;
        }
        if let Ok(r) = std::fs::read_dir(&d) {
            for e in r.filter_map(|e| e.ok()) {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    let n = e.file_name().to_string_lossy().to_string();
                    if !matches!(n.as_str(), "node_modules" | ".git") {
                        stack.push((e.path(), depth + 1));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// Local scripts a command line runs, resolved the way the agent would:
/// `$CLAUDE_PROJECT_DIR` / `${CLAUDE_PLUGIN_ROOT}` / `~` expanded, relative
/// paths against the working directory. Only regular files under 5 MiB are
/// returned; interpreters, binaries on PATH and package runners are not.
fn script_targets(
    parts: &[String],
    cwd: Option<&Path>,
    home: &Path,
    plugin_root: Option<&Path>,
) -> Vec<PathBuf> {
    const INTERPRETERS: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "dash",
        "python",
        "python3",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "pwsh",
        "powershell",
        "uv",
        "tsx",
        "ts-node",
    ];
    let expand = |t: &str| -> Option<PathBuf> {
        let mut s = t.to_string();
        if let Some(proj) = cwd {
            for v in ["${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"] {
                s = s.replace(v, &proj.to_string_lossy());
            }
        }
        if let Some(root) = plugin_root {
            for v in ["${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT"] {
                s = s.replace(v, &root.to_string_lossy());
            }
        }
        for v in ["${HOME}", "$HOME"] {
            s = s.replace(v, &home.to_string_lossy());
        }
        if let Some(r) = s.strip_prefix("~/") {
            s = home.join(r).to_string_lossy().to_string();
        }
        if s.contains('$') || s.starts_with('-') || s.contains("://") {
            return None;
        }
        let p = PathBuf::from(&s);
        let p = if p.is_absolute() {
            p
        } else if s.contains('/') || s.contains('.') {
            cwd?.join(p)
        } else {
            return None;
        };
        let meta = std::fs::metadata(&p).ok()?;
        if !meta.is_file() || meta.len() >= 5 * 1024 * 1024 {
            return None;
        }
        // Scripts only: a compiled server binary is not something the
        // content rules can judge, and would only earn provenance noise.
        let mut head = [0u8; 1024];
        let n = std::io::Read::read(&mut std::fs::File::open(&p).ok()?, &mut head).ok()?;
        (!head[..n].contains(&0)).then_some(p)
    };
    let mut out = Vec::new();
    let mut i = 0;
    // Skip env assignments.
    while i < parts.len() && parts[i].contains('=') && !parts[i].starts_with('-') {
        i += 1;
    }
    let Some(head) = parts.get(i) else {
        return out;
    };
    let base = head.rsplit('/').next().unwrap_or(head);
    if INTERPRETERS.contains(&base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')) {
        // First non-flag argument after the interpreter (and after `run`
        // for `uv run` / `bun run` / `deno run`).
        for t in &parts[i + 1..] {
            if t.starts_with('-') || t == "run" {
                continue;
            }
            if let Some(p) = expand(t) {
                out.push(p);
            }
            break;
        }
    } else if let Some(p) = expand(head) {
        // A script invoked directly; binaries are skipped by the scanner's
        // own binary handling, but keep obviously non-text files out.
        out.push(p);
    }
    out
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn severity_verdict(max: Option<Severity>) -> Verdict {
    match max {
        Some(Severity::Critical) => Verdict::CriticalRisk,
        Some(Severity::High) => Verdict::HighRisk,
        Some(Severity::Medium) => Verdict::MediumRisk,
        _ => Verdict::LowRisk,
    }
}

/// Scan content items with the scanner, and scripts that config items run.
pub fn evaluate(items: &mut [Item]) {
    for item in items.iter_mut() {
        if item.kind.is_content() {
            let target = std::fs::canonicalize(&item.path).unwrap_or(item.path.clone());
            let r = scanner::run_scan(&target, None, None);
            item.files_scanned = r.files_scanned;
            item.score = r.score;
            item.verdict = Some(r.verdict.to_string());
            item.findings = r.findings;
            continue;
        }
        let mut script_worst: Option<Verdict> = None;
        for s in item.scripts.clone() {
            let r = scanner::run_scan(&s, None, None);
            item.files_scanned += r.files_scanned;
            if r.verdict != Verdict::LowRisk || !r.findings.is_empty() {
                script_worst = Some(match (script_worst, r.verdict) {
                    (Some(Verdict::CriticalRisk), _) | (_, Verdict::CriticalRisk) => {
                        Verdict::CriticalRisk
                    }
                    (Some(Verdict::HighRisk), _) | (_, Verdict::HighRisk) => Verdict::HighRisk,
                    (Some(Verdict::MediumRisk), _) | (_, Verdict::MediumRisk) => {
                        Verdict::MediumRisk
                    }
                    _ => Verdict::LowRisk,
                });
            }
            let shown = s.display().to_string();
            item.findings.extend(r.findings.into_iter().map(|mut f| {
                f.file = shown.clone();
                f
            }));
        }
        item.score = scanner::scoring::calculate_score(&item.findings);
        let cfg = severity_verdict(
            item.findings
                .iter()
                .filter(|f| f.rule.starts_with("AGENTCFG-"))
                .map(|f| f.severity)
                .max(),
        );
        let v = match (cfg, script_worst) {
            (Verdict::CriticalRisk, _) | (_, Some(Verdict::CriticalRisk)) => Verdict::CriticalRisk,
            (Verdict::HighRisk, _) | (_, Some(Verdict::HighRisk)) => Verdict::HighRisk,
            (Verdict::MediumRisk, _) | (_, Some(Verdict::MediumRisk)) => Verdict::MediumRisk,
            _ => Verdict::LowRisk,
        };
        item.verdict = Some(v.to_string());
    }
}

pub fn discover(opts: &Options) -> (Vec<Item>, Vec<(PathBuf, bool)>) {
    let mut d = Discovery::new(opts);
    d.skills();
    d.plugins();
    d.extensions();
    d.instructions();
    d.settings();
    d.mcp_configs();
    let mut items = d.items;
    if let Some(tools) = &opts.tools {
        items.retain(|i| tools.iter().any(|t| t.eq_ignore_ascii_case(&i.tool)));
    }
    (items, d.searched)
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Exit code for a fleet/CI gate: 1 when any finding in any item is at or
/// above `threshold`, as `sigil scan --fail-on` does for one tree.
pub fn exit_code(items: &[Item], threshold: Severity) -> i32 {
    if items
        .iter()
        .flat_map(|i| i.findings.iter())
        .any(|f| f.severity >= threshold)
    {
        crate::EXIT_FINDINGS
    } else {
        crate::EXIT_CLEAN
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_skills(
    action: &str,
    root: Option<PathBuf>,
    project: Option<PathBuf>,
    no_project: bool,
    no_user: bool,
    fail_on: &str,
    tools: Option<&str>,
    format: &str,
    verbose: bool,
) -> i32 {
    let Some(threshold) = parse_severity(fail_on) else {
        eprintln!(
            "{} invalid --fail-on '{fail_on}' (use low, medium, high, critical)",
            "error:".bold().red()
        );
        return crate::EXIT_ERROR;
    };
    let scan = match action {
        "scan" => true,
        "list" => false,
        other => {
            eprintln!(
                "{} unknown action '{other}' (use scan or list)",
                "error:".bold().red()
            );
            return crate::EXIT_ERROR;
        }
    };
    // `--root`, else SIGIL_HOME (as `sigil residue` honours it), else the
    // real home directory.
    let root = root.or_else(|| std::env::var_os("SIGIL_HOME").map(PathBuf::from));
    let home = match &root {
        Some(r) => r.clone(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => {
                eprintln!(
                    "{} cannot determine the home directory; pass --root",
                    "error:".bold().red()
                );
                return crate::EXIT_ERROR;
            }
        },
    };
    if !home.is_dir() {
        eprintln!(
            "{} not a directory: {}",
            "error:".bold().red(),
            home.display()
        );
        return crate::EXIT_ERROR;
    }
    let project = if no_project {
        None
    } else {
        project.or_else(|| std::env::current_dir().ok())
    };
    let opts = Options {
        home: std::fs::canonicalize(&home).unwrap_or(home),
        project: project.map(|p| std::fs::canonicalize(&p).unwrap_or(p)),
        system: root.is_none(),
        tools: tools.map(|t| t.split(',').map(|s| s.trim().to_string()).collect()),
        env_overrides: root.is_none(),
        user: !no_user,
    };
    if !opts.user && opts.project.is_none() {
        eprintln!(
            "{} --no-user with --no-project leaves nothing to inspect",
            "error:".bold().red()
        );
        return crate::EXIT_ERROR;
    }
    let (mut items, searched) = discover(&opts);
    if scan {
        evaluate(&mut items);
    }
    if format == "json" {
        print_json(&opts, &items, scan, fail_on);
    } else {
        print_text(&opts, &items, &searched, scan, verbose);
    }
    if scan {
        exit_code(&items, threshold)
    } else {
        crate::EXIT_CLEAN
    }
}

fn print_json(opts: &Options, items: &[Item], scan: bool, fail_on: &str) {
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_verdict: BTreeMap<String, usize> = BTreeMap::new();
    for i in items {
        *by_kind.entry(i.kind.label()).or_default() += 1;
        if let Some(v) = &i.verdict {
            *by_verdict.entry(v.clone()).or_default() += 1;
        }
    }
    let max = items
        .iter()
        .flat_map(|i| i.findings.iter())
        .map(|f| f.severity)
        .max();
    let doc = serde_json::json!({
        "home": opts.home,
        "project": opts.project,
        "mode": if scan { "scan" } else { "list" },
        "items": items,
        "summary": {
            "items": items.len(),
            "by_kind": by_kind,
            "by_verdict": by_verdict,
            "findings": items.iter().map(|i| i.findings.len()).sum::<usize>(),
            "max_severity": max.map(|s| s.to_string()),
            "fail_on": fail_on,
        },
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
}

fn colour_verdict(v: &str) -> String {
    let padded = format!("{v:<13}");
    match v {
        "LOW RISK" => padded.green().to_string(),
        "MEDIUM RISK" => padded.yellow().to_string(),
        "HIGH RISK" => padded.red().to_string(),
        "CRITICAL RISK" => padded.red().bold().to_string(),
        _ => padded,
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn print_text(
    opts: &Options,
    items: &[Item],
    searched: &[(PathBuf, bool)],
    scan: bool,
    verbose: bool,
) {
    println!();
    println!(
        "  {} agent tooling inventory — home {}{}",
        "sigil skills".bold().cyan(),
        opts.home.display(),
        opts.project
            .as_ref()
            .map(|p| format!(", project {}", p.display()))
            .unwrap_or_default()
    );
    if verbose {
        println!("  searched:");
        for (p, found) in searched {
            println!(
                "    {} {}",
                if *found { "found  " } else { "missing" },
                p.display()
            );
        }
    }
    println!();
    if items.is_empty() {
        println!("  No agent skills, plugins, hooks or MCP servers found.");
        return;
    }
    if scan {
        println!(
            "  {:<13} {:<14} {:<8} {:<12} {:<30} LOCATION",
            "VERDICT", "TOOL", "SCOPE", "KIND", "NAME"
        );
    } else {
        println!(
            "  {:<14} {:<8} {:<12} {:<30} {:<48} LOCATION",
            "TOOL", "SCOPE", "KIND", "NAME", "DETAIL"
        );
    }
    for i in items {
        if scan {
            println!(
                "  {} {:<14} {:<8} {:<12} {:<30} {}",
                colour_verdict(i.verdict.as_deref().unwrap_or("")),
                clip(&i.tool, 14),
                clip(&i.scope, 8),
                i.kind.label(),
                clip(&i.name, 30),
                i.location
            );
            let mut shown: Vec<&Finding> = i
                .findings
                .iter()
                .filter(|f| {
                    verbose || f.severity >= Severity::Medium || f.rule.starts_with("AGENTCFG-")
                })
                .collect();
            shown.sort_by(|a, b| b.severity.cmp(&a.severity));
            let limit = if verbose { usize::MAX } else { 4 };
            for f in shown.iter().take(limit) {
                let loc = match f.line {
                    Some(l) => format!("{}:{l}", f.file),
                    None => f.file.clone(),
                };
                println!(
                    "      {:<8} {:<14} {}  {}",
                    f.severity.to_string(),
                    f.rule,
                    clip(&f.snippet.replace('\n', " "), 110),
                    loc.dimmed()
                );
            }
            if shown.len() > limit {
                println!("      … {} more (use --verbose)", shown.len() - limit);
            }
        } else {
            println!(
                "  {:<14} {:<8} {:<12} {:<30} {:<40} {}",
                clip(&i.tool, 14),
                clip(&i.scope, 8),
                i.kind.label(),
                clip(&i.name, 30),
                clip(&i.detail, 48),
                i.location
            );
        }
    }
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for i in items {
        *kinds.entry(i.kind.label()).or_default() += 1;
    }
    let kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{n} {k}")).collect();
    println!();
    println!("  {} items: {}", items.len(), kinds.join(", "));
    if scan {
        let count = |v: &str| {
            items
                .iter()
                .filter(|i| i.verdict.as_deref() == Some(v))
                .count()
        };
        println!(
            "  verdicts: {} critical, {} high, {} medium, {} low",
            count("CRITICAL RISK"),
            count("HIGH RISK"),
            count("MEDIUM RISK"),
            count("LOW RISK")
        );
    }
}

// ---------------------------------------------------------------------------
// Minimal TOML reader (Codex config)
// ---------------------------------------------------------------------------

/// Enough TOML to read agent configs without a dependency: tables, dotted
/// and quoted keys, basic and literal strings (single- and multi-line),
/// numbers, booleans, arrays (multi-line) and inline tables. Dates and
/// arrays of tables are read as plain values/tables. Unknown syntax is an
/// error, and the file is then skipped rather than half-read.
mod mini_toml {
    use serde_json::{Map, Value};

    struct P<'a> {
        s: &'a [u8],
        i: usize,
    }

    impl P<'_> {
        fn peek(&self) -> Option<u8> {
            self.s.get(self.i).copied()
        }
        fn ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t')) {
                self.i += 1;
            }
        }
        fn ws_nl(&mut self) {
            loop {
                match self.peek() {
                    Some(b' ' | b'\t' | b'\r' | b'\n') => self.i += 1,
                    Some(b'#') => {
                        while !matches!(self.peek(), None | Some(b'\n')) {
                            self.i += 1;
                        }
                    }
                    _ => break,
                }
            }
        }
        fn eol(&mut self) -> Result<(), String> {
            self.ws();
            if self.peek() == Some(b'#') {
                while !matches!(self.peek(), None | Some(b'\n')) {
                    self.i += 1;
                }
            }
            match self.peek() {
                None => Ok(()),
                Some(b'\r' | b'\n') => Ok(()),
                Some(c) => Err(format!("unexpected {:?} at byte {}", c as char, self.i)),
            }
        }
        fn starts(&self, t: &str) -> bool {
            self.s[self.i..].starts_with(t.as_bytes())
        }
        fn key_part(&mut self) -> Result<String, String> {
            self.ws();
            match self.peek() {
                Some(b'"') => self.basic_string(),
                Some(b'\'') => self.literal_string(),
                _ => {
                    let start = self.i;
                    while self
                        .peek()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    {
                        self.i += 1;
                    }
                    if start == self.i {
                        return Err(format!("expected a key at byte {}", self.i));
                    }
                    Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
                }
            }
        }
        fn key(&mut self) -> Result<Vec<String>, String> {
            let mut parts = vec![self.key_part()?];
            loop {
                self.ws();
                if self.peek() == Some(b'.') {
                    self.i += 1;
                    parts.push(self.key_part()?);
                } else {
                    return Ok(parts);
                }
            }
        }
        fn basic_string(&mut self) -> Result<String, String> {
            let multi = self.starts("\"\"\"");
            self.i += if multi { 3 } else { 1 };
            if multi && self.peek() == Some(b'\n') {
                self.i += 1;
            }
            let mut out = Vec::new();
            loop {
                let c = self.peek().ok_or("unterminated string")?;
                if multi && self.starts("\"\"\"") {
                    self.i += 3;
                    break;
                }
                if !multi && c == b'"' {
                    self.i += 1;
                    break;
                }
                if !multi && c == b'\n' {
                    return Err("newline in string".into());
                }
                if c == b'\\' {
                    let e = *self.s.get(self.i + 1).ok_or("bad escape")?;
                    self.i += 2;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'u' | b'U' => {
                            let n = if e == b'u' { 4 } else { 8 };
                            let hex = std::str::from_utf8(
                                self.s.get(self.i..self.i + n).ok_or("bad escape")?,
                            )
                            .map_err(|_| "bad escape")?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad escape")?;
                            let ch = char::from_u32(cp).ok_or("bad escape")?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            self.i += n;
                        }
                        b'\n' | b' ' | b'\r' if multi => {
                            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                                self.i += 1;
                            }
                        }
                        other => out.push(other),
                    }
                    continue;
                }
                out.push(c);
                self.i += 1;
            }
            Ok(String::from_utf8_lossy(&out).into_owned())
        }
        fn literal_string(&mut self) -> Result<String, String> {
            let multi = self.starts("'''");
            self.i += if multi { 3 } else { 1 };
            if multi && self.peek() == Some(b'\n') {
                self.i += 1;
            }
            let start = self.i;
            loop {
                let c = self.peek().ok_or("unterminated string")?;
                if multi && self.starts("'''") {
                    let v = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                    self.i += 3;
                    return Ok(v);
                }
                if !multi && c == b'\'' {
                    let v = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                    self.i += 1;
                    return Ok(v);
                }
                if !multi && c == b'\n' {
                    return Err("newline in string".into());
                }
                self.i += 1;
            }
        }
        fn value(&mut self) -> Result<Value, String> {
            self.ws();
            match self.peek() {
                Some(b'"') => Ok(Value::String(self.basic_string()?)),
                Some(b'\'') => Ok(Value::String(self.literal_string()?)),
                Some(b'[') => {
                    self.i += 1;
                    let mut arr = Vec::new();
                    loop {
                        self.ws_nl();
                        if self.peek() == Some(b']') {
                            self.i += 1;
                            return Ok(Value::Array(arr));
                        }
                        arr.push(self.value()?);
                        self.ws_nl();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b']') => {}
                            _ => return Err(format!("bad array at byte {}", self.i)),
                        }
                    }
                }
                Some(b'{') => {
                    self.i += 1;
                    let mut m = Map::new();
                    loop {
                        self.ws();
                        if self.peek() == Some(b'}') {
                            self.i += 1;
                            return Ok(Value::Object(m));
                        }
                        let k = self.key()?;
                        self.ws();
                        if self.peek() != Some(b'=') {
                            return Err("expected '=' in inline table".into());
                        }
                        self.i += 1;
                        let v = self.value()?;
                        insert(&mut m, &k, v)?;
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {}
                            _ => return Err(format!("bad inline table at byte {}", self.i)),
                        }
                    }
                }
                Some(_) => {
                    let start = self.i;
                    while self
                        .peek()
                        .is_some_and(|c| !matches!(c, b',' | b']' | b'}' | b'\n' | b'\r' | b'#'))
                    {
                        self.i += 1;
                    }
                    let raw = String::from_utf8_lossy(&self.s[start..self.i])
                        .trim()
                        .to_string();
                    if raw.is_empty() {
                        return Err(format!("missing value at byte {start}"));
                    }
                    Ok(match raw.as_str() {
                        "true" => Value::Bool(true),
                        "false" => Value::Bool(false),
                        _ => raw
                            .replace('_', "")
                            .parse::<i64>()
                            .map(Value::from)
                            .or_else(|_| raw.parse::<f64>().map(Value::from))
                            .unwrap_or(Value::String(raw)),
                    })
                }
                None => Err("missing value".into()),
            }
        }
    }

    fn table<'m>(
        root: &'m mut Map<String, Value>,
        path: &[String],
    ) -> Result<&'m mut Map<String, Value>, String> {
        let mut cur = root;
        for k in path {
            let slot = cur
                .entry(k.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let slot = match slot {
                Value::Array(a) => a.last_mut().ok_or("empty table array")?,
                other => other,
            };
            cur = slot.as_object_mut().ok_or(format!("{k} is not a table"))?;
        }
        Ok(cur)
    }

    fn insert(m: &mut Map<String, Value>, key: &[String], v: Value) -> Result<(), String> {
        let (last, parents) = key.split_last().ok_or("empty key")?;
        let t = table(m, parents)?;
        t.insert(last.clone(), v);
        Ok(())
    }

    pub fn parse(text: &str) -> Result<Value, String> {
        let mut p = P {
            s: text.as_bytes(),
            i: 0,
        };
        let mut root = Map::new();
        let mut current: Vec<String> = Vec::new();
        loop {
            p.ws_nl();
            let Some(c) = p.peek() else { break };
            if c == b'[' {
                let array = p.starts("[[");
                p.i += if array { 2 } else { 1 };
                let path = p.key()?;
                p.ws();
                let close = if array { "]]" } else { "]" };
                if !p.starts(close) {
                    return Err(format!("unterminated table header at byte {}", p.i));
                }
                p.i += close.len();
                p.eol()?;
                if array {
                    let (last, parents) = path.split_last().ok_or("empty header")?;
                    let t = table(&mut root, parents)?;
                    let slot = t
                        .entry(last.clone())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    slot.as_array_mut()
                        .ok_or(format!("{last} is not an array of tables"))?
                        .push(Value::Object(Map::new()));
                } else {
                    table(&mut root, &path)?;
                }
                current = path;
                continue;
            }
            let key = p.key()?;
            p.ws();
            if p.peek() != Some(b'=') {
                return Err(format!("expected '=' at byte {}", p.i));
            }
            p.i += 1;
            let v = p.value()?;
            p.eol()?;
            let t = table(&mut root, &current)?;
            insert(t, &key, v)?;
        }
        Ok(Value::Object(root))
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
