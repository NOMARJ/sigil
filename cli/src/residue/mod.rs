//! `sigil residue` — what installed agent tooling left behind on this machine.
//!
//! `sigil scan` judges code *before* it runs. This command looks at the host
//! *after* something ran: the crontab entry an uninstalled skill left, the
//! line a setup script appended to `~/.zshrc`, the git hook that still fires
//! on every commit, the credential file an agent wrote world-readable, the
//! cache directory of a tool that is no longer installed.
//!
//! sigil:ignore-file PERSIST-005 -- the doc comment names the shell startup files the checks read
//!
//! Two design rules, both learned from prism-scanner's residue engine, which
//! this adopts the shape of and not the heuristics:
//!
//! 1. **Severity comes from what an entry does, not what it is called.** A
//!    systemd unit named `mcp-gateway` is inventory; a cron line that pipes
//!    `curl` into `sh` from `/tmp` is Critical, whatever it is called. Every
//!    persistence entry is judged by its command — through the same compiled
//!    rule corpus `sigil scan` uses, plus a few host-only checks (runs from a
//!    temporary path, executable no longer exists).
//! 2. **Nothing here is destructive without a backup and a way back.** A scan
//!    is read-only. A plan is a document. `apply` backs every file up under
//!    `~/.sigil/backups/<id>/` before touching it, verifies the file has not
//!    changed since the plan was made, and `rollback <id>` restores it —
//!    CHARTER II.6, reversibility first. A fixed list of things is never
//!    planned at all (system directories, credential-file deletion, anything
//!    outside `$HOME`, symlinks).
//!
//! Residue findings never enter a scan's score or verdict, and the JSON
//! document is deliberately a different shape from scan output (`kind:
//! "residue"`, `items` rather than `findings`) so no scan consumer can
//! mistake one for the other.

pub mod checks;
pub mod plan;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scanner::Severity;

/// Residue severity. Adds `Info` — inventory that is worth listing but is
/// not a finding — to the scanner's four levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn from_scan(s: Severity) -> Level {
        match s {
            Severity::Low => Level::Low,
            Severity::Medium => Level::Medium,
            Severity::High => Level::High,
            Severity::Critical => Level::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Level::Info),
            "low" => Some(Level::Low),
            "medium" => Some(Level::Medium),
            "high" => Some(Level::High),
            "critical" => Some(Level::Critical),
            _ => None,
        }
    }
}

/// A reversible fix for one item. Every variant maps to exactly one backup
/// strategy in `plan.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Remove one line from a text file, matched by number *and* content.
    RemoveLine {
        path: String,
        line: usize,
        content: String,
    },
    /// Tighten a file's permission bits.
    Chmod { path: String, mode: u32 },
    /// Remove a user-owned file (a launch agent, a unit, a hook).
    RemoveFile { path: String },
    /// Remove a cache directory of a tool that is no longer installed.
    RemoveDir { path: String },
    /// Remove one line from the user's crontab, by exact content.
    RemoveCrontabLine { content: String },
}

/// One residue item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub severity: Level,
    /// `shell_rc`, `persistence`, `git_hook`, `credential`, `residue_dir`,
    /// `package`, `network`.
    pub category: String,
    pub title: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Redacted excerpt: at most 120 characters, long token-shaped runs masked.
    pub evidence: String,
    /// `unknown`, `sigil-setup`, or `installer:<name>`.
    pub origin: String,
    pub fixable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub os: String,
    pub home: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub items_count: usize,
    pub duration_ms: u64,
}

/// The residue scan document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub kind: String,
    pub residue_schema: u32,
    pub host: Host,
    pub checks_run: Vec<String>,
    pub checks_skipped: Vec<Skipped>,
    pub items: Vec<Item>,
    pub items_suppressed: Vec<Item>,
    pub summary: Summary,
}

/// Where to look. `home` honours `SIGIL_HOME` so tests and CI never touch a
/// real home directory; `sigil_dir` is where backups and the allowlist live.
#[derive(Debug, Clone)]
pub struct Context {
    pub home: PathBuf,
    pub sigil_dir: PathBuf,
    pub repo: Option<PathBuf>,
    pub os: &'static str,
}

impl Context {
    /// Build a context for the current user, optionally anchored on a repo.
    pub fn detect(repo: Option<&Path>) -> Context {
        let home = std::env::var_os("SIGIL_HOME")
            .map(PathBuf::from)
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let repo = repo.map(Path::to_path_buf).or_else(|| {
            let cwd = std::env::current_dir().ok()?;
            if cwd.join(".git").exists() {
                Some(cwd)
            } else {
                None
            }
        });
        Context {
            sigil_dir: home.join(".sigil"),
            home,
            repo,
            os: std::env::consts::OS,
        }
    }

    /// A context rooted entirely under `root` (tests).
    #[cfg(test)]
    pub fn rooted(root: &Path) -> Context {
        Context {
            home: root.to_path_buf(),
            sigil_dir: root.join(".sigil"),
            repo: None,
            os: std::env::consts::OS,
        }
    }

    /// Expand a leading `~` or `$HOME` against this context's home.
    pub fn expand(&self, path: &str) -> PathBuf {
        let home = self.home.to_string_lossy().to_string();
        let expanded = if let Some(rest) = path.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else if path == "~" {
            home.clone()
        } else if let Some(rest) = path.strip_prefix("$HOME/") {
            format!("{home}/{rest}")
        } else if let Some(rest) = path.strip_prefix("${HOME}/") {
            format!("{home}/{rest}")
        } else {
            path.to_string()
        };
        PathBuf::from(expanded)
    }

    /// Is this path inside the user's home?
    pub fn in_home(&self, path: &Path) -> bool {
        path.starts_with(&self.home)
    }
}

/// Run every check and assemble the report.
pub fn scan(ctx: &Context) -> Report {
    let start = std::time::Instant::now();
    let mut report = Report {
        kind: "residue".to_string(),
        residue_schema: 1,
        host: Host {
            os: ctx.os.to_string(),
            home: ctx.home.to_string_lossy().to_string(),
        },
        checks_run: Vec::new(),
        checks_skipped: Vec::new(),
        items: Vec::new(),
        items_suppressed: Vec::new(),
        summary: Summary::default(),
    };

    checks::shell_rc(ctx, &mut report);
    checks::persistence(ctx, &mut report);
    checks::git_hooks(ctx, &mut report);
    checks::credentials(ctx, &mut report);
    checks::residue_dirs(ctx, &mut report);
    checks::hosts_file(ctx, &mut report, Path::new("/etc/hosts"));
    checks::global_packages(ctx, &mut report);

    apply_allowlist(ctx, &mut report);

    report
        .items
        .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
    for item in &report.items {
        match item.severity {
            Level::Critical => report.summary.critical += 1,
            Level::High => report.summary.high += 1,
            Level::Medium => report.summary.medium += 1,
            Level::Low => report.summary.low += 1,
            Level::Info => report.summary.info += 1,
        }
    }
    report.summary.items_count = report.items.len();
    report.summary.duration_ms = start.elapsed().as_millis() as u64;
    report
}

/// `~/.sigil/residue-allow`: one entry per line, `RULE-ID <path>` or just a
/// path. Matching items are still reported, under `items_suppressed`.
fn apply_allowlist(ctx: &Context, report: &mut Report) {
    let Ok(text) = std::fs::read_to_string(ctx.sigil_dir.join("residue-allow")) else {
        return;
    };
    let entries: Vec<(Option<String>, String)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| match l.split_once(char::is_whitespace) {
            Some((rule, path)) if rule.starts_with("RES-") => {
                (Some(rule.to_string()), path.trim().to_string())
            }
            _ => (None, l.to_string()),
        })
        .collect();
    if entries.is_empty() {
        return;
    }
    let items = std::mem::take(&mut report.items);
    for item in items {
        let suppressed = entries.iter().any(|(rule, path)| {
            rule.as_deref().is_none_or(|r| r == item.id)
                && ctx.expand(path).to_string_lossy() == item.path
        });
        if suppressed {
            report.items_suppressed.push(item);
        } else {
            report.items.push(item);
        }
    }
}

/// Mask token-shaped runs so a credential never lands in a report.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 20 {
            out.push_str(&run[..4]);
            out.push('…');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    let trimmed: String = out.chars().take(120).collect();
    trimmed
}

/// Text rendering of a report.
pub fn render_text(report: &Report) -> String {
    use colored::Colorize;
    let mut out = String::new();
    out.push_str(&format!(
        "\n  {} residue scan — {} ({})\n",
        "sigil".bold().cyan(),
        report.host.os,
        report.host.home
    ));
    out.push_str(&format!(
        "  checks: {} run, {} skipped\n",
        report.checks_run.len(),
        report.checks_skipped.len()
    ));
    for s in &report.checks_skipped {
        out.push_str(&format!("    skipped {}: {}\n", s.id, s.reason));
    }
    if report.items.is_empty() {
        out.push_str(&format!("\n  {} No residue found.\n", "[*]".green()));
    }
    for item in &report.items {
        let sev = match item.severity {
            Level::Critical => "CRITICAL".red().bold().to_string(),
            Level::High => "HIGH    ".red().to_string(),
            Level::Medium => "MEDIUM  ".yellow().to_string(),
            Level::Low => "LOW     ".dimmed().to_string(),
            Level::Info => "INFO    ".dimmed().to_string(),
        };
        let location = match item.line {
            Some(l) => format!("{}:{}", item.path, l),
            None => item.path.clone(),
        };
        out.push_str(&format!(
            "\n  {} [{}] {}\n       {}\n",
            sev,
            item.id.dimmed(),
            location.bold(),
            item.title
        ));
        if !item.evidence.is_empty() {
            out.push_str(&format!("       {}\n", item.evidence.dimmed()));
        }
        if item.origin != "unknown" {
            out.push_str(&format!("       origin: {}\n", item.origin.dimmed()));
        }
        out.push_str(&format!(
            "       {} {}{}\n",
            "fix:".cyan(),
            item.remediation.dimmed(),
            if item.fixable {
                " (plannable)".dimmed().to_string()
            } else {
                String::new()
            }
        ));
    }
    if !report.items_suppressed.is_empty() {
        out.push_str(&format!(
            "\n  {} {} item(s) suppressed by ~/.sigil/residue-allow\n",
            "[*]".green(),
            report.items_suppressed.len()
        ));
    }
    let s = &report.summary;
    out.push_str(&format!(
        "\n  {} item(s): {} critical, {} high, {} medium, {} low, {} info ({} ms)\n",
        s.items_count, s.critical, s.high, s.medium, s.low, s.info, s.duration_ms
    ));
    if s.items_count > 0 {
        out.push_str("  Next: `sigil residue plan` to see the reversible fixes, `sigil residue apply` to run them with backups.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_long_token_runs_only() {
        assert_eq!(redact("export X=short"), "export X=short");
        let r = redact("token=abcdefghijklmnopqrstuvwxyz0123456789 end");
        assert!(r.starts_with("token=abcd…"), "{r}");
        assert!(r.ends_with(" end"));
        assert!(!r.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn expand_handles_home_forms() {
        let ctx = Context::rooted(Path::new("/h/u"));
        assert_eq!(ctx.expand("~/.zshrc"), PathBuf::from("/h/u/.zshrc"));
        assert_eq!(ctx.expand("$HOME/.cache"), PathBuf::from("/h/u/.cache"));
        assert_eq!(ctx.expand("/etc/hosts"), PathBuf::from("/etc/hosts"));
        assert!(ctx.in_home(Path::new("/h/u/.zshrc")));
        assert!(!ctx.in_home(Path::new("/etc/hosts")));
    }

    #[test]
    fn empty_home_scans_clean() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let report = scan(&ctx);
        assert_eq!(report.kind, "residue");
        assert!(
            report.items.iter().all(|i| i.category != "shell_rc"),
            "{:?}",
            report.items
        );
    }
}
